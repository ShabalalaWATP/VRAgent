"""
Power Schedule Service

Power schedules determine how much "energy" (fuzzing iterations) each seed gets.
This is one of the most important optimizations in modern fuzzers.

AFL++'s power schedules include:
- FAST: Prioritize fast-executing seeds
- COE (Cut-Off Exponential): Focus on seeds hitting rare edges
- EXPLORE: Favor seeds with unexplored neighbor paths
- EXPLOIT: Focus on seeds that have historically found bugs
- QUAD: Quadratic schedule based on execution time
- LIN: Linear schedule
- RARE: Heavily prioritize seeds hitting rare edges

The key insight: A seed that hits a rarely-covered edge is MUCH more
valuable than one hitting common edges. We should fuzz it more.

Without power schedules: All seeds get equal time
With power schedules: 10-100x more efficient coverage discovery
"""

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib
import random

logger = logging.getLogger(__name__)


class PowerSchedule(str, Enum):
    """Available power schedules."""
    FAST = "fast"  # Prioritize fast seeds
    COE = "coe"  # Cut-off exponential (rare edges)
    EXPLORE = "explore"  # Maximize exploration
    EXPLOIT = "exploit"  # Focus on bug-finding seeds
    QUAD = "quad"  # Quadratic based on depth
    LIN = "lin"  # Linear schedule
    RARE = "rare"  # Heavily favor rare edge seeds
    MMOPT = "mmopt"  # AFL++'s MOpt mutator optimization
    SEEK = "seek"  # Seek new coverage aggressively


@dataclass
class SeedInfo:
    """Information about a seed for scheduling."""
    seed_id: str
    seed_data: bytes
    seed_hash: str

    # Execution characteristics
    exec_time_us: int = 0  # Execution time in microseconds
    bitmap_size: int = 0  # Number of edges hit
    depth: int = 0  # How many mutations from original

    # Coverage info
    edges_hit: Set[int] = field(default_factory=set)
    unique_edges: int = 0  # Edges only this seed hits
    rare_edges: int = 0  # Edges hit by few seeds

    # History
    fuzz_count: int = 0  # Times this seed has been fuzzed
    crashes_found: int = 0  # Crashes found from this seed
    new_coverage_found: int = 0  # New edges found from this seed

    # Calculated energy
    energy: float = 1.0  # Fuzzing energy (iterations)

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    last_fuzzed: Optional[datetime] = None

    # Flags
    favored: bool = False  # Is this a favored seed?
    disabled: bool = False  # Skip this seed?


@dataclass
class EdgeInfo:
    """Information about a coverage edge."""
    edge_id: int
    hit_count: int = 0  # Total hits across all seeds
    seed_count: int = 0  # Number of seeds that hit this
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScheduleStats:
    """Statistics about the schedule."""
    total_seeds: int = 0
    favored_seeds: int = 0
    disabled_seeds: int = 0
    total_edges: int = 0
    rare_edges: int = 0  # Edges hit by <= 3 seeds
    average_energy: float = 0.0
    schedule_type: str = ""


class PowerScheduleService:
    """
    Sophisticated seed prioritization using power schedules.

    Key algorithms:

    1. RARE EDGE DETECTION
       - Track how many seeds hit each edge
       - Edges hit by few seeds are "rare" and valuable
       - Seeds hitting rare edges get more energy

    2. FAVORED SEED SELECTION
       - For each edge, pick the "best" seed that hits it
       - Best = fastest execution + smallest size
       - Favored seeds get priority in queue

    3. ENERGY CALCULATION
       - Base energy from schedule formula
       - Multiply by rare edge bonus
       - Multiply by history bonus (found bugs before?)
       - Cap at reasonable limits
    """

    # Constants
    RARE_EDGE_THRESHOLD = 3  # Edges hit by <= this many seeds are "rare"
    MIN_ENERGY = 1.0
    MAX_ENERGY = 10000.0
    DEFAULT_ENERGY = 100.0

    # Energy multipliers
    RARE_EDGE_MULTIPLIER = 4.0
    CRASH_HISTORY_MULTIPLIER = 2.0
    NEW_COV_MULTIPLIER = 1.5
    FAVORED_MULTIPLIER = 2.0
    DEPTH_PENALTY = 0.95  # Per depth level

    def __init__(
        self,
        schedule: PowerSchedule = PowerSchedule.EXPLORE,
        havoc_cycles: int = 256,
    ):
        self.schedule = schedule
        self.havoc_cycles = havoc_cycles

        # Seed storage
        self._seeds: Dict[str, SeedInfo] = {}
        self._seed_queue: List[str] = []  # Ordered queue

        # Edge tracking
        self._edges: Dict[int, EdgeInfo] = {}
        self._edge_to_seeds: Dict[int, Set[str]] = defaultdict(set)

        # Favored seeds (one per edge)
        self._favored_for_edge: Dict[int, str] = {}

        # Statistics
        self._total_execs = 0
        self._total_crashes = 0

        logger.info(f"PowerScheduleService initialized with schedule={schedule.value}")

    def add_seed(
        self,
        seed_data: bytes,
        edges_hit: Set[int],
        exec_time_us: int = 0,
        depth: int = 0,
        parent_id: Optional[str] = None,
    ) -> SeedInfo:
        """
        Add a new seed to the schedule.

        Args:
            seed_data: The seed bytes
            edges_hit: Set of edge IDs this seed covers
            exec_time_us: Execution time in microseconds
            depth: Mutation depth from original seed
            parent_id: ID of parent seed (if mutated from another)

        Returns:
            SeedInfo with calculated energy
        """
        seed_hash = hashlib.sha256(seed_data).hexdigest()[:16]
        seed_id = f"seed_{seed_hash}"

        # Check for duplicate
        if seed_id in self._seeds:
            return self._seeds[seed_id]

        # Create seed info
        seed = SeedInfo(
            seed_id=seed_id,
            seed_data=seed_data,
            seed_hash=seed_hash,
            exec_time_us=exec_time_us,
            depth=depth,
            edges_hit=edges_hit,
            bitmap_size=len(edges_hit),
        )

        # Update edge tracking
        new_edges = self._update_edge_tracking(seed)

        # Calculate initial energy
        seed.energy = self._calculate_energy(seed)

        # Check if this should be favored
        self._update_favored_seeds(seed)

        # Add to queue
        self._seeds[seed_id] = seed
        self._seed_queue.append(seed_id)

        if new_edges:
            logger.debug(f"Seed {seed_id} added, {len(new_edges)} new edges, energy={seed.energy:.1f}")

        return seed

    def _update_edge_tracking(self, seed: SeedInfo) -> Set[int]:
        """Update edge tracking and return set of NEW edges."""
        new_edges = set()

        for edge_id in seed.edges_hit:
            if edge_id not in self._edges:
                # New edge!
                self._edges[edge_id] = EdgeInfo(edge_id=edge_id)
                new_edges.add(edge_id)

            # Update edge info
            edge = self._edges[edge_id]
            edge.hit_count += 1
            edge.seed_count += 1
            edge.last_seen = datetime.utcnow()

            # Track which seeds hit this edge
            self._edge_to_seeds[edge_id].add(seed.seed_id)

        # Count unique and rare edges for this seed
        seed.unique_edges = sum(
            1 for e in seed.edges_hit
            if self._edges[e].seed_count == 1
        )
        seed.rare_edges = sum(
            1 for e in seed.edges_hit
            if self._edges[e].seed_count <= self.RARE_EDGE_THRESHOLD
        )
        seed.new_coverage_found = len(new_edges)

        return new_edges

    def _update_favored_seeds(self, seed: SeedInfo):
        """Update favored seed selection."""
        for edge_id in seed.edges_hit:
            current_favored = self._favored_for_edge.get(edge_id)

            if current_favored is None:
                # No favored seed for this edge yet
                self._favored_for_edge[edge_id] = seed.seed_id
                seed.favored = True
            else:
                # Compare with current favored
                current = self._seeds.get(current_favored)
                if current and self._is_better_seed(seed, current):
                    # This seed is better
                    self._favored_for_edge[edge_id] = seed.seed_id
                    seed.favored = True

                    # Check if old favored still favors any edge
                    still_favored = any(
                        fav == current_favored
                        for fav in self._favored_for_edge.values()
                    )
                    if not still_favored:
                        current.favored = False

    def _is_better_seed(self, new: SeedInfo, old: SeedInfo) -> bool:
        """Determine if new seed is better than old for favoring."""
        # Prefer faster execution
        if new.exec_time_us < old.exec_time_us * 0.8:
            return True

        # Prefer smaller seeds (same execution time)
        if abs(new.exec_time_us - old.exec_time_us) < 100:
            if len(new.seed_data) < len(old.seed_data) * 0.9:
                return True

        # Prefer seeds with more unique edges
        if new.unique_edges > old.unique_edges:
            return True

        return False

    def _calculate_energy(self, seed: SeedInfo) -> float:
        """
        Calculate fuzzing energy for a seed.

        Energy determines how many mutations we perform on this seed.
        Higher energy = more fuzzing time.
        """
        if self.schedule == PowerSchedule.FAST:
            energy = self._energy_fast(seed)
        elif self.schedule == PowerSchedule.COE:
            energy = self._energy_coe(seed)
        elif self.schedule == PowerSchedule.EXPLORE:
            energy = self._energy_explore(seed)
        elif self.schedule == PowerSchedule.EXPLOIT:
            energy = self._energy_exploit(seed)
        elif self.schedule == PowerSchedule.QUAD:
            energy = self._energy_quad(seed)
        elif self.schedule == PowerSchedule.LIN:
            energy = self._energy_lin(seed)
        elif self.schedule == PowerSchedule.RARE:
            energy = self._energy_rare(seed)
        else:
            energy = self.DEFAULT_ENERGY

        # Apply multipliers
        if seed.rare_edges > 0:
            rare_bonus = 1.0 + (seed.rare_edges / max(len(seed.edges_hit), 1)) * (self.RARE_EDGE_MULTIPLIER - 1)
            energy *= rare_bonus

        if seed.crashes_found > 0:
            energy *= self.CRASH_HISTORY_MULTIPLIER

        if seed.new_coverage_found > 0:
            energy *= self.NEW_COV_MULTIPLIER

        if seed.favored:
            energy *= self.FAVORED_MULTIPLIER

        # Depth penalty (deeper = less energy)
        if seed.depth > 0:
            energy *= (self.DEPTH_PENALTY ** seed.depth)

        # Clamp to bounds
        return max(self.MIN_ENERGY, min(self.MAX_ENERGY, energy))

    def _energy_fast(self, seed: SeedInfo) -> float:
        """FAST schedule: Inversely proportional to execution time."""
        if seed.exec_time_us <= 0:
            return self.DEFAULT_ENERGY

        # Faster seeds get more energy
        # Baseline: 1ms execution = 100 energy
        baseline_us = 1000
        return self.DEFAULT_ENERGY * (baseline_us / max(seed.exec_time_us, 1))

    def _energy_coe(self, seed: SeedInfo) -> float:
        """COE (Cut-Off Exponential): Focus on rare edge seeds."""
        if not seed.edges_hit:
            return self.MIN_ENERGY

        # Calculate average "rarity" of edges
        total_rarity = 0
        for edge_id in seed.edges_hit:
            edge = self._edges.get(edge_id)
            if edge:
                # Rarity = inverse of seed count
                total_rarity += 1.0 / max(edge.seed_count, 1)

        avg_rarity = total_rarity / len(seed.edges_hit)

        # Exponential based on rarity
        # avg_rarity of 1.0 = unique edge = high energy
        return self.DEFAULT_ENERGY * math.exp(avg_rarity * 2)

    def _energy_explore(self, seed: SeedInfo) -> float:
        """EXPLORE: Balance coverage and speed."""
        base = self.DEFAULT_ENERGY

        # Bonus for more edges
        coverage_bonus = 1.0 + (seed.bitmap_size / 1000)

        # Bonus for unique edges
        unique_bonus = 1.0 + (seed.unique_edges * 0.5)

        # Speed factor
        speed_factor = 1.0
        if seed.exec_time_us > 0:
            speed_factor = min(2.0, 1000 / seed.exec_time_us)

        return base * coverage_bonus * unique_bonus * speed_factor

    def _energy_exploit(self, seed: SeedInfo) -> float:
        """EXPLOIT: Focus on seeds that have found bugs."""
        base = self.DEFAULT_ENERGY

        # Big bonus for crash-finding seeds
        if seed.crashes_found > 0:
            base *= (1 + seed.crashes_found * 2)

        # Bonus for seeds that found new coverage
        if seed.new_coverage_found > 0:
            base *= (1 + seed.new_coverage_found * 0.1)

        return base

    def _energy_quad(self, seed: SeedInfo) -> float:
        """QUAD: Quadratic based on depth."""
        # Shallower seeds get quadratically more energy
        depth_factor = max(1, seed.depth)
        return self.DEFAULT_ENERGY * (1.0 / (depth_factor ** 2)) * 10

    def _energy_lin(self, seed: SeedInfo) -> float:
        """LIN: Linear based on depth."""
        depth_factor = max(1, seed.depth)
        return self.DEFAULT_ENERGY * (1.0 / depth_factor) * 2

    def _energy_rare(self, seed: SeedInfo) -> float:
        """RARE: Heavily prioritize seeds with rare edges."""
        if seed.rare_edges == 0:
            return self.MIN_ENERGY

        # Exponential bonus for rare edges
        return self.DEFAULT_ENERGY * (2 ** min(seed.rare_edges, 10))

    def get_next_seed(self) -> Optional[SeedInfo]:
        """
        Get the next seed to fuzz from the queue.

        Uses weighted selection based on energy.
        """
        if not self._seed_queue:
            return None

        # Filter out disabled seeds
        active_seeds = [
            sid for sid in self._seed_queue
            if sid in self._seeds and not self._seeds[sid].disabled
        ]

        if not active_seeds:
            return None

        # Weighted selection based on energy
        total_energy = sum(self._seeds[sid].energy for sid in active_seeds)
        if total_energy <= 0:
            # Fallback to random
            seed_id = random.choice(active_seeds)
        else:
            # Weighted random selection
            r = random.uniform(0, total_energy)
            cumulative = 0
            seed_id = active_seeds[-1]  # Default to last

            for sid in active_seeds:
                cumulative += self._seeds[sid].energy
                if cumulative >= r:
                    seed_id = sid
                    break

        seed = self._seeds[seed_id]
        seed.fuzz_count += 1
        seed.last_fuzzed = datetime.utcnow()

        return seed

    def report_crash(self, seed_id: str):
        """Report that a seed produced a crash."""
        if seed_id in self._seeds:
            self._seeds[seed_id].crashes_found += 1
            # Recalculate energy
            self._seeds[seed_id].energy = self._calculate_energy(self._seeds[seed_id])
            self._total_crashes += 1

    def report_new_coverage(self, seed_id: str, new_edges: int):
        """Report that a seed found new coverage."""
        if seed_id in self._seeds:
            self._seeds[seed_id].new_coverage_found += new_edges
            # Recalculate energy
            self._seeds[seed_id].energy = self._calculate_energy(self._seeds[seed_id])

    def get_mutation_count(self, seed: SeedInfo) -> int:
        """Get number of mutations to perform on this seed."""
        # Energy translates to havoc cycles
        base_cycles = self.havoc_cycles
        energy_factor = seed.energy / self.DEFAULT_ENERGY
        return max(1, int(base_cycles * energy_factor))

    def get_statistics(self) -> ScheduleStats:
        """Get schedule statistics."""
        if not self._seeds:
            return ScheduleStats(schedule_type=self.schedule.value)

        energies = [s.energy for s in self._seeds.values()]
        rare_edge_count = sum(
            1 for e in self._edges.values()
            if e.seed_count <= self.RARE_EDGE_THRESHOLD
        )

        return ScheduleStats(
            total_seeds=len(self._seeds),
            favored_seeds=sum(1 for s in self._seeds.values() if s.favored),
            disabled_seeds=sum(1 for s in self._seeds.values() if s.disabled),
            total_edges=len(self._edges),
            rare_edges=rare_edge_count,
            average_energy=sum(energies) / len(energies) if energies else 0,
            schedule_type=self.schedule.value,
        )

    def get_queue_state(self) -> List[Dict[str, Any]]:
        """Get current queue state for monitoring."""
        return [
            {
                "seed_id": s.seed_id,
                "energy": s.energy,
                "edges": len(s.edges_hit),
                "rare_edges": s.rare_edges,
                "fuzz_count": s.fuzz_count,
                "crashes": s.crashes_found,
                "favored": s.favored,
            }
            for s in sorted(
                self._seeds.values(),
                key=lambda x: x.energy,
                reverse=True,
            )[:20]  # Top 20
        ]


# =============================================================================
# Convenience Functions
# =============================================================================

_schedule_service: Optional[PowerScheduleService] = None


def get_power_schedule_service(
    schedule: PowerSchedule = PowerSchedule.EXPLORE,
) -> PowerScheduleService:
    """Get global power schedule service."""
    global _schedule_service
    if _schedule_service is None:
        _schedule_service = PowerScheduleService(schedule=schedule)
    return _schedule_service


def calculate_seed_energy(
    seed_data: bytes,
    edges_hit: Set[int],
    exec_time_us: int = 0,
    schedule: PowerSchedule = PowerSchedule.EXPLORE,
) -> float:
    """Convenience function to calculate energy for a seed."""
    service = get_power_schedule_service(schedule)
    seed = service.add_seed(seed_data, edges_hit, exec_time_us)
    return seed.energy
