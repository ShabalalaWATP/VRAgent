"""
Corpus Management Service - Advanced corpus management with coverage-guided selection.

This service provides:
- Coverage-guided input selection for fuzzing
- Differential coverage analysis between inputs
- Enhanced corpus minimization with progress reporting
- Coverage-based clustering
- Redundant input detection
"""

import asyncio
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Set, Tuple


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class CorpusEntry:
    """Enhanced corpus entry with coverage data."""
    id: str
    path: str
    data_hash: str
    size: int
    timestamp: float
    edge_count: int = 0
    unique_edges: int = 0
    new_edges_added: int = 0
    favored: bool = False
    depth: int = 0
    handicap: int = 0
    perf_score: float = 1.0
    execution_time_ms: float = 0.0
    edge_bitmap_hash: Optional[str] = None
    source: str = "unknown"  # manual, afl, concolic, taint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "data_hash": self.data_hash,
            "size": self.size,
            "timestamp": self.timestamp,
            "edge_count": self.edge_count,
            "unique_edges": self.unique_edges,
            "new_edges_added": self.new_edges_added,
            "favored": self.favored,
            "depth": self.depth,
            "perf_score": round(self.perf_score, 3),
            "execution_time_ms": round(self.execution_time_ms, 2),
            "source": self.source,
        }


@dataclass
class CorpusCoverageDelta:
    """Differential coverage analysis between inputs."""
    input_a: str
    input_b: str
    edges_only_a: Set[int]
    edges_only_b: Set[int]
    edges_common: Set[int]
    coverage_similarity: float  # Jaccard index

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_a": self.input_a,
            "input_b": self.input_b,
            "edges_only_a": len(self.edges_only_a),
            "edges_only_b": len(self.edges_only_b),
            "edges_common": len(self.edges_common),
            "coverage_similarity": round(self.coverage_similarity, 4),
            "edges_only_a_sample": list(self.edges_only_a)[:20],
            "edges_only_b_sample": list(self.edges_only_b)[:20],
        }


@dataclass
class MinimizationProgress:
    """Progress during corpus minimization."""
    phase: str  # analyzing, minimizing, finalizing
    total_inputs: int
    processed: int
    kept: int
    removed: int
    coverage_preserved_pct: float
    estimated_remaining_sec: float
    current_input: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "total_inputs": self.total_inputs,
            "processed": self.processed,
            "kept": self.kept,
            "removed": self.removed,
            "coverage_preserved_pct": round(self.coverage_preserved_pct, 2),
            "estimated_remaining_sec": round(self.estimated_remaining_sec, 1),
            "current_input": self.current_input,
            "error": self.error,
        }


@dataclass
class MinimizationResult:
    """Result of corpus minimization."""
    original_count: int
    minimized_count: int
    removed_count: int
    original_size_bytes: int
    minimized_size_bytes: int
    coverage_preserved_pct: float
    duration_sec: float
    output_dir: str
    kept_inputs: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_count": self.original_count,
            "minimized_count": self.minimized_count,
            "removed_count": self.removed_count,
            "original_size_bytes": self.original_size_bytes,
            "minimized_size_bytes": self.minimized_size_bytes,
            "size_reduction_pct": round(
                (1 - self.minimized_size_bytes / max(1, self.original_size_bytes)) * 100, 2
            ),
            "coverage_preserved_pct": round(self.coverage_preserved_pct, 2),
            "duration_sec": round(self.duration_sec, 2),
            "output_dir": self.output_dir,
        }


@dataclass
class IncrementalMinimizationState:
    """State for incremental minimization of large corpora."""
    session_id: str
    original_count: int
    minimized_count: int
    total_edges_preserved: int
    checkpoint_path: str
    last_processed: int
    is_complete: bool
    kept_hashes: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "original_count": self.original_count,
            "minimized_count": self.minimized_count,
            "total_edges_preserved": self.total_edges_preserved,
            "checkpoint_path": self.checkpoint_path,
            "last_processed": self.last_processed,
            "is_complete": self.is_complete,
            "progress_pct": round(self.last_processed / max(1, self.original_count) * 100, 1),
        }


@dataclass
class CoverageCluster:
    """A cluster of inputs with similar coverage."""
    cluster_id: int
    centroid_input: str
    members: List[str]
    common_edges: int
    average_similarity: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "centroid_input": self.centroid_input,
            "member_count": len(self.members),
            "common_edges": self.common_edges,
            "average_similarity": round(self.average_similarity, 4),
            "members": self.members[:10],  # First 10 members
        }


# ============================================================================
# Corpus Management Service
# ============================================================================


class CorpusManagementService:
    """
    Advanced corpus management with coverage-guided selection.

    Usage:
        service = CorpusManagementService(corpus_dir="/path/to/corpus")

        # Select inputs for next fuzzing round
        selected = await service.select_for_fuzzing(strategy="power_schedule", count=10)

        # Compare coverage between inputs
        delta = service.compare_coverage("input_a.bin", "input_b.bin")

        # Minimize corpus with progress
        async for progress in service.minimize_with_progress(output_dir):
            print(f"Progress: {progress.processed}/{progress.total_inputs}")
    """

    def __init__(
        self,
        corpus_dir: str,
        coverage_map_size: int = 65536,
    ):
        self.corpus_dir = corpus_dir
        self.coverage_map_size = coverage_map_size

        # In-memory tracking
        self._entries: Dict[str, CorpusEntry] = {}  # hash -> entry
        self._coverage_bitmaps: Dict[str, bytes] = {}  # hash -> bitmap
        self._edge_sets: Dict[str, Set[int]] = {}  # hash -> set of edge IDs
        self._global_coverage: Set[int] = set()  # All edges covered by corpus
        self._favored_inputs: Set[str] = set()

        # Scan corpus directory
        self._scan_corpus()

    def _scan_corpus(self):
        """Scan corpus directory and load entry metadata."""
        if not os.path.isdir(self.corpus_dir):
            return

        for entry in os.scandir(self.corpus_dir):
            if not entry.is_file():
                continue

            try:
                stat = entry.stat()
                with open(entry.path, "rb") as f:
                    data = f.read()

                data_hash = hashlib.sha256(data).hexdigest()[:16]

                corpus_entry = CorpusEntry(
                    id=entry.name,
                    path=entry.path,
                    data_hash=data_hash,
                    size=stat.st_size,
                    timestamp=stat.st_mtime,
                )

                self._entries[data_hash] = corpus_entry

            except Exception:
                continue

    # =========================================================================
    # Coverage-Guided Selection
    # =========================================================================

    async def select_for_fuzzing(
        self,
        strategy: str = "power_schedule",
        count: int = 10,
    ) -> List[CorpusEntry]:
        """
        Select inputs for next fuzzing round using coverage-guided selection.

        Strategies:
        - power_schedule: AFL-style power schedule favoring rare edges
        - round_robin: Simple rotation through corpus
        - favored_first: Prioritize inputs that cover unique edges
        - rare_edge: Focus on inputs that hit rarely-covered edges
        - random: Random selection
        """
        entries = list(self._entries.values())

        if not entries:
            return []

        if strategy == "power_schedule":
            return self._select_power_schedule(entries, count)
        elif strategy == "favored_first":
            return self._select_favored_first(entries, count)
        elif strategy == "rare_edge":
            return self._select_rare_edge(entries, count)
        elif strategy == "round_robin":
            return entries[:count]
        else:  # random
            import random
            return random.sample(entries, min(count, len(entries)))

    def _select_power_schedule(
        self,
        entries: List[CorpusEntry],
        count: int,
    ) -> List[CorpusEntry]:
        """AFL-style power schedule selection."""
        # Score inputs based on: unique edges, size, depth, performance
        scored = []
        for entry in entries:
            score = entry.perf_score
            if entry.favored:
                score *= 2.0
            if entry.unique_edges > 0:
                score *= (1 + entry.unique_edges / 10)
            if entry.size < 1000:  # Prefer smaller inputs
                score *= 1.5
            scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:count]]

    def _select_favored_first(
        self,
        entries: List[CorpusEntry],
        count: int,
    ) -> List[CorpusEntry]:
        """Select favored inputs first."""
        favored = [e for e in entries if e.favored]
        non_favored = [e for e in entries if not e.favored]

        result = favored[:count]
        if len(result) < count:
            result.extend(non_favored[:count - len(result)])

        return result

    def _select_rare_edge(
        self,
        entries: List[CorpusEntry],
        count: int,
    ) -> List[CorpusEntry]:
        """Select inputs that hit rare edges."""
        if not self._edge_sets:
            return entries[:count]

        # Count how many inputs hit each edge
        edge_counts: Dict[int, int] = {}
        for edge_set in self._edge_sets.values():
            for edge in edge_set:
                edge_counts[edge] = edge_counts.get(edge, 0) + 1

        # Score inputs by rarity of their edges
        scored = []
        for entry in entries:
            edge_set = self._edge_sets.get(entry.data_hash, set())
            if edge_set:
                rarity_score = sum(
                    1.0 / edge_counts.get(e, 1)
                    for e in edge_set
                ) / len(edge_set)
            else:
                rarity_score = 0

            scored.append((rarity_score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [e for _, e in scored[:count]]

    def calculate_input_priority(
        self,
        entry: CorpusEntry,
    ) -> float:
        """Calculate fuzzing priority based on coverage contribution."""
        priority = 1.0

        # Favor inputs with unique edges
        if entry.unique_edges > 0:
            priority += entry.unique_edges * 0.5

        # Favor smaller inputs
        if entry.size < 100:
            priority *= 2.0
        elif entry.size < 1000:
            priority *= 1.5

        # Favor favored inputs
        if entry.favored:
            priority *= 2.0

        # Consider performance score
        priority *= entry.perf_score

        return priority

    def identify_favored_inputs(self) -> List[CorpusEntry]:
        """Identify inputs that cover unique edges (favored inputs)."""
        if not self._edge_sets:
            return []

        # Find edges only covered by one input
        edge_to_inputs: Dict[int, List[str]] = {}
        for hash_val, edge_set in self._edge_sets.items():
            for edge in edge_set:
                if edge not in edge_to_inputs:
                    edge_to_inputs[edge] = []
                edge_to_inputs[edge].append(hash_val)

        # Find inputs that are the only one to cover at least one edge
        favored_hashes: Set[str] = set()
        for edge, input_hashes in edge_to_inputs.items():
            if len(input_hashes) == 1:
                favored_hashes.add(input_hashes[0])

        # Update entries
        for hash_val, entry in self._entries.items():
            entry.favored = hash_val in favored_hashes
            if entry.favored:
                entry.unique_edges = sum(
                    1 for e in self._edge_sets.get(hash_val, set())
                    if len(edge_to_inputs.get(e, [])) == 1
                )

        self._favored_inputs = favored_hashes

        return [e for e in self._entries.values() if e.favored]

    # =========================================================================
    # Differential Analysis
    # =========================================================================

    def compare_coverage(
        self,
        input_a_path: str,
        input_b_path: str,
    ) -> CorpusCoverageDelta:
        """Compare coverage between two inputs."""
        # Get edge sets for both inputs
        hash_a = self._get_hash_for_path(input_a_path)
        hash_b = self._get_hash_for_path(input_b_path)

        edges_a = self._edge_sets.get(hash_a, set())
        edges_b = self._edge_sets.get(hash_b, set())

        edges_only_a = edges_a - edges_b
        edges_only_b = edges_b - edges_a
        edges_common = edges_a & edges_b

        # Jaccard similarity
        union = edges_a | edges_b
        similarity = len(edges_common) / len(union) if union else 0.0

        return CorpusCoverageDelta(
            input_a=input_a_path,
            input_b=input_b_path,
            edges_only_a=edges_only_a,
            edges_only_b=edges_only_b,
            edges_common=edges_common,
            coverage_similarity=similarity,
        )

    def _get_hash_for_path(self, path: str) -> str:
        """Get hash for a file path."""
        for hash_val, entry in self._entries.items():
            if entry.path == path or entry.id == path:
                return hash_val

        # Not in cache, compute hash
        if os.path.isfile(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]

        return ""

    def find_similar_inputs(
        self,
        target_path: str,
        threshold: float = 0.9,
    ) -> List[Tuple[str, float]]:
        """Find inputs with similar coverage profiles."""
        target_hash = self._get_hash_for_path(target_path)
        target_edges = self._edge_sets.get(target_hash, set())

        if not target_edges:
            return []

        similar = []
        for hash_val, edge_set in self._edge_sets.items():
            if hash_val == target_hash:
                continue

            # Calculate Jaccard similarity
            intersection = len(target_edges & edge_set)
            union = len(target_edges | edge_set)
            similarity = intersection / union if union > 0 else 0.0

            if similarity >= threshold:
                entry = self._entries.get(hash_val)
                if entry:
                    similar.append((entry.path, similarity))

        similar.sort(key=lambda x: x[1], reverse=True)
        return similar

    def cluster_by_coverage(
        self,
        n_clusters: int = 10,
    ) -> List[CoverageCluster]:
        """Cluster corpus inputs by coverage similarity."""
        if not self._edge_sets or n_clusters <= 0:
            return []

        entries = list(self._entries.values())
        if len(entries) <= n_clusters:
            # Each input is its own cluster
            return [
                CoverageCluster(
                    cluster_id=i,
                    centroid_input=e.path,
                    members=[e.path],
                    common_edges=len(self._edge_sets.get(e.data_hash, set())),
                    average_similarity=1.0,
                )
                for i, e in enumerate(entries)
            ]

        # Simple greedy clustering
        clusters: List[CoverageCluster] = []
        assigned: Set[str] = set()

        # Sort by edge count (most edges first as potential centroids)
        sorted_entries = sorted(
            entries,
            key=lambda e: len(self._edge_sets.get(e.data_hash, set())),
            reverse=True,
        )

        cluster_id = 0
        for entry in sorted_entries:
            if entry.data_hash in assigned:
                continue

            if cluster_id >= n_clusters:
                break

            # Create new cluster with this entry as centroid
            centroid_edges = self._edge_sets.get(entry.data_hash, set())
            members = [entry.path]
            assigned.add(entry.data_hash)
            similarities = [1.0]

            # Find similar inputs for this cluster
            for other in sorted_entries:
                if other.data_hash in assigned:
                    continue

                other_edges = self._edge_sets.get(other.data_hash, set())
                intersection = len(centroid_edges & other_edges)
                union = len(centroid_edges | other_edges)
                similarity = intersection / union if union > 0 else 0.0

                if similarity >= 0.5:  # Similarity threshold
                    members.append(other.path)
                    assigned.add(other.data_hash)
                    similarities.append(similarity)

            clusters.append(CoverageCluster(
                cluster_id=cluster_id,
                centroid_input=entry.path,
                members=members,
                common_edges=len(centroid_edges),
                average_similarity=sum(similarities) / len(similarities),
            ))

            cluster_id += 1

        return clusters

    # =========================================================================
    # Enhanced Minimization
    # =========================================================================

    async def minimize_with_progress(
        self,
        output_dir: str,
        preserve_crashes: bool = True,
    ) -> AsyncGenerator[MinimizationProgress, None]:
        """Minimize corpus with progress reporting."""
        entries = list(self._entries.values())
        total = len(entries)

        if total == 0:
            yield MinimizationProgress(
                phase="complete",
                total_inputs=0,
                processed=0,
                kept=0,
                removed=0,
                coverage_preserved_pct=100.0,
                estimated_remaining_sec=0.0,
            )
            return

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Phase 1: Analyzing
        yield MinimizationProgress(
            phase="analyzing",
            total_inputs=total,
            processed=0,
            kept=0,
            removed=0,
            coverage_preserved_pct=100.0,
            estimated_remaining_sec=total * 0.01,
        )

        # Calculate total coverage
        total_edges = set()
        for edge_set in self._edge_sets.values():
            total_edges.update(edge_set)

        original_coverage = len(total_edges)

        # Sort by new edges added (greedy selection)
        sorted_entries = sorted(
            entries,
            key=lambda e: len(self._edge_sets.get(e.data_hash, set())),
            reverse=True,
        )

        # Phase 2: Minimizing
        kept_entries: List[CorpusEntry] = []
        kept_edges: Set[int] = set()
        start_time = time.time()

        for i, entry in enumerate(sorted_entries):
            entry_edges = self._edge_sets.get(entry.data_hash, set())
            new_edges = entry_edges - kept_edges

            # Keep if it adds new coverage
            if new_edges or (preserve_crashes and "crash" in entry.id.lower()):
                kept_entries.append(entry)
                kept_edges.update(entry_edges)

                # Copy to output
                src_path = entry.path
                dst_path = os.path.join(output_dir, entry.id)
                if os.path.isfile(src_path):
                    shutil.copy2(src_path, dst_path)

            # Report progress
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed if elapsed > 0 else 1
            remaining = (total - i - 1) / rate if rate > 0 else 0

            yield MinimizationProgress(
                phase="minimizing",
                total_inputs=total,
                processed=i + 1,
                kept=len(kept_entries),
                removed=i + 1 - len(kept_entries),
                coverage_preserved_pct=(len(kept_edges) / original_coverage * 100) if original_coverage > 0 else 100,
                estimated_remaining_sec=remaining,
                current_input=entry.id,
            )

            # Yield control periodically
            if i % 10 == 0:
                await asyncio.sleep(0)

        # Phase 3: Finalizing
        duration = time.time() - start_time

        yield MinimizationProgress(
            phase="complete",
            total_inputs=total,
            processed=total,
            kept=len(kept_entries),
            removed=total - len(kept_entries),
            coverage_preserved_pct=(len(kept_edges) / original_coverage * 100) if original_coverage > 0 else 100,
            estimated_remaining_sec=0,
        )

    async def incremental_minimize(
        self,
        output_dir: str,
        batch_size: int = 100,
        checkpoint_interval: int = 50,
    ) -> AsyncGenerator[MinimizationProgress, None]:
        """Incrementally minimize large corpus with checkpointing."""
        entries = list(self._entries.values())
        total = len(entries)

        if total == 0:
            yield MinimizationProgress(
                phase="complete",
                total_inputs=0,
                processed=0,
                kept=0,
                removed=0,
                coverage_preserved_pct=100.0,
                estimated_remaining_sec=0.0,
            )
            return

        os.makedirs(output_dir, exist_ok=True)
        checkpoint_file = os.path.join(output_dir, ".minimize_checkpoint")

        # Load checkpoint if exists
        kept_hashes: Set[str] = set()
        start_idx = 0
        if os.path.isfile(checkpoint_file):
            try:
                with open(checkpoint_file, "r") as f:
                    checkpoint = json.loads(f.read())
                    kept_hashes = set(checkpoint.get("kept_hashes", []))
                    start_idx = checkpoint.get("last_processed", 0)
            except (json.JSONDecodeError, Exception):
                pass

        # Sort entries
        sorted_entries = sorted(
            entries,
            key=lambda e: len(self._edge_sets.get(e.data_hash, set())),
            reverse=True,
        )

        kept_edges: Set[int] = set()
        for h in kept_hashes:
            kept_edges.update(self._edge_sets.get(h, set()))

        original_coverage = sum(len(s) for s in self._edge_sets.values())
        start_time = time.time()

        for i in range(start_idx, total):
            entry = sorted_entries[i]
            entry_edges = self._edge_sets.get(entry.data_hash, set())
            new_edges = entry_edges - kept_edges

            if new_edges:
                kept_hashes.add(entry.data_hash)
                kept_edges.update(entry_edges)

                # Copy to output
                dst_path = os.path.join(output_dir, entry.id)
                if os.path.isfile(entry.path):
                    shutil.copy2(entry.path, dst_path)

            # Checkpoint periodically
            if (i + 1) % checkpoint_interval == 0:
                with open(checkpoint_file, "w") as f:
                    f.write(json.dumps({
                        "kept_hashes": list(kept_hashes),
                        "last_processed": i + 1,
                    }))

            # Report progress
            elapsed = time.time() - start_time
            rate = (i - start_idx + 1) / elapsed if elapsed > 0 else 1
            remaining = (total - i - 1) / rate if rate > 0 else 0

            yield MinimizationProgress(
                phase="minimizing",
                total_inputs=total,
                processed=i + 1,
                kept=len(kept_hashes),
                removed=i + 1 - len(kept_hashes),
                coverage_preserved_pct=(len(kept_edges) / original_coverage * 100) if original_coverage > 0 else 100,
                estimated_remaining_sec=remaining,
                current_input=entry.id,
            )

            if i % batch_size == 0:
                await asyncio.sleep(0)

        # Clean up checkpoint
        if os.path.isfile(checkpoint_file):
            os.remove(checkpoint_file)

        yield MinimizationProgress(
            phase="complete",
            total_inputs=total,
            processed=total,
            kept=len(kept_hashes),
            removed=total - len(kept_hashes),
            coverage_preserved_pct=(len(kept_edges) / original_coverage * 100) if original_coverage > 0 else 100,
            estimated_remaining_sec=0,
        )

    # =========================================================================
    # Analysis
    # =========================================================================

    def get_coverage_contribution_report(self) -> Dict[str, Any]:
        """Report on each input's coverage contribution."""
        if not self._entries:
            return {
                "total_inputs": 0,
                "total_edges": 0,
                "inputs": [],
            }

        # Calculate contribution for each input
        total_edges = len(self._global_coverage)
        contributions = []

        for hash_val, entry in self._entries.items():
            edge_set = self._edge_sets.get(hash_val, set())
            unique = sum(
                1 for e in edge_set
                if sum(1 for s in self._edge_sets.values() if e in s) == 1
            )

            contributions.append({
                "id": entry.id,
                "path": entry.path,
                "size": entry.size,
                "total_edges": len(edge_set),
                "unique_edges": unique,
                "contribution_pct": (len(edge_set) / total_edges * 100) if total_edges > 0 else 0,
                "favored": entry.favored,
            })

        contributions.sort(key=lambda x: x["unique_edges"], reverse=True)

        return {
            "total_inputs": len(self._entries),
            "total_edges": total_edges,
            "favored_count": sum(1 for c in contributions if c["favored"]),
            "inputs": contributions,
        }

    def identify_redundant_inputs(self) -> List[str]:
        """Find inputs that add no unique coverage."""
        if not self._edge_sets:
            return []

        # Count how many inputs cover each edge
        edge_counts: Dict[int, int] = {}
        for edge_set in self._edge_sets.values():
            for edge in edge_set:
                edge_counts[edge] = edge_counts.get(edge, 0) + 1

        # Find inputs where all edges are covered by at least 2 inputs
        redundant = []
        for hash_val, entry in self._entries.items():
            edge_set = self._edge_sets.get(hash_val, set())
            if edge_set and all(edge_counts.get(e, 0) >= 2 for e in edge_set):
                redundant.append(entry.path)

        return redundant

    def get_corpus_stats(self) -> Dict[str, Any]:
        """Get overall corpus statistics."""
        total_size = sum(e.size for e in self._entries.values())
        avg_size = total_size / len(self._entries) if self._entries else 0

        return {
            "total_inputs": len(self._entries),
            "total_size_bytes": total_size,
            "average_size_bytes": int(avg_size),
            "total_edges": len(self._global_coverage),
            "favored_inputs": len(self._favored_inputs),
            "redundant_inputs": len(self.identify_redundant_inputs()),
        }

    # =========================================================================
    # Coverage Data Management
    # =========================================================================

    def register_input_coverage(
        self,
        input_path: str,
        coverage_bitmap: bytes,
    ):
        """Register coverage data for an input."""
        if not os.path.isfile(input_path):
            return

        with open(input_path, "rb") as f:
            data_hash = hashlib.sha256(f.read()).hexdigest()[:16]

        # Extract edge set from bitmap
        edge_set: Set[int] = set()
        for i, hit in enumerate(coverage_bitmap):
            if hit > 0:
                edge_set.add(i)

        self._coverage_bitmaps[data_hash] = coverage_bitmap
        self._edge_sets[data_hash] = edge_set
        self._global_coverage.update(edge_set)

        # Update entry if exists
        if data_hash in self._entries:
            self._entries[data_hash].edge_count = len(edge_set)

    def register_input_edges(
        self,
        input_path: str,
        edge_ids: Set[int],
    ):
        """Register edge IDs for an input (alternative to bitmap)."""
        if not os.path.isfile(input_path):
            return

        with open(input_path, "rb") as f:
            data_hash = hashlib.sha256(f.read()).hexdigest()[:16]

        self._edge_sets[data_hash] = edge_ids
        self._global_coverage.update(edge_ids)

        if data_hash in self._entries:
            self._entries[data_hash].edge_count = len(edge_ids)

    def clear_coverage_data(self):
        """Clear all cached coverage data."""
        self._coverage_bitmaps.clear()
        self._edge_sets.clear()
        self._global_coverage.clear()
        self._favored_inputs.clear()


# ============================================================================
# Factory Functions
# ============================================================================


def create_corpus_manager(
    corpus_dir: str,
    coverage_map_size: int = 65536,
) -> CorpusManagementService:
    """Create a corpus management service instance."""
    return CorpusManagementService(
        corpus_dir=corpus_dir,
        coverage_map_size=coverage_map_size,
    )


async def quick_minimize_corpus(
    input_dir: str,
    output_dir: str,
    coverage_data: Dict[str, bytes],
) -> MinimizationResult:
    """Quick corpus minimization with provided coverage data."""
    manager = CorpusManagementService(corpus_dir=input_dir)

    # Register coverage data
    for path, bitmap in coverage_data.items():
        manager.register_input_coverage(path, bitmap)

    # Run minimization
    start_time = time.time()
    kept_inputs = []
    original_size = 0
    minimized_size = 0

    async for progress in manager.minimize_with_progress(output_dir):
        if progress.phase == "complete":
            break

    # Calculate sizes
    for entry in manager._entries.values():
        original_size += entry.size

    for f in os.listdir(output_dir):
        path = os.path.join(output_dir, f)
        if os.path.isfile(path):
            minimized_size += os.path.getsize(path)
            kept_inputs.append(f)

    duration = time.time() - start_time

    return MinimizationResult(
        original_count=len(manager._entries),
        minimized_count=len(kept_inputs),
        removed_count=len(manager._entries) - len(kept_inputs),
        original_size_bytes=original_size,
        minimized_size_bytes=minimized_size,
        coverage_preserved_pct=100.0,  # Greedy minimization preserves all coverage
        duration_sec=duration,
        output_dir=output_dir,
        kept_inputs=kept_inputs,
    )
