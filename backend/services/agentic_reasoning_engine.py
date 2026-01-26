"""
Agentic Reasoning Engine

A truly agentic AI system for autonomous fuzzing that:
1. LEARNS from outcomes - tracks what works and adjusts future decisions
2. HAS MEMORY - remembers past decisions, successes, and failures
3. REASONS IN CHAINS - multi-step thinking with explicit reasoning
4. EXPLORES STRATEGICALLY - balances trying new things vs exploiting what works

This transforms the fuzzer from a simple "LLM makes one decision" system
into a genuine autonomous agent that improves over time.
"""

import asyncio
import hashlib
import json
import logging
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import os

logger = logging.getLogger(__name__)


# =============================================================================
# Memory System
# =============================================================================

@dataclass
class MemoryEntry:
    """A single memory entry tracking a decision and its outcome."""
    memory_id: str
    timestamp: datetime

    # What was decided
    decision_type: str
    decision_params: Dict[str, Any]
    reasoning: str

    # Context when decision was made
    coverage_before: float
    crashes_before: int
    exec_per_sec_before: float
    strategy_before: str

    # Outcome (filled in later)
    outcome_recorded: bool = False
    coverage_after: float = 0.0
    crashes_after: int = 0
    exec_per_sec_after: float = 0.0

    # Computed effectiveness
    was_effective: Optional[bool] = None
    effectiveness_score: float = 0.0  # -1.0 to 1.0

    # Learning tags
    tags: List[str] = field(default_factory=list)


@dataclass
class StrategyPerformance:
    """Tracks performance of a specific strategy."""
    strategy_name: str
    times_used: int = 0
    total_coverage_gained: float = 0.0
    total_crashes_found: int = 0
    total_time_used_seconds: float = 0.0

    # Computed metrics
    avg_coverage_per_hour: float = 0.0
    avg_crashes_per_hour: float = 0.0
    effectiveness_score: float = 0.5  # Prior belief

    # Bayesian tracking
    successes: int = 1  # Start with prior
    failures: int = 1   # Start with prior

    @property
    def success_rate(self) -> float:
        """Beta distribution mean."""
        return self.successes / (self.successes + self.failures)

    @property
    def confidence(self) -> float:
        """How confident are we in this estimate?"""
        total = self.successes + self.failures
        return min(1.0, total / 20)  # Need ~20 samples for high confidence


class AgentMemory:
    """
    Long-term memory for the agentic system.

    Stores:
    - Decision history with outcomes
    - Strategy performance statistics
    - Binary-specific patterns (what works for what type of binary)
    - Failed approaches to avoid
    """

    MAX_MEMORY_SIZE = 10000

    def __init__(self):
        # Decision memory
        self._memories: Dict[str, MemoryEntry] = {}
        self._memory_by_campaign: Dict[str, List[str]] = defaultdict(list)

        # Strategy performance tracking
        self._strategy_performance: Dict[str, StrategyPerformance] = {}

        # Pattern memory: binary_type -> strategy -> effectiveness
        self._binary_patterns: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

        # Failure memory: what to avoid
        self._failed_approaches: Dict[str, int] = defaultdict(int)  # approach -> failure count

        # Working memory for current reasoning
        self._working_memory: List[str] = []

        logger.info("AgentMemory initialized")

    def remember_decision(
        self,
        campaign_id: str,
        decision_type: str,
        decision_params: Dict[str, Any],
        reasoning: str,
        coverage: float,
        crashes: int,
        exec_per_sec: float,
        strategy: str,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Remember a decision that was made."""
        memory_id = hashlib.md5(
            f"{campaign_id}:{decision_type}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]

        entry = MemoryEntry(
            memory_id=memory_id,
            timestamp=datetime.utcnow(),
            decision_type=decision_type,
            decision_params=decision_params,
            reasoning=reasoning,
            coverage_before=coverage,
            crashes_before=crashes,
            exec_per_sec_before=exec_per_sec,
            strategy_before=strategy,
            tags=tags or [],
        )

        self._memories[memory_id] = entry
        self._memory_by_campaign[campaign_id].append(memory_id)

        # Prune if too large
        if len(self._memories) > self.MAX_MEMORY_SIZE:
            self._prune_old_memories()

        logger.debug(f"Remembered decision {memory_id}: {decision_type}")
        return memory_id

    def record_outcome(
        self,
        memory_id: str,
        coverage: float,
        crashes: int,
        exec_per_sec: float,
    ) -> None:
        """Record the outcome of a past decision."""
        if memory_id not in self._memories:
            logger.warning(f"Unknown memory_id: {memory_id}")
            return

        entry = self._memories[memory_id]
        entry.outcome_recorded = True
        entry.coverage_after = coverage
        entry.crashes_after = crashes
        entry.exec_per_sec_after = exec_per_sec

        # Compute effectiveness
        coverage_delta = coverage - entry.coverage_before
        crash_delta = crashes - entry.crashes_before

        # Effectiveness score: weighted combination
        # Coverage increase is good, crashes found is very good
        entry.effectiveness_score = min(1.0, max(-1.0,
            (coverage_delta * 0.1) +  # 10% coverage = +1.0
            (crash_delta * 0.5)       # 2 crashes = +1.0
        ))

        entry.was_effective = entry.effectiveness_score > 0

        # Update strategy performance
        self._update_strategy_performance(entry)

        # Update failure tracking
        if entry.effectiveness_score < -0.2:
            approach_key = f"{entry.decision_type}:{json.dumps(entry.decision_params, sort_keys=True)[:50]}"
            self._failed_approaches[approach_key] += 1

        logger.debug(f"Outcome for {memory_id}: effective={entry.was_effective}, score={entry.effectiveness_score:.2f}")

    def _update_strategy_performance(self, entry: MemoryEntry) -> None:
        """Update strategy performance based on outcome."""
        strategy = entry.strategy_before

        if strategy not in self._strategy_performance:
            self._strategy_performance[strategy] = StrategyPerformance(strategy_name=strategy)

        perf = self._strategy_performance[strategy]
        perf.times_used += 1
        perf.total_coverage_gained += max(0, entry.coverage_after - entry.coverage_before)
        perf.total_crashes_found += max(0, entry.crashes_after - entry.crashes_before)

        # Bayesian update
        if entry.was_effective:
            perf.successes += 1
        else:
            perf.failures += 1

    def get_strategy_performance(self, strategy: str) -> Optional[StrategyPerformance]:
        """Get performance stats for a strategy."""
        return self._strategy_performance.get(strategy)

    def get_best_strategies(self, top_n: int = 3) -> List[Tuple[str, float]]:
        """Get the best performing strategies."""
        if not self._strategy_performance:
            return []

        # Use Thompson Sampling score (samples from Beta distribution)
        scored = []
        for name, perf in self._strategy_performance.items():
            # Sample from Beta(successes, failures) - Thompson Sampling
            score = random.betavariate(perf.successes, perf.failures)
            scored.append((name, score, perf.confidence))

        # Sort by score * confidence (balance exploration/exploitation)
        scored.sort(key=lambda x: x[1] * (0.5 + 0.5 * x[2]), reverse=True)

        return [(name, score) for name, score, _ in scored[:top_n]]

    def get_recent_decisions(self, campaign_id: str, count: int = 10) -> List[MemoryEntry]:
        """Get recent decisions for a campaign."""
        memory_ids = self._memory_by_campaign.get(campaign_id, [])[-count:]
        return [self._memories[mid] for mid in memory_ids if mid in self._memories]

    def should_avoid(self, approach_key: str, threshold: int = 3) -> bool:
        """Check if an approach has failed too many times."""
        return self._failed_approaches.get(approach_key, 0) >= threshold

    def get_working_memory(self) -> List[str]:
        """Get current working memory (reasoning chain)."""
        return self._working_memory.copy()

    def add_to_working_memory(self, thought: str) -> None:
        """Add a thought to working memory."""
        self._working_memory.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {thought}")
        # Keep last 20 thoughts
        if len(self._working_memory) > 20:
            self._working_memory = self._working_memory[-20:]

    def clear_working_memory(self) -> None:
        """Clear working memory for new reasoning chain."""
        self._working_memory = []

    def _prune_old_memories(self) -> None:
        """Remove oldest memories to stay under limit."""
        sorted_mems = sorted(self._memories.items(), key=lambda x: x[1].timestamp)
        to_remove = len(sorted_mems) - self.MAX_MEMORY_SIZE + 1000  # Remove 1000 extra

        for memory_id, _ in sorted_mems[:to_remove]:
            del self._memories[memory_id]

    def get_memory_summary(self) -> Dict[str, Any]:
        """Get a summary of memory state."""
        return {
            "total_memories": len(self._memories),
            "strategies_tracked": len(self._strategy_performance),
            "failed_approaches": len(self._failed_approaches),
            "working_memory_size": len(self._working_memory),
            "best_strategies": self.get_best_strategies(3),
        }


# =============================================================================
# Chain-of-Thought Reasoning
# =============================================================================

@dataclass
class ReasoningStep:
    """A single step in a chain of reasoning."""
    step_number: int
    thought: str
    evidence: List[str]
    conclusion: Optional[str] = None
    confidence: float = 0.5


@dataclass
class ReasoningChain:
    """A complete chain of reasoning leading to a decision."""
    chain_id: str
    started_at: datetime
    steps: List[ReasoningStep] = field(default_factory=list)
    final_decision: Optional[str] = None
    final_confidence: float = 0.0
    reasoning_summary: str = ""


class ChainOfThoughtReasoner:
    """
    Implements multi-step reasoning with explicit chain-of-thought.

    Instead of making one LLM call for a decision, this:
    1. Analyzes the current situation
    2. Recalls relevant past experiences
    3. Generates hypotheses
    4. Evaluates each hypothesis
    5. Makes a final decision with full reasoning trace
    """

    def __init__(self, memory: AgentMemory, ai_client=None):
        self.memory = memory
        self.ai_client = ai_client
        self._current_chain: Optional[ReasoningChain] = None

    async def reason(
        self,
        campaign_state: Dict[str, Any],
        available_actions: List[str],
        context: str = "",
    ) -> ReasoningChain:
        """
        Perform multi-step reasoning to decide on an action.

        Returns a complete reasoning chain with the decision.
        """
        chain_id = hashlib.md5(f"{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        chain = ReasoningChain(chain_id=chain_id, started_at=datetime.utcnow())
        self._current_chain = chain

        self.memory.clear_working_memory()

        # Step 1: Situation Analysis
        step1 = await self._analyze_situation(campaign_state)
        chain.steps.append(step1)
        self.memory.add_to_working_memory(f"ANALYSIS: {step1.conclusion}")

        # Step 2: Recall Past Experiences
        step2 = await self._recall_experiences(campaign_state)
        chain.steps.append(step2)
        self.memory.add_to_working_memory(f"MEMORY: {step2.conclusion}")

        # Step 3: Generate Hypotheses
        step3 = await self._generate_hypotheses(campaign_state, available_actions, step1, step2)
        chain.steps.append(step3)
        self.memory.add_to_working_memory(f"HYPOTHESES: {step3.conclusion}")

        # Step 4: Evaluate Hypotheses
        step4 = await self._evaluate_hypotheses(campaign_state, step3)
        chain.steps.append(step4)
        self.memory.add_to_working_memory(f"EVALUATION: {step4.conclusion}")

        # Step 5: Make Final Decision
        step5 = await self._make_decision(campaign_state, step4)
        chain.steps.append(step5)

        chain.final_decision = step5.conclusion
        chain.final_confidence = step5.confidence
        chain.reasoning_summary = self._summarize_chain(chain)

        self.memory.add_to_working_memory(f"DECISION: {step5.conclusion} (confidence: {step5.confidence:.0%})")

        logger.info(f"Reasoning chain {chain_id} complete: {chain.final_decision}")
        return chain

    async def _analyze_situation(self, state: Dict[str, Any]) -> ReasoningStep:
        """Step 1: Analyze the current situation."""
        evidence = []

        coverage = state.get("coverage_percentage", 0)
        crashes = state.get("unique_crashes", 0)
        exec_per_sec = state.get("executions_per_second", 0)
        coverage_trend = state.get("coverage_trend", "unknown")
        elapsed_hours = state.get("elapsed_hours", 0)

        # Gather evidence
        if coverage < 20:
            evidence.append("Coverage is LOW (<20%) - still in early exploration phase")
        elif coverage < 50:
            evidence.append("Coverage is MODERATE (20-50%) - making progress")
        elif coverage < 80:
            evidence.append("Coverage is GOOD (50-80%) - hitting harder-to-reach paths")
        else:
            evidence.append("Coverage is HIGH (>80%) - diminishing returns expected")

        if coverage_trend == "plateau" or coverage_trend == "stable":
            evidence.append("Coverage has PLATEAUED - current approach isn't finding new paths")
        elif coverage_trend == "increasing":
            evidence.append("Coverage is INCREASING - current approach is working")
        elif coverage_trend == "decreasing":
            evidence.append("Coverage is DECREASING - something is wrong")

        if crashes > 0:
            evidence.append(f"Found {crashes} crashes - target has vulnerabilities")
        else:
            evidence.append("No crashes yet - target may be robust or inputs not reaching vulnerable code")

        if exec_per_sec < 100:
            evidence.append("Execution speed is SLOW - target may be complex or I/O bound")
        elif exec_per_sec > 10000:
            evidence.append("Execution speed is FAST - can try more aggressive mutations")

        # Form conclusion
        if coverage_trend in ["plateau", "stable"] and coverage < 80:
            conclusion = "Campaign is STUCK - need to change approach"
        elif crashes > 0 and state.get("exploitable_crashes", 0) == 0:
            conclusion = "Have crashes but none exploitable - need deeper analysis"
        elif coverage_trend == "increasing":
            conclusion = "Campaign is PROGRESSING - continue current approach with minor adjustments"
        else:
            conclusion = "Campaign status UNCLEAR - need more information"

        return ReasoningStep(
            step_number=1,
            thought="Analyzing current campaign state to understand where we are",
            evidence=evidence,
            conclusion=conclusion,
            confidence=0.8,
        )

    async def _recall_experiences(self, state: Dict[str, Any]) -> ReasoningStep:
        """Step 2: Recall relevant past experiences."""
        evidence = []

        campaign_id = state.get("campaign_id", "")
        recent_decisions = self.memory.get_recent_decisions(campaign_id, 5)

        # What have we tried?
        for entry in recent_decisions:
            if entry.outcome_recorded:
                outcome = "WORKED" if entry.was_effective else "DIDN'T WORK"
                evidence.append(f"Tried {entry.decision_type}: {outcome} (score: {entry.effectiveness_score:.2f})")

        # What strategies work best?
        best_strategies = self.memory.get_best_strategies(3)
        if best_strategies:
            for strat, score in best_strategies:
                evidence.append(f"Strategy '{strat}' has success rate ~{score:.0%}")

        # What to avoid?
        avoided = 0
        for approach, count in self.memory._failed_approaches.items():
            if count >= 3:
                avoided += 1
        if avoided > 0:
            evidence.append(f"{avoided} approaches marked as 'avoid' due to repeated failures")

        # Form conclusion
        if not recent_decisions:
            conclusion = "No past experience for this campaign - will rely on general knowledge"
        elif any(e.was_effective for e in recent_decisions if e.outcome_recorded):
            conclusion = "Some past decisions worked - can build on those successes"
        else:
            conclusion = "Recent decisions haven't been effective - need to try something different"

        return ReasoningStep(
            step_number=2,
            thought="Recalling past experiences to inform current decision",
            evidence=evidence,
            conclusion=conclusion,
            confidence=0.7,
        )

    async def _generate_hypotheses(
        self,
        state: Dict[str, Any],
        available_actions: List[str],
        analysis: ReasoningStep,
        memory: ReasoningStep,
    ) -> ReasoningStep:
        """Step 3: Generate possible hypotheses/actions."""
        evidence = []
        hypotheses = []

        coverage_trend = state.get("coverage_trend", "unknown")
        crashes = state.get("unique_crashes", 0)
        current_strategy = state.get("current_strategy", "coverage_guided")

        # Generate hypotheses based on analysis
        if "STUCK" in analysis.conclusion:
            if "concolic" not in current_strategy.lower():
                hypotheses.append({
                    "action": "enable_concolic",
                    "reasoning": "Coverage plateaued - symbolic execution can solve constraints",
                    "confidence": 0.7,
                })
            hypotheses.append({
                "action": "switch_strategy",
                "params": {"strategy": "directed_fuzzing"},
                "reasoning": "Try targeting specific uncovered functions",
                "confidence": 0.6,
            })
            hypotheses.append({
                "action": "generate_seeds",
                "reasoning": "New seeds might reach unexplored code paths",
                "confidence": 0.5,
            })

        if crashes > 0:
            hypotheses.append({
                "action": "switch_strategy",
                "params": {"strategy": "exploit_oriented"},
                "reasoning": "Have crashes - focus on understanding and exploiting them",
                "confidence": 0.8,
            })

        if "PROGRESSING" in analysis.conclusion:
            hypotheses.append({
                "action": "continue",
                "reasoning": "Current approach is working - don't fix what isn't broken",
                "confidence": 0.7,
            })
            hypotheses.append({
                "action": "scale_up",
                "reasoning": "Making progress - more resources could accelerate",
                "confidence": 0.5,
            })

        # Filter out actions we should avoid
        filtered_hypotheses = []
        for h in hypotheses:
            approach_key = f"{h['action']}:{json.dumps(h.get('params', {}), sort_keys=True)[:50]}"
            if self.memory.should_avoid(approach_key):
                evidence.append(f"SKIPPING {h['action']} - has failed repeatedly before")
            else:
                filtered_hypotheses.append(h)
                evidence.append(f"HYPOTHESIS: {h['action']} - {h['reasoning']}")

        if not filtered_hypotheses:
            # Fallback if all filtered out
            filtered_hypotheses.append({
                "action": "continue",
                "reasoning": "No good alternatives - continue current approach",
                "confidence": 0.4,
            })

        conclusion = f"Generated {len(filtered_hypotheses)} possible actions to consider"

        return ReasoningStep(
            step_number=3,
            thought="Generating possible actions based on analysis",
            evidence=evidence,
            conclusion=conclusion,
            confidence=0.6,
        )

    async def _evaluate_hypotheses(
        self,
        state: Dict[str, Any],
        hypotheses_step: ReasoningStep,
    ) -> ReasoningStep:
        """Step 4: Evaluate and rank hypotheses."""
        evidence = []

        # Parse hypotheses from evidence
        hypotheses = []
        for ev in hypotheses_step.evidence:
            if ev.startswith("HYPOTHESIS:"):
                # Extract action name
                action = ev.split("HYPOTHESIS:")[1].split("-")[0].strip()
                hypotheses.append(action)

        # Score each hypothesis
        scored = []
        for action in hypotheses:
            score = 0.5  # Base score

            # Check historical performance
            perf = self.memory.get_strategy_performance(action)
            if perf:
                score = perf.success_rate
                evidence.append(f"{action}: historical success rate {perf.success_rate:.0%}")
            else:
                evidence.append(f"{action}: no historical data, using prior")

            # Adjust based on current context
            coverage = state.get("coverage_percentage", 0)
            if action == "enable_concolic" and coverage > 50:
                score *= 1.2  # Concolic more useful when stuck at higher coverage
                evidence.append(f"{action}: boosted because coverage is high")

            if action == "continue" and state.get("coverage_trend") == "increasing":
                score *= 1.3  # Continue if making progress
                evidence.append(f"{action}: boosted because coverage is increasing")

            scored.append((action, min(1.0, score)))

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        if scored:
            best_action, best_score = scored[0]
            conclusion = f"Best action: {best_action} (score: {best_score:.2f})"
        else:
            conclusion = "No actions to evaluate - will continue"

        return ReasoningStep(
            step_number=4,
            thought="Evaluating hypotheses based on historical performance and context",
            evidence=evidence,
            conclusion=conclusion,
            confidence=0.75,
        )

    async def _make_decision(
        self,
        state: Dict[str, Any],
        evaluation: ReasoningStep,
    ) -> ReasoningStep:
        """Step 5: Make final decision."""
        evidence = []

        # Extract best action from evaluation
        if "Best action:" in evaluation.conclusion:
            parts = evaluation.conclusion.split("Best action:")[1]
            action = parts.split("(")[0].strip()
            score_part = parts.split("score:")[1].split(")")[0].strip() if "score:" in parts else "0.5"
            try:
                confidence = float(score_part)
            except (ValueError, TypeError, IndexError) as e:
                logger.debug(f"Could not parse confidence score: {e}, using default 0.5")
                confidence = 0.5
        else:
            action = "continue"
            confidence = 0.4

        evidence.append(f"Selected action: {action}")
        evidence.append(f"Confidence: {confidence:.0%}")

        # Add reasoning trace
        working_memory = self.memory.get_working_memory()
        if working_memory:
            evidence.append("Reasoning trace:")
            for thought in working_memory[-5:]:
                evidence.append(f"  {thought}")

        return ReasoningStep(
            step_number=5,
            thought="Making final decision based on evaluation",
            evidence=evidence,
            conclusion=action,
            confidence=confidence,
        )

    def _summarize_chain(self, chain: ReasoningChain) -> str:
        """Create a human-readable summary of the reasoning chain."""
        lines = [f"Reasoning Chain {chain.chain_id}:"]
        for step in chain.steps:
            lines.append(f"  Step {step.step_number}: {step.thought}")
            lines.append(f"    -> {step.conclusion}")
        lines.append(f"  FINAL: {chain.final_decision} (confidence: {chain.final_confidence:.0%})")
        return "\n".join(lines)


# =============================================================================
# Exploration vs Exploitation Strategy
# =============================================================================

class ExplorationStrategy(str, Enum):
    """Exploration strategies."""
    PURE_EXPLORATION = "pure_exploration"  # Try new things
    PURE_EXPLOITATION = "pure_exploitation"  # Use what works
    EPSILON_GREEDY = "epsilon_greedy"  # Mostly exploit, sometimes explore
    UCB = "ucb"  # Upper Confidence Bound
    THOMPSON_SAMPLING = "thompson_sampling"  # Bayesian approach


class ExplorationManager:
    """
    Manages the exploration vs exploitation tradeoff.

    Key insight: Early in a campaign, we should EXPLORE (try different strategies).
    Later, we should EXPLOIT (use what we know works).

    Uses Thompson Sampling for principled exploration.
    """

    def __init__(self, memory: AgentMemory):
        self.memory = memory
        self.strategy = ExplorationStrategy.THOMPSON_SAMPLING
        self.exploration_rate = 0.3  # For epsilon-greedy

        # Track exploration state
        self._total_decisions = 0
        self._exploration_decisions = 0
        self._exploitation_decisions = 0

    def should_explore(self, elapsed_fraction: float = 0.0) -> bool:
        """
        Decide whether to explore (try something new) or exploit (use best known).

        Args:
            elapsed_fraction: How much of the time budget has elapsed (0-1)

        Returns:
            True if we should explore, False if we should exploit
        """
        self._total_decisions += 1

        if self.strategy == ExplorationStrategy.PURE_EXPLORATION:
            self._exploration_decisions += 1
            return True

        if self.strategy == ExplorationStrategy.PURE_EXPLOITATION:
            self._exploitation_decisions += 1
            return False

        if self.strategy == ExplorationStrategy.EPSILON_GREEDY:
            # Decrease exploration over time
            adjusted_rate = self.exploration_rate * (1 - elapsed_fraction * 0.5)
            explore = random.random() < adjusted_rate
            if explore:
                self._exploration_decisions += 1
            else:
                self._exploitation_decisions += 1
            return explore

        if self.strategy == ExplorationStrategy.THOMPSON_SAMPLING:
            # Thompson Sampling naturally balances explore/exploit
            # We explore when uncertain, exploit when confident
            best_strategies = self.memory.get_best_strategies(3)
            if not best_strategies:
                self._exploration_decisions += 1
                return True  # No data, must explore

            # Check confidence in best strategy
            best_strat = best_strategies[0][0]
            perf = self.memory.get_strategy_performance(best_strat)
            if perf and perf.confidence > 0.8:
                self._exploitation_decisions += 1
                return False  # High confidence, exploit
            else:
                self._exploration_decisions += 1
                return True  # Low confidence, explore

        # Default
        return random.random() < 0.2

    def select_action(
        self,
        available_actions: List[str],
        elapsed_fraction: float = 0.0,
    ) -> Tuple[str, str]:
        """
        Select an action using exploration strategy.

        Returns:
            (action, mode) where mode is "explore" or "exploit"
        """
        if self.should_explore(elapsed_fraction):
            # Exploration: try something potentially new
            # Prefer actions with less data
            action_scores = []
            for action in available_actions:
                perf = self.memory.get_strategy_performance(action)
                if perf is None:
                    # Never tried, high exploration value
                    action_scores.append((action, 1.0))
                else:
                    # Less data = more exploration value
                    exploration_value = 1.0 - perf.confidence
                    action_scores.append((action, exploration_value))

            # Softmax selection
            total = sum(score for _, score in action_scores)
            if total == 0:
                return random.choice(available_actions), "explore"

            r = random.random() * total
            cumulative = 0
            for action, score in action_scores:
                cumulative += score
                if cumulative >= r:
                    return action, "explore"

            return action_scores[-1][0], "explore"

        else:
            # Exploitation: use best known action
            best_strategies = self.memory.get_best_strategies(len(available_actions))

            for strat, score in best_strategies:
                if strat in available_actions:
                    return strat, "exploit"

            # Fallback
            return available_actions[0] if available_actions else "continue", "exploit"

    def get_stats(self) -> Dict[str, Any]:
        """Get exploration statistics."""
        total = self._total_decisions or 1
        return {
            "total_decisions": self._total_decisions,
            "exploration_decisions": self._exploration_decisions,
            "exploitation_decisions": self._exploitation_decisions,
            "exploration_rate": self._exploration_decisions / total,
            "strategy": self.strategy.value,
        }


# =============================================================================
# Main Agentic Reasoning Engine
# =============================================================================

class AgenticReasoningEngine:
    """
    The main agentic reasoning engine that combines all components:
    - Memory system for learning from past decisions
    - Chain-of-thought reasoning for multi-step decision making
    - Exploration/exploitation for strategic action selection
    - Feedback loop integration for continuous improvement
    """

    def __init__(self, ai_client=None, feedback_loop=None):
        self.ai_client = ai_client
        self.feedback_loop = feedback_loop

        # Core components
        self.memory = AgentMemory()
        self.reasoner = ChainOfThoughtReasoner(self.memory, ai_client)
        self.explorer = ExplorationManager(self.memory)

        # Pending outcomes to track
        self._pending_outcomes: Dict[str, Dict[str, Any]] = {}

        # Available actions the agent can take
        self.available_actions = [
            "continue",
            "switch_strategy_coverage",
            "switch_strategy_directed",
            "switch_strategy_concolic",
            "switch_strategy_exploit",
            "enable_cmplog",
            "generate_seeds",
            "adjust_mutations",
            "scale_up",
            "scale_down",
            "minimize_corpus",
            "focus_function",
        ]

        logger.info("AgenticReasoningEngine initialized")

    async def decide(
        self,
        campaign_state: Dict[str, Any],
        force_reasoning: bool = False,
    ) -> Dict[str, Any]:
        """
        Make an agentic decision based on the current campaign state.

        This is the main entry point that:
        1. Records pending outcomes from previous decisions
        2. Uses chain-of-thought reasoning
        3. Balances exploration vs exploitation
        4. Returns a decision with full reasoning trace

        Args:
            campaign_state: Current state of the fuzzing campaign
            force_reasoning: If True, always use full reasoning chain

        Returns:
            Decision dict with action, parameters, reasoning, and confidence
        """
        campaign_id = campaign_state.get("campaign_id", "unknown")

        # Step 1: Record outcomes from previous decisions
        await self._record_pending_outcomes(campaign_state)

        # Step 2: Determine if we should explore or exploit
        elapsed = campaign_state.get("elapsed_hours", 0)
        max_duration = campaign_state.get("max_duration_hours", 24)
        elapsed_fraction = min(1.0, elapsed / max_duration) if max_duration > 0 else 0.5

        explore = self.explorer.should_explore(elapsed_fraction)

        # Step 3: Use reasoning chain for decision
        reasoning_chain = await self.reasoner.reason(
            campaign_state=campaign_state,
            available_actions=self.available_actions,
            context=f"Mode: {'EXPLORATION' if explore else 'EXPLOITATION'}",
        )

        # Step 4: Refine decision based on explore/exploit mode
        action = reasoning_chain.final_decision
        confidence = reasoning_chain.final_confidence

        if explore and confidence > 0.8:
            # High confidence but in explore mode - maybe try something else
            alternative_action, _ = self.explorer.select_action(
                [a for a in self.available_actions if a != action],
                elapsed_fraction,
            )
            # 30% chance to override with exploration
            if random.random() < 0.3:
                action = alternative_action
                confidence *= 0.8  # Lower confidence for exploration
                self.memory.add_to_working_memory(f"EXPLORATION OVERRIDE: Trying {action} instead")

        # Step 5: Convert action to decision parameters
        decision = self._action_to_decision(action, campaign_state)
        decision["confidence"] = confidence
        decision["reasoning_chain"] = reasoning_chain.reasoning_summary
        decision["mode"] = "explore" if explore else "exploit"

        # Step 6: Remember this decision for outcome tracking
        memory_id = self.memory.remember_decision(
            campaign_id=campaign_id,
            decision_type=decision["action"],
            decision_params=decision.get("parameters", {}),
            reasoning=reasoning_chain.reasoning_summary,
            coverage=campaign_state.get("coverage_percentage", 0),
            crashes=campaign_state.get("unique_crashes", 0),
            exec_per_sec=campaign_state.get("executions_per_second", 0),
            strategy=campaign_state.get("current_strategy", "unknown"),
            tags=[decision["mode"]],
        )

        # Track for outcome recording
        self._pending_outcomes[memory_id] = {
            "campaign_id": campaign_id,
            "decision": decision,
            "timestamp": datetime.utcnow(),
        }

        # Step 7: Record in feedback loop if available
        if self.feedback_loop:
            try:
                from backend.services.ai_feedback_loop import SuggestionType
                suggestion_type = self._action_to_suggestion_type(decision["action"])
                self.feedback_loop.record_suggestion(
                    suggestion_type=suggestion_type,
                    content=decision,
                    campaign_id=campaign_id,
                    coverage=campaign_state.get("coverage_percentage", 0),
                    crashes=campaign_state.get("unique_crashes", 0),
                    executions=campaign_state.get("total_executions", 0),
                    ai_confidence=confidence,
                    ai_reasoning=reasoning_chain.reasoning_summary,
                )
            except Exception as e:
                logger.debug(f"Failed to record in feedback loop: {e}")

        logger.info(
            f"Agentic decision: {decision['action']} "
            f"(mode={decision['mode']}, confidence={confidence:.0%})"
        )

        return decision

    async def _record_pending_outcomes(self, current_state: Dict[str, Any]) -> None:
        """Record outcomes for previous decisions."""
        campaign_id = current_state.get("campaign_id", "")

        to_remove = []
        for memory_id, pending in self._pending_outcomes.items():
            if pending["campaign_id"] != campaign_id:
                continue

            # Check if enough time has passed (at least 60 seconds)
            elapsed = (datetime.utcnow() - pending["timestamp"]).total_seconds()
            if elapsed < 60:
                continue

            # Record outcome
            self.memory.record_outcome(
                memory_id=memory_id,
                coverage=current_state.get("coverage_percentage", 0),
                crashes=current_state.get("unique_crashes", 0),
                exec_per_sec=current_state.get("executions_per_second", 0),
            )

            to_remove.append(memory_id)

        for memory_id in to_remove:
            del self._pending_outcomes[memory_id]

    def _action_to_decision(self, action: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an action name to a full decision dict."""
        decision = {
            "action": action,
            "parameters": {},
        }

        if action == "continue":
            decision["action_type"] = "continue"

        elif action.startswith("switch_strategy_"):
            strategy = action.replace("switch_strategy_", "")
            strategy_map = {
                "coverage": "coverage_guided",
                "directed": "directed_fuzzing",
                "concolic": "concolic_execution",
                "exploit": "exploit_oriented",
            }
            decision["action_type"] = "switch_strategy"
            decision["parameters"]["strategy"] = strategy_map.get(strategy, strategy)

        elif action == "enable_cmplog":
            decision["action_type"] = "enable_concolic"
            decision["parameters"]["enable_cmplog"] = True

        elif action == "generate_seeds":
            decision["action_type"] = "generate_seeds"
            decision["parameters"]["count"] = 10

        elif action == "adjust_mutations":
            decision["action_type"] = "adjust_mutations"
            # Adjust based on current performance
            if state.get("coverage_trend") == "plateau":
                decision["parameters"]["weights"] = {
                    "havoc": 0.5,  # More aggressive
                    "splice": 0.2,
                    "arithmetic": 0.15,
                    "dictionary": 0.15,
                }

        elif action == "scale_up":
            decision["action_type"] = "scale_up"
            decision["parameters"]["engines"] = 2

        elif action == "scale_down":
            decision["action_type"] = "scale_down"
            decision["parameters"]["engines"] = 1

        elif action == "minimize_corpus":
            decision["action_type"] = "minimize_corpus"

        elif action == "focus_function":
            decision["action_type"] = "focus_function"
            # Select a function to focus on based on campaign state
            target_function = self._select_focus_function(campaign_state)
            decision["parameters"]["function"] = target_function
            decision["parameters"]["reason"] = "Selected function with low coverage and high complexity"

        return decision

    def _select_focus_function(self, campaign_state: Dict[str, Any]) -> Optional[str]:
        """
        Select a function to focus directed fuzzing on.

        Prioritizes functions with:
        1. Low coverage but high complexity
        2. Known vulnerabilities or dangerous patterns
        3. Previously found crashes in related code

        Returns:
            Function name/address to focus on, or None if no suitable target
        """
        # Check if we have function coverage data
        function_coverage = campaign_state.get("function_coverage", {})
        binary_profile = campaign_state.get("profile", {})
        functions = binary_profile.get("functions", [])

        if not functions:
            # Fallback: suggest common vulnerable functions
            dangerous_functions = [
                "strcpy", "strcat", "sprintf", "gets", "scanf",
                "memcpy", "memmove", "read", "recv", "fread",
                "malloc", "realloc", "free",
            ]
            # Check binary imports
            imports = binary_profile.get("imports", [])
            for func in dangerous_functions:
                if any(func in imp.lower() for imp in imports):
                    logger.info(f"Selected dangerous function for focus: {func}")
                    return func
            return None

        # Find functions with low coverage but high complexity
        candidates = []
        for func in functions:
            func_name = func.get("name", func) if isinstance(func, dict) else str(func)
            coverage = function_coverage.get(func_name, 0)
            complexity = func.get("complexity", 10) if isinstance(func, dict) else 10

            # Prioritize low coverage + high complexity
            if coverage < 50:  # Less than 50% coverage
                score = complexity * (100 - coverage) / 100
                candidates.append((func_name, score))

        if candidates:
            # Sort by score descending, pick best
            candidates.sort(key=lambda x: x[1], reverse=True)
            best = candidates[0][0]
            logger.info(f"Selected function for focus: {best}")
            return best

        # Fallback: return first uncovered function
        for func in functions:
            func_name = func.get("name", func) if isinstance(func, dict) else str(func)
            if function_coverage.get(func_name, 0) < 100:
                return func_name

        return None

    def _action_to_suggestion_type(self, action: str):
        """Map action to SuggestionType."""
        from backend.services.ai_feedback_loop import SuggestionType

        if "strategy" in action:
            return SuggestionType.STRATEGY
        elif "seed" in action:
            return SuggestionType.SEED
        elif "mutation" in action:
            return SuggestionType.MUTATION
        elif "focus" in action:
            return SuggestionType.FOCUS_AREA
        else:
            return SuggestionType.STRATEGY

    def get_agent_state(self) -> Dict[str, Any]:
        """Get the current state of the agent for debugging/monitoring."""
        return {
            "memory": self.memory.get_memory_summary(),
            "exploration": self.explorer.get_stats(),
            "working_memory": self.memory.get_working_memory(),
            "pending_outcomes": len(self._pending_outcomes),
        }


# =============================================================================
# Convenience Functions
# =============================================================================

_agentic_engine: Optional[AgenticReasoningEngine] = None


def get_agentic_engine(ai_client=None, feedback_loop=None) -> AgenticReasoningEngine:
    """Get or create the global agentic reasoning engine."""
    global _agentic_engine
    if _agentic_engine is None:
        _agentic_engine = AgenticReasoningEngine(ai_client, feedback_loop)
    return _agentic_engine


async def make_agentic_decision(campaign_state: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to make an agentic decision."""
    engine = get_agentic_engine()
    return await engine.decide(campaign_state)


# =============================================================================
# Intelligent AFL++ Feature Selector
# =============================================================================

class AFLPPFeatureSelector:
    """
    Intelligently selects AFL++ features based on:
    1. Target characteristics (binary type, size, complexity)
    2. Campaign phase (early exploration vs late exploitation)
    3. Historical performance data
    4. Current campaign state

    This is what makes us BETTER than raw AFL++ - we dynamically
    tune the fuzzer for maximum effectiveness.
    """

    def __init__(self, memory: AgentMemory):
        self.memory = memory

        # Feature effectiveness tracking
        self._feature_performance: Dict[str, Dict[str, float]] = {
            "power_schedule": {},
            "cmplog": {"enabled": 0.5, "disabled": 0.5},
            "mopt": {"enabled": 0.5, "disabled": 0.5},
            "parallel_strategy": {},
        }

    def select_power_schedule(
        self,
        campaign_state: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> str:
        """
        Intelligently select power schedule based on campaign state.

        Returns: Power schedule name (fast, coe, explore, exploit, rare, etc.)
        """
        coverage = campaign_state.get("coverage_percentage", 0)
        crashes = campaign_state.get("unique_crashes", 0)
        elapsed_fraction = campaign_state.get("elapsed_fraction", 0)
        coverage_trend = campaign_state.get("coverage_trend", "unknown")

        # Decision logic based on campaign phase and state
        # Early phase (< 20% time): EXPLORE to find initial coverage
        if elapsed_fraction < 0.2:
            if coverage < 10:
                return "fast"  # Quick initial exploration
            return "explore"  # Broader exploration

        # Mid phase (20-60% time): Adapt based on progress
        if elapsed_fraction < 0.6:
            if coverage_trend == "plateau":
                # Coverage stuck - try RARE to find new edges
                return "rare"
            if crashes > 0:
                # Found crashes - balance between finding more and exploring
                return "coe"  # Cut-off exponential
            return "explore"

        # Late phase (60-80% time): More exploitation
        if elapsed_fraction < 0.8:
            if crashes > 0:
                return "exploit"  # Focus on crash-finding paths
            if coverage > 70:
                return "rare"  # Try to find last few edges
            return "mmopt"  # Modified MOpt for adaptive mutations

        # Final phase (> 80% time): Heavy exploitation
        if crashes > 0:
            return "exploit"
        return "seek"  # Seek any remaining coverage

    def should_enable_cmplog(
        self,
        campaign_state: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Decide whether to enable CMPLOG.

        CMPLOG is most useful when:
        - Target has magic bytes/checksums
        - Coverage is plateauing
        - We haven't found many crashes yet

        Returns: (should_enable, reasoning)
        """
        coverage = campaign_state.get("coverage_percentage", 0)
        coverage_trend = campaign_state.get("coverage_trend", "unknown")
        has_magic_bytes = target_info.get("has_magic_bytes", True)  # Assume yes

        # Always enable if target likely has magic bytes
        if has_magic_bytes and coverage < 50:
            return True, "Target likely has magic bytes, CMPLOG will help solve them"

        # Enable if coverage is stuck
        if coverage_trend == "plateau" and coverage < 80:
            return True, "Coverage plateaued, CMPLOG may find new paths through comparisons"

        # Enable early in campaign
        if campaign_state.get("elapsed_fraction", 0) < 0.3:
            return True, "Early campaign phase, CMPLOG helps with initial exploration"

        return False, "CMPLOG not critical at this stage"

    def select_parallel_config(
        self,
        campaign_state: Dict[str, Any],
        available_cpus: int,
    ) -> Dict[str, Any]:
        """
        Select optimal parallel fuzzing configuration.

        Returns configuration for parallel instances with diverse strategies.
        """
        coverage = campaign_state.get("coverage_percentage", 0)
        elapsed_fraction = campaign_state.get("elapsed_fraction", 0)

        # Determine number of instances
        num_instances = min(available_cpus, 8)  # Cap at 8

        # Configure diverse strategies for each instance
        configs = []

        # Main instance - always explore
        configs.append({
            "role": "main",
            "power_schedule": "explore",
            "skip_deterministic": False,
        })

        # Distribute strategies among secondary instances
        secondary_strategies = []

        if elapsed_fraction < 0.5:
            # Early: More exploration diversity
            secondary_strategies = ["rare", "fast", "coe", "explore", "mmopt", "seek", "quad"]
        else:
            # Late: More exploitation
            secondary_strategies = ["exploit", "rare", "coe", "fast", "mmopt", "explore", "seek"]

        for i in range(num_instances - 1):
            strategy = secondary_strategies[i % len(secondary_strategies)]
            configs.append({
                "role": "secondary",
                "power_schedule": strategy,
                "skip_deterministic": True,  # Secondaries skip deterministic
            })

        return {
            "num_instances": num_instances,
            "configs": configs,
            "sync_interval_seconds": 60,
        }

    def select_mutation_config(
        self,
        campaign_state: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Select optimal mutation configuration.

        Returns mutation settings including MOpt, custom mutators, etc.
        """
        coverage_trend = campaign_state.get("coverage_trend", "unknown")
        input_format = target_info.get("input_format", "binary")

        config = {
            "use_mopt": True,  # Almost always beneficial
            "use_radamsa": False,
            "use_grammar": False,
            "dictionary_tokens": [],
        }

        # Enable grammar mutator for structured inputs
        if input_format in ["json", "xml", "html", "javascript", "sql"]:
            config["use_grammar"] = True
            config["grammar_type"] = input_format

        # Radamsa for more aggressive mutations when stuck
        if coverage_trend == "plateau":
            config["use_radamsa"] = True

        return config

    def get_optimal_config(
        self,
        campaign_state: Dict[str, Any],
        target_info: Dict[str, Any],
        available_cpus: int = 4,
    ) -> Dict[str, Any]:
        """
        Get complete optimal AFL++ configuration.

        This is the main entry point that combines all feature selection.
        """
        power_schedule = self.select_power_schedule(campaign_state, target_info)
        enable_cmplog, cmplog_reason = self.should_enable_cmplog(campaign_state, target_info)
        parallel_config = self.select_parallel_config(campaign_state, available_cpus)
        mutation_config = self.select_mutation_config(campaign_state, target_info)

        config = {
            "power_schedule": power_schedule,
            "enable_cmplog": enable_cmplog,
            "cmplog_reason": cmplog_reason,
            "cmplog_level": 2 if enable_cmplog else 0,
            "parallel": parallel_config,
            "mutation": mutation_config,
            "reasoning": {
                "power_schedule": f"Selected '{power_schedule}' based on campaign state",
                "cmplog": cmplog_reason,
                "parallel": f"Using {parallel_config['num_instances']} instances with diverse strategies",
            },
        }

        # Record for learning
        self._record_config_selection(campaign_state, config)

        return config

    def _record_config_selection(
        self,
        campaign_state: Dict[str, Any],
        config: Dict[str, Any],
    ) -> None:
        """Record configuration selection for learning."""
        # Store selection in memory for outcome tracking
        selection_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "campaign_id": campaign_state.get("campaign_id", "unknown"),
            "coverage_at_selection": campaign_state.get("coverage_percentage", 0),
            "crashes_at_selection": campaign_state.get("unique_crashes", 0),
            "execs_at_selection": campaign_state.get("total_executions", 0),
            "config": {
                "power_schedule": config.get("power_schedule"),
                "enable_cmplog": config.get("enable_cmplog"),
                "num_instances": config.get("parallel", {}).get("num_instances", 1),
            },
        }

        # Store in pending selections (to be matched with outcomes later)
        if not hasattr(self, "_pending_selections"):
            self._pending_selections = []
        self._pending_selections.append(selection_record)

        # Keep only last 100 selections
        if len(self._pending_selections) > 100:
            self._pending_selections = self._pending_selections[-100:]

        logger.debug(
            f"Recorded config selection: schedule={config.get('power_schedule')}, "
            f"cmplog={config.get('enable_cmplog')}"
        )

    def record_config_outcome(
        self,
        config: Dict[str, Any],
        coverage_delta: float,
        crashes_found: int,
    ) -> None:
        """Record outcome of a configuration for future learning."""
        # Update feature performance tracking
        power_schedule = config.get("power_schedule")
        if power_schedule:
            current = self._feature_performance["power_schedule"].get(power_schedule, 0.5)
            # Bayesian update based on outcome
            success = coverage_delta > 0 or crashes_found > 0
            if success:
                self._feature_performance["power_schedule"][power_schedule] = min(1.0, current + 0.1)
            else:
                self._feature_performance["power_schedule"][power_schedule] = max(0.0, current - 0.05)

        # Track CMPLOG effectiveness
        cmplog_key = "enabled" if config.get("enable_cmplog") else "disabled"
        current = self._feature_performance["cmplog"].get(cmplog_key, 0.5)
        success = coverage_delta > 0 or crashes_found > 0
        if success:
            self._feature_performance["cmplog"][cmplog_key] = min(1.0, current + 0.1)


# Create global feature selector
_feature_selector: Optional[AFLPPFeatureSelector] = None


def get_feature_selector(memory: Optional[AgentMemory] = None) -> AFLPPFeatureSelector:
    """Get global feature selector."""
    global _feature_selector
    if _feature_selector is None:
        if memory is None:
            memory = AgentMemory()
        _feature_selector = AFLPPFeatureSelector(memory)
    return _feature_selector
