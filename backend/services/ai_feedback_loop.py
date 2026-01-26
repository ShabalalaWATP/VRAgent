"""
AI Feedback Loop Service

Tracks AI suggestions and their outcomes to improve future decisions.
Enables the system to learn from what actually works.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

class SuggestionType(str, Enum):
    """Types of AI suggestions we track."""
    SEED = "seed"
    STRATEGY = "strategy"
    MUTATION = "mutation"
    FOCUS_AREA = "focus_area"
    BYPASS_TECHNIQUE = "bypass_technique"
    EXPLOIT_APPROACH = "exploit_approach"
    CVE_MATCH = "cve_match"


class OutcomeType(str, Enum):
    """Types of outcomes from suggestions."""
    COVERAGE_INCREASE = "coverage_increase"
    CRASH_FOUND = "crash_found"
    UNIQUE_CRASH = "unique_crash"
    EXPLOITABLE_CRASH = "exploitable_crash"
    NO_EFFECT = "no_effect"
    NEGATIVE_EFFECT = "negative_effect"


@dataclass
class Suggestion:
    """A recorded AI suggestion."""
    suggestion_id: str
    suggestion_type: SuggestionType
    content: Dict[str, Any]
    campaign_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Context at time of suggestion
    coverage_at_suggestion: float = 0.0
    crashes_at_suggestion: int = 0
    executions_at_suggestion: int = 0

    # AI metadata
    ai_confidence: float = 0.0
    ai_reasoning: str = ""


@dataclass
class Outcome:
    """Recorded outcome of a suggestion."""
    suggestion_id: str
    outcome_type: OutcomeType
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Metrics at outcome
    coverage_after: float = 0.0
    crashes_after: int = 0
    executions_after: int = 0

    # Delta from suggestion
    coverage_delta: float = 0.0
    crashes_delta: int = 0

    # Additional context
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SuggestionStats:
    """Statistics for a type of suggestion."""
    suggestion_type: SuggestionType
    total_suggestions: int = 0
    positive_outcomes: int = 0
    negative_outcomes: int = 0
    neutral_outcomes: int = 0

    # Effectiveness metrics
    avg_coverage_delta: float = 0.0
    avg_crashes_found: float = 0.0
    success_rate: float = 0.0

    # Timing
    avg_time_to_outcome: float = 0.0  # seconds


@dataclass
class FeedbackReport:
    """Summary report of AI effectiveness."""
    campaign_id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)

    # Overall metrics
    total_suggestions: int = 0
    effective_suggestions: int = 0
    overall_success_rate: float = 0.0

    # By type
    stats_by_type: Dict[str, SuggestionStats] = field(default_factory=dict)

    # Top performers
    most_effective_strategies: List[str] = field(default_factory=list)
    most_effective_mutations: List[str] = field(default_factory=list)

    # Recommendations for improvement
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# Feedback Loop Service
# =============================================================================

class AIFeedbackLoop:
    """
    Tracks AI suggestions and their outcomes to enable learning.

    This service:
    1. Records all AI suggestions with context
    2. Tracks outcomes (coverage increase, crashes, etc.)
    3. Computes effectiveness statistics
    4. Provides recommendations for future decisions
    """

    def __init__(self, persistence_service=None):
        self._suggestions: Dict[str, Suggestion] = {}
        self._outcomes: Dict[str, List[Outcome]] = defaultdict(list)
        self._stats_cache: Dict[str, SuggestionStats] = {}
        self._persistence = persistence_service

        # Pattern learning
        self._successful_patterns: Dict[str, int] = defaultdict(int)
        self._failed_patterns: Dict[str, int] = defaultdict(int)

    # =========================================================================
    # Recording
    # =========================================================================

    def record_suggestion(
        self,
        suggestion_type: SuggestionType,
        content: Dict[str, Any],
        campaign_id: str,
        coverage: float = 0.0,
        crashes: int = 0,
        executions: int = 0,
        ai_confidence: float = 0.0,
        ai_reasoning: str = "",
    ) -> str:
        """
        Record an AI suggestion for tracking.

        Returns suggestion_id for future outcome tracking.
        """
        suggestion_id = hashlib.md5(
            f"{campaign_id}:{suggestion_type}:{datetime.utcnow().isoformat()}:{json.dumps(content, sort_keys=True)[:100]}".encode()
        ).hexdigest()[:16]

        suggestion = Suggestion(
            suggestion_id=suggestion_id,
            suggestion_type=suggestion_type,
            content=content,
            campaign_id=campaign_id,
            coverage_at_suggestion=coverage,
            crashes_at_suggestion=crashes,
            executions_at_suggestion=executions,
            ai_confidence=ai_confidence,
            ai_reasoning=ai_reasoning,
        )

        self._suggestions[suggestion_id] = suggestion

        logger.debug(f"Recorded suggestion {suggestion_id}: {suggestion_type.value}")
        return suggestion_id

    def record_outcome(
        self,
        suggestion_id: str,
        outcome_type: OutcomeType,
        coverage: float = 0.0,
        crashes: int = 0,
        executions: int = 0,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Record the outcome of a suggestion."""
        suggestion = self._suggestions.get(suggestion_id)
        if not suggestion:
            logger.warning(f"Unknown suggestion_id: {suggestion_id}")
            return False

        outcome = Outcome(
            suggestion_id=suggestion_id,
            outcome_type=outcome_type,
            coverage_after=coverage,
            crashes_after=crashes,
            executions_after=executions,
            coverage_delta=coverage - suggestion.coverage_at_suggestion,
            crashes_delta=crashes - suggestion.crashes_at_suggestion,
            details=details or {},
        )

        self._outcomes[suggestion_id].append(outcome)

        # Update pattern learning
        self._update_patterns(suggestion, outcome)

        # Invalidate stats cache
        self._stats_cache.pop(str(suggestion.suggestion_type), None)

        logger.debug(f"Recorded outcome for {suggestion_id}: {outcome_type.value}")
        return True

    def _update_patterns(self, suggestion: Suggestion, outcome: Outcome) -> None:
        """Update pattern learning based on outcome."""
        # Extract pattern key from suggestion content
        pattern_key = self._extract_pattern_key(suggestion)

        if outcome.outcome_type in [
            OutcomeType.COVERAGE_INCREASE,
            OutcomeType.CRASH_FOUND,
            OutcomeType.UNIQUE_CRASH,
            OutcomeType.EXPLOITABLE_CRASH,
        ]:
            self._successful_patterns[pattern_key] += 1
        elif outcome.outcome_type == OutcomeType.NEGATIVE_EFFECT:
            self._failed_patterns[pattern_key] += 1

    def _extract_pattern_key(self, suggestion: Suggestion) -> str:
        """Extract a pattern key from suggestion for learning."""
        content = suggestion.content

        if suggestion.suggestion_type == SuggestionType.STRATEGY:
            return f"strategy:{content.get('name', 'unknown')}"
        elif suggestion.suggestion_type == SuggestionType.SEED:
            # Pattern based on seed characteristics
            seed_size = len(content.get('data', b''))
            return f"seed:size_{seed_size // 100 * 100}"
        elif suggestion.suggestion_type == SuggestionType.MUTATION:
            return f"mutation:{content.get('type', 'unknown')}"
        elif suggestion.suggestion_type == SuggestionType.FOCUS_AREA:
            return f"focus:{content.get('area', 'unknown')}"
        else:
            return f"{suggestion.suggestion_type.value}:unknown"

    # =========================================================================
    # Analysis
    # =========================================================================

    def get_stats(self, suggestion_type: Optional[SuggestionType] = None) -> Dict[str, SuggestionStats]:
        """Get effectiveness statistics by suggestion type."""
        if suggestion_type:
            types_to_analyze = [suggestion_type]
        else:
            types_to_analyze = list(SuggestionType)

        stats = {}
        for stype in types_to_analyze:
            cache_key = str(stype)
            if cache_key not in self._stats_cache:
                self._stats_cache[cache_key] = self._compute_stats(stype)
            stats[cache_key] = self._stats_cache[cache_key]

        return stats

    def _compute_stats(self, suggestion_type: SuggestionType) -> SuggestionStats:
        """Compute statistics for a suggestion type."""
        relevant_suggestions = [
            s for s in self._suggestions.values()
            if s.suggestion_type == suggestion_type
        ]

        if not relevant_suggestions:
            return SuggestionStats(suggestion_type=suggestion_type)

        positive = 0
        negative = 0
        neutral = 0
        total_coverage_delta = 0.0
        total_crashes_found = 0
        total_time_to_outcome = 0.0
        outcome_count = 0

        for suggestion in relevant_suggestions:
            outcomes = self._outcomes.get(suggestion.suggestion_id, [])

            for outcome in outcomes:
                outcome_count += 1

                # Time to outcome
                time_delta = (outcome.timestamp - suggestion.created_at).total_seconds()
                total_time_to_outcome += time_delta

                # Coverage delta
                total_coverage_delta += outcome.coverage_delta

                # Crashes
                total_crashes_found += outcome.crashes_delta

                # Classify
                if outcome.outcome_type in [
                    OutcomeType.COVERAGE_INCREASE,
                    OutcomeType.CRASH_FOUND,
                    OutcomeType.UNIQUE_CRASH,
                    OutcomeType.EXPLOITABLE_CRASH,
                ]:
                    positive += 1
                elif outcome.outcome_type == OutcomeType.NEGATIVE_EFFECT:
                    negative += 1
                else:
                    neutral += 1

        total = positive + negative + neutral
        success_rate = positive / total if total > 0 else 0.0

        return SuggestionStats(
            suggestion_type=suggestion_type,
            total_suggestions=len(relevant_suggestions),
            positive_outcomes=positive,
            negative_outcomes=negative,
            neutral_outcomes=neutral,
            avg_coverage_delta=total_coverage_delta / outcome_count if outcome_count > 0 else 0.0,
            avg_crashes_found=total_crashes_found / outcome_count if outcome_count > 0 else 0.0,
            success_rate=success_rate,
            avg_time_to_outcome=total_time_to_outcome / outcome_count if outcome_count > 0 else 0.0,
        )

    def generate_report(self, campaign_id: str) -> FeedbackReport:
        """Generate a comprehensive feedback report."""
        campaign_suggestions = [
            s for s in self._suggestions.values()
            if s.campaign_id == campaign_id
        ]

        # Get stats by type
        stats_by_type = self.get_stats()

        # Calculate overall metrics
        total = len(campaign_suggestions)
        effective = sum(
            1 for s in campaign_suggestions
            if any(
                o.outcome_type in [
                    OutcomeType.COVERAGE_INCREASE,
                    OutcomeType.CRASH_FOUND,
                    OutcomeType.UNIQUE_CRASH,
                    OutcomeType.EXPLOITABLE_CRASH,
                ]
                for o in self._outcomes.get(s.suggestion_id, [])
            )
        )

        # Find most effective strategies
        strategy_effectiveness = []
        for pattern, count in self._successful_patterns.items():
            if pattern.startswith("strategy:"):
                strategy_name = pattern.split(":", 1)[1]
                fail_count = self._failed_patterns.get(pattern, 0)
                success_rate = count / (count + fail_count) if (count + fail_count) > 0 else 0
                strategy_effectiveness.append((strategy_name, success_rate, count))

        strategy_effectiveness.sort(key=lambda x: (x[1], x[2]), reverse=True)
        most_effective_strategies = [s[0] for s in strategy_effectiveness[:5]]

        # Generate recommendations
        recommendations = self._generate_recommendations(stats_by_type, campaign_suggestions)

        return FeedbackReport(
            campaign_id=campaign_id,
            total_suggestions=total,
            effective_suggestions=effective,
            overall_success_rate=effective / total if total > 0 else 0.0,
            stats_by_type=stats_by_type,
            most_effective_strategies=most_effective_strategies,
            recommendations=recommendations,
        )

    def _generate_recommendations(
        self,
        stats: Dict[str, SuggestionStats],
        suggestions: List[Suggestion],
    ) -> List[str]:
        """Generate actionable recommendations based on feedback data."""
        recommendations = []

        # Check strategy effectiveness
        strategy_stats = stats.get(str(SuggestionType.STRATEGY))
        if strategy_stats and strategy_stats.success_rate < 0.3:
            recommendations.append(
                "Strategy suggestions have low success rate. Consider using more context-aware strategy selection."
            )

        # Check seed effectiveness
        seed_stats = stats.get(str(SuggestionType.SEED))
        if seed_stats:
            if seed_stats.avg_coverage_delta < 0.1:
                recommendations.append(
                    "AI-generated seeds are not significantly improving coverage. "
                    "Consider using format-aware seed generation or more diverse mutations."
                )
            if seed_stats.avg_crashes_found < 0.01:
                recommendations.append(
                    "AI seeds are finding few crashes. Focus on boundary conditions and malformed inputs."
                )

        # Check for underutilized successful patterns
        for pattern, count in self._successful_patterns.items():
            if count >= 5:  # Pattern has proven successful
                # Check if it's being used recently
                recent_suggestions = [
                    s for s in suggestions
                    if self._extract_pattern_key(s) == pattern
                    and (datetime.utcnow() - s.created_at) < timedelta(hours=1)
                ]
                if not recent_suggestions:
                    pattern_type, pattern_name = pattern.split(":", 1)
                    recommendations.append(
                        f"Successful pattern '{pattern_name}' ({pattern_type}) hasn't been used recently. "
                        "Consider prioritizing this approach."
                    )

        # Check for repeated failures
        for pattern, count in self._failed_patterns.items():
            if count >= 3:
                success_count = self._successful_patterns.get(pattern, 0)
                if success_count == 0 or count / (count + success_count) > 0.8:
                    pattern_type, pattern_name = pattern.split(":", 1)
                    recommendations.append(
                        f"Pattern '{pattern_name}' ({pattern_type}) has high failure rate. "
                        "Consider avoiding or modifying this approach."
                    )

        return recommendations[:10]  # Limit to top 10

    # =========================================================================
    # Decision Support
    # =========================================================================

    def get_recommended_approaches(
        self,
        suggestion_type: SuggestionType,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Get recommended approaches based on past success."""
        recommended = []

        # Find patterns with good success rates
        relevant_patterns = [
            (pattern, count)
            for pattern, count in self._successful_patterns.items()
            if pattern.startswith(f"{suggestion_type.value}:")
        ]

        for pattern, success_count in sorted(relevant_patterns, key=lambda x: x[1], reverse=True)[:limit]:
            fail_count = self._failed_patterns.get(pattern, 0)
            total = success_count + fail_count
            success_rate = success_count / total if total > 0 else 0.0

            _, approach_name = pattern.split(":", 1)
            recommended.append({
                "approach": approach_name,
                "success_rate": success_rate,
                "uses": total,
                "confidence": min(0.95, 0.5 + (total / 20) * 0.45),  # More uses = more confidence
            })

        return recommended

    def should_try_approach(
        self,
        suggestion_type: SuggestionType,
        approach_name: str,
    ) -> Tuple[bool, float, str]:
        """
        Decide whether to try an approach based on past data.

        Returns: (should_try, confidence, reasoning)
        """
        pattern_key = f"{suggestion_type.value}:{approach_name}"

        success_count = self._successful_patterns.get(pattern_key, 0)
        fail_count = self._failed_patterns.get(pattern_key, 0)
        total = success_count + fail_count

        if total == 0:
            # No data - explore
            return True, 0.5, "No prior data, worth exploring"

        success_rate = success_count / total

        if total < 3:
            # Not enough data
            return True, 0.5, f"Limited data ({total} uses), needs more exploration"

        if success_rate >= 0.5:
            confidence = min(0.95, 0.6 + success_rate * 0.35)
            return True, confidence, f"Good success rate ({success_rate:.1%} over {total} uses)"

        if success_rate >= 0.2:
            return True, 0.4, f"Moderate success rate ({success_rate:.1%}), may work in specific contexts"

        return False, 0.8, f"Low success rate ({success_rate:.1%} over {total} uses), consider alternatives"

    # =========================================================================
    # Persistence
    # =========================================================================

    async def save_to_db(self, campaign_id: str) -> bool:
        """Save feedback data to database."""
        if not self._persistence:
            return False

        try:
            # This would integrate with campaign_persistence.py
            # For now, just log
            logger.info(f"Feedback data for campaign {campaign_id}: {len(self._suggestions)} suggestions")
            return True
        except Exception as e:
            logger.error(f"Failed to save feedback data: {e}")
            return False

    def export_to_dict(self) -> Dict[str, Any]:
        """Export all feedback data to dictionary."""
        return {
            "suggestions": [
                {
                    "id": s.suggestion_id,
                    "type": s.suggestion_type.value,
                    "content": s.content,
                    "campaign_id": s.campaign_id,
                    "created_at": s.created_at.isoformat(),
                    "coverage": s.coverage_at_suggestion,
                    "crashes": s.crashes_at_suggestion,
                    "confidence": s.ai_confidence,
                }
                for s in self._suggestions.values()
            ],
            "outcomes": {
                sid: [
                    {
                        "type": o.outcome_type.value,
                        "timestamp": o.timestamp.isoformat(),
                        "coverage_delta": o.coverage_delta,
                        "crashes_delta": o.crashes_delta,
                    }
                    for o in outcomes
                ]
                for sid, outcomes in self._outcomes.items()
            },
            "successful_patterns": dict(self._successful_patterns),
            "failed_patterns": dict(self._failed_patterns),
        }


# =============================================================================
# Convenience Functions
# =============================================================================

# Global feedback loop instance
_feedback_loop: Optional[AIFeedbackLoop] = None


def get_feedback_loop() -> AIFeedbackLoop:
    """Get the global feedback loop instance."""
    global _feedback_loop
    if _feedback_loop is None:
        _feedback_loop = AIFeedbackLoop()
    return _feedback_loop


def record_suggestion(
    suggestion_type: SuggestionType,
    content: Dict[str, Any],
    campaign_id: str,
    **kwargs,
) -> str:
    """Convenience function to record a suggestion."""
    return get_feedback_loop().record_suggestion(
        suggestion_type, content, campaign_id, **kwargs
    )


def record_outcome(suggestion_id: str, outcome_type: OutcomeType, **kwargs) -> bool:
    """Convenience function to record an outcome."""
    return get_feedback_loop().record_outcome(suggestion_id, outcome_type, **kwargs)


from typing import Tuple
