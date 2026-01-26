"""
MITM Agentic Brain

Provides the intelligent reasoning system for the MITM attack agent including:
- Memory system for attack decisions and outcomes (with database persistence)
- Chain-of-thought reasoning (5-step process)
- Thompson Sampling for explore/exploit balance
- Bayesian performance tracking per tool and target type
- Cross-session learning via persisted memories
"""

import json
import logging
import math
import random
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ============================================================================
# Database Persistence Helpers
# ============================================================================

def _get_db_session():
    """Get a database session for persistence operations."""
    try:
        from ..core.database import SessionLocal
        return SessionLocal()
    except Exception as e:
        logger.warning(f"Could not get database session: {e}")
        return None


def _save_memory_to_db(memory: 'MITMMemoryEntry', db: 'Session') -> bool:
    """Save a memory entry to the database."""
    try:
        from ..models.models import MITMAgentMemoryEntry

        db_entry = MITMAgentMemoryEntry(
            memory_id=memory.memory_id,
            tool_id=memory.tool_id,
            target_host=memory.target_host,
            target_type=memory.target_type,
            attack_surface_snapshot=memory.attack_surface_snapshot,
            reasoning_chain_id=memory.reasoning_chain_id,
            reasoning_steps=memory.reasoning_steps,
            confidence=memory.confidence,
            attack_succeeded=memory.attack_succeeded,
            credentials_captured=memory.credentials_captured,
            tokens_captured=memory.tokens_captured,
            sessions_hijacked=memory.sessions_hijacked,
            findings_generated=memory.findings_generated,
            effectiveness_score=memory.effectiveness_score,
            phase=memory.phase,
            chain_triggered=memory.chain_triggered,
            execution_time_ms=memory.execution_time_ms,
            error_message=memory.error_message,
        )
        db.add(db_entry)
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to save memory to database: {e}")
        db.rollback()
        return False


def _update_memory_in_db(memory_id: str, updates: Dict[str, Any], db: 'Session') -> bool:
    """Update a memory entry in the database."""
    try:
        from ..models.models import MITMAgentMemoryEntry

        db.query(MITMAgentMemoryEntry).filter(
            MITMAgentMemoryEntry.memory_id == memory_id
        ).update(updates)
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to update memory in database: {e}")
        db.rollback()
        return False


def _load_memories_from_db(
    target_host: Optional[str] = None,
    target_type: Optional[str] = None,
    limit: int = 100,
    db: 'Session' = None
) -> List['MITMMemoryEntry']:
    """Load memories from database with optional filters."""
    memories = []
    try:
        from ..models.models import MITMAgentMemoryEntry

        query = db.query(MITMAgentMemoryEntry)

        if target_host:
            query = query.filter(MITMAgentMemoryEntry.target_host == target_host)
        if target_type:
            query = query.filter(MITMAgentMemoryEntry.target_type == target_type)

        query = query.order_by(MITMAgentMemoryEntry.created_at.desc()).limit(limit)

        for row in query.all():
            memories.append(MITMMemoryEntry(
                memory_id=row.memory_id,
                timestamp=row.created_at,
                tool_id=row.tool_id,
                target_host=row.target_host,
                target_type=row.target_type or "",
                attack_surface_snapshot=row.attack_surface_snapshot or {},
                reasoning_chain_id=row.reasoning_chain_id or "",
                reasoning_steps=row.reasoning_steps or [],
                confidence=row.confidence or 0.0,
                attack_succeeded=row.attack_succeeded or False,
                credentials_captured=row.credentials_captured or 0,
                tokens_captured=row.tokens_captured or 0,
                sessions_hijacked=row.sessions_hijacked or 0,
                findings_generated=row.findings_generated or 0,
                effectiveness_score=row.effectiveness_score or 0.0,
                phase=row.phase or "",
                chain_triggered=row.chain_triggered,
                execution_time_ms=row.execution_time_ms or 0.0,
                error_message=row.error_message,
            ))
    except Exception as e:
        logger.error(f"Failed to load memories from database: {e}")

    return memories


def _save_tool_performance_to_db(tool_id: str, perf: 'MITMToolPerformance', db: 'Session') -> bool:
    """Save or update tool performance stats in database."""
    try:
        from ..models.models import MITMToolPerformanceStats

        for target_type in set(list(perf.target_type_successes.keys()) + list(perf.target_type_failures.keys())):
            successes = perf.target_type_successes.get(target_type, 0)
            failures = perf.target_type_failures.get(target_type, 0)

            existing = db.query(MITMToolPerformanceStats).filter(
                MITMToolPerformanceStats.tool_id == tool_id,
                MITMToolPerformanceStats.target_type == target_type
            ).first()

            if existing:
                existing.successes = successes
                existing.failures = failures
                existing.total_executions = perf.total_executions
                existing.total_findings = perf.total_findings
                existing.total_credentials = perf.total_credentials
                existing.effectiveness_history = perf.effectiveness_history[-100:]
            else:
                db_entry = MITMToolPerformanceStats(
                    tool_id=tool_id,
                    target_type=target_type,
                    successes=successes,
                    failures=failures,
                    total_executions=perf.total_executions,
                    total_findings=perf.total_findings,
                    total_credentials=perf.total_credentials,
                    effectiveness_history=perf.effectiveness_history[-100:],
                )
                db.add(db_entry)

        db.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to save tool performance to database: {e}")
        db.rollback()
        return False


def _load_tool_performance_from_db(db: 'Session') -> Dict[str, 'MITMToolPerformance']:
    """Load all tool performance stats from database."""
    tool_performance = {}
    try:
        from ..models.models import MITMToolPerformanceStats

        for row in db.query(MITMToolPerformanceStats).all():
            if row.tool_id not in tool_performance:
                tool_performance[row.tool_id] = MITMToolPerformance(tool_id=row.tool_id)

            perf = tool_performance[row.tool_id]
            perf.target_type_successes[row.target_type] = row.successes or 0
            perf.target_type_failures[row.target_type] = row.failures or 0
            perf.total_executions = max(perf.total_executions, row.total_executions or 0)
            perf.total_findings = max(perf.total_findings, row.total_findings or 0)
            perf.total_credentials = max(perf.total_credentials, row.total_credentials or 0)
            if row.effectiveness_history:
                perf.effectiveness_history.extend(row.effectiveness_history)

    except Exception as e:
        logger.error(f"Failed to load tool performance from database: {e}")

    return tool_performance


# ============================================================================
# Memory System
# ============================================================================

@dataclass
class MITMMemoryEntry:
    """Memory entry for a single attack decision and outcome."""
    memory_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Context
    tool_id: str = ""
    target_host: str = ""
    target_type: str = ""  # web_app, api, websocket, network, etc.
    attack_surface_snapshot: Dict[str, Any] = field(default_factory=dict)

    # Reasoning
    reasoning_chain_id: str = ""
    reasoning_steps: List[str] = field(default_factory=list)
    confidence: float = 0.0

    # Outcomes
    attack_succeeded: bool = False
    credentials_captured: int = 0
    tokens_captured: int = 0
    sessions_hijacked: int = 0
    findings_generated: int = 0
    effectiveness_score: float = 0.0  # -1.0 to 1.0

    # Metadata
    phase: str = ""
    chain_triggered: Optional[str] = None
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MITMMemoryEntry':
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


@dataclass
class MITMToolPerformance:
    """Bayesian performance tracking for a tool across target types."""
    tool_id: str

    # Success/failure counts per target type for Thompson Sampling
    target_type_successes: Dict[str, int] = field(default_factory=dict)
    target_type_failures: Dict[str, int] = field(default_factory=dict)

    # Overall statistics
    total_executions: int = 0
    total_successes: int = 0
    total_findings: int = 0
    total_credentials: int = 0

    # Effectiveness history
    effectiveness_history: List[float] = field(default_factory=list)

    def thompson_sample_for_target(self, target_type: str) -> float:
        """
        Thompson Sampling for explore/exploit balance.

        Uses Beta distribution to sample from posterior of success probability.
        More exploration early (high variance), more exploitation later (converges).
        """
        # Get success/failure counts for this target type
        successes = self.target_type_successes.get(target_type, 0)
        failures = self.target_type_failures.get(target_type, 0)

        # Prior: Beta(1, 1) = uniform
        # Posterior: Beta(1 + successes, 1 + failures)
        alpha = 1 + successes
        beta = 1 + failures

        # Sample from Beta distribution
        return np.random.beta(alpha, beta)

    def update_performance(self, target_type: str, success: bool, effectiveness: float):
        """Update performance tracking after tool execution."""
        self.total_executions += 1

        if success:
            self.total_successes += 1
            self.target_type_successes[target_type] = \
                self.target_type_successes.get(target_type, 0) + 1
        else:
            self.target_type_failures[target_type] = \
                self.target_type_failures.get(target_type, 0) + 1

        self.effectiveness_history.append(effectiveness)
        # Keep only last 100 effectiveness scores
        if len(self.effectiveness_history) > 100:
            self.effectiveness_history = self.effectiveness_history[-100:]

    @property
    def average_effectiveness(self) -> float:
        """Calculate average effectiveness across all executions."""
        if not self.effectiveness_history:
            return 0.0
        return sum(self.effectiveness_history) / len(self.effectiveness_history)

    @property
    def success_rate(self) -> float:
        """Calculate overall success rate."""
        if self.total_executions == 0:
            return 0.0
        return self.total_successes / self.total_executions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "target_type_successes": self.target_type_successes,
            "target_type_failures": self.target_type_failures,
            "total_executions": self.total_executions,
            "total_successes": self.total_successes,
            "total_findings": self.total_findings,
            "total_credentials": self.total_credentials,
            "average_effectiveness": self.average_effectiveness,
            "success_rate": self.success_rate
        }


class MITMAgentMemory:
    """
    Memory system for the MITM attack agent.

    Stores attack decisions, outcomes, and provides retrieval
    with relevance decay for learning from past experiences.

    Supports database persistence for cross-session learning when
    persist_to_db=True. Historical memories are loaded on initialization.
    """

    DECAY_RATE = 0.9  # 0.9^hours relevance decay

    def __init__(self, max_memories: int = 1000, persist_to_db: bool = True):
        self.memories: List[MITMMemoryEntry] = []
        self.max_memories = max_memories
        self.tool_performance: Dict[str, MITMToolPerformance] = {}
        self.session_id = str(uuid.uuid4())
        self.persist_to_db = persist_to_db
        self._db_session = None

        # Load historical data from database if persistence is enabled
        if persist_to_db:
            self._load_from_database()

    def _get_db(self):
        """Get or create database session."""
        if self._db_session is None:
            self._db_session = _get_db_session()
        return self._db_session

    def _load_from_database(self):
        """Load historical memories and tool performance from database."""
        db = self._get_db()
        if not db:
            logger.warning("Database not available, running without persistence")
            self.persist_to_db = False
            return

        try:
            # Load recent memories
            historical_memories = _load_memories_from_db(limit=self.max_memories, db=db)
            self.memories.extend(historical_memories)
            logger.info(f"Loaded {len(historical_memories)} historical memories from database")

            # Load tool performance stats
            self.tool_performance = _load_tool_performance_from_db(db)
            logger.info(f"Loaded performance stats for {len(self.tool_performance)} tools from database")

        except Exception as e:
            logger.error(f"Error loading from database: {e}")

    def _close_db(self):
        """Close database session."""
        if self._db_session:
            try:
                self._db_session.close()
            except Exception:
                pass
            self._db_session = None

    def remember_attack(
        self,
        tool_id: str,
        target_host: str,
        target_type: str,
        attack_surface: Dict[str, Any],
        reasoning_chain_id: str,
        reasoning_steps: List[str],
        confidence: float,
        phase: str
    ) -> str:
        """
        Store an attack decision with context.

        Returns the memory_id for later outcome recording.
        Persists to database for cross-session learning.
        """
        memory = MITMMemoryEntry(
            tool_id=tool_id,
            target_host=target_host,
            target_type=target_type,
            attack_surface_snapshot=attack_surface,
            reasoning_chain_id=reasoning_chain_id,
            reasoning_steps=reasoning_steps,
            confidence=confidence,
            phase=phase
        )

        self.memories.append(memory)

        # Persist to database
        if self.persist_to_db:
            db = self._get_db()
            if db:
                _save_memory_to_db(memory, db)

        # Trim old memories if needed
        if len(self.memories) > self.max_memories:
            self.memories = self.memories[-self.max_memories:]

        return memory.memory_id

    def record_outcome(
        self,
        memory_id: str,
        success: bool,
        credentials_captured: int = 0,
        tokens_captured: int = 0,
        sessions_hijacked: int = 0,
        findings_generated: int = 0,
        execution_time_ms: float = 0.0,
        chain_triggered: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """Record the outcome of an attack decision and persist to database."""
        memory = self._find_memory(memory_id)
        if not memory:
            logger.warning(f"Memory not found: {memory_id}")
            return

        memory.attack_succeeded = success
        memory.credentials_captured = credentials_captured
        memory.tokens_captured = tokens_captured
        memory.sessions_hijacked = sessions_hijacked
        memory.findings_generated = findings_generated
        memory.execution_time_ms = execution_time_ms
        memory.chain_triggered = chain_triggered
        memory.error_message = error_message

        # Calculate effectiveness score (-1.0 to 1.0)
        effectiveness = self._calculate_effectiveness(memory)
        memory.effectiveness_score = effectiveness

        # Update tool performance tracking
        self._update_tool_performance(memory)

        # Persist outcome to database
        if self.persist_to_db:
            db = self._get_db()
            if db:
                _update_memory_in_db(memory_id, {
                    'attack_succeeded': success,
                    'credentials_captured': credentials_captured,
                    'tokens_captured': tokens_captured,
                    'sessions_hijacked': sessions_hijacked,
                    'findings_generated': findings_generated,
                    'execution_time_ms': execution_time_ms,
                    'chain_triggered': chain_triggered,
                    'error_message': error_message,
                    'effectiveness_score': effectiveness,
                }, db)
                # Also persist updated tool performance
                _save_tool_performance_to_db(memory.tool_id, self.tool_performance[memory.tool_id], db)

    def _calculate_effectiveness(self, memory: MITMMemoryEntry) -> float:
        """Calculate effectiveness score based on outcomes."""
        if not memory.attack_succeeded:
            return -0.5 if memory.error_message else -0.2

        score = 0.2  # Base score for success

        # Add bonuses for valuable outcomes
        if memory.credentials_captured > 0:
            score += min(0.3, memory.credentials_captured * 0.1)
        if memory.tokens_captured > 0:
            score += min(0.2, memory.tokens_captured * 0.05)
        if memory.sessions_hijacked > 0:
            score += min(0.2, memory.sessions_hijacked * 0.1)
        if memory.findings_generated > 0:
            score += min(0.1, memory.findings_generated * 0.02)
        if memory.chain_triggered:
            score += 0.1

        return min(1.0, score)

    def _update_tool_performance(self, memory: MITMMemoryEntry):
        """Update tool performance tracking after outcome recorded."""
        tool_id = memory.tool_id

        if tool_id not in self.tool_performance:
            self.tool_performance[tool_id] = MITMToolPerformance(tool_id=tool_id)

        perf = self.tool_performance[tool_id]
        perf.update_performance(
            memory.target_type,
            memory.attack_succeeded,
            memory.effectiveness_score
        )

        if memory.attack_succeeded:
            perf.total_findings += memory.findings_generated
            perf.total_credentials += memory.credentials_captured

    def _find_memory(self, memory_id: str) -> Optional[MITMMemoryEntry]:
        """Find a memory by ID."""
        for m in reversed(self.memories):  # Recent first
            if m.memory_id == memory_id:
                return m
        return None

    def get_tool_performance(self, tool_id: str) -> Optional[MITMToolPerformance]:
        """Get Bayesian performance stats for a tool."""
        return self.tool_performance.get(tool_id)

    def get_best_tools_for_context(
        self,
        target_type: str,
        available_tools: List[str],
        top_n: int = 5
    ) -> List[Tuple[str, float]]:
        """
        Get best tools for context using Thompson sampling.

        Returns list of (tool_id, sampled_score) sorted by score.
        """
        scores = []

        for tool_id in available_tools:
            perf = self.tool_performance.get(tool_id)
            if perf:
                # Thompson sample for exploration/exploitation
                score = perf.thompson_sample_for_target(target_type)
            else:
                # No data - sample from uniform prior (high exploration)
                score = np.random.beta(1, 1)

            scores.append((tool_id, score))

        # Sort by sampled score descending
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_n]

    def get_similar_experiences(
        self,
        target_type: str,
        target_host: str,
        limit: int = 10
    ) -> List[MITMMemoryEntry]:
        """Get past experiences with similar targets."""
        similar = []
        now = datetime.utcnow()

        for memory in reversed(self.memories):
            # Check similarity
            if memory.target_type == target_type:
                # Calculate relevance with time decay
                hours_old = (now - memory.timestamp).total_seconds() / 3600
                relevance = self.DECAY_RATE ** hours_old

                if relevance > 0.1:  # Minimum relevance threshold
                    similar.append(memory)
                    if len(similar) >= limit:
                        break

        return similar

    def decay_memories(self):
        """
        Apply time-based relevance decay.

        Removes memories that have decayed below usefulness threshold.
        """
        now = datetime.utcnow()
        cutoff = timedelta(hours=48)  # Remove memories older than 48 hours

        self.memories = [
            m for m in self.memories
            if (now - m.timestamp) < cutoff
        ]

    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics for the current session."""
        if not self.memories:
            return {
                "total_attacks": 0,
                "successful_attacks": 0,
                "total_credentials": 0,
                "total_findings": 0,
                "average_effectiveness": 0.0
            }

        successful = [m for m in self.memories if m.attack_succeeded]

        return {
            "total_attacks": len(self.memories),
            "successful_attacks": len(successful),
            "success_rate": len(successful) / len(self.memories),
            "total_credentials": sum(m.credentials_captured for m in self.memories),
            "total_tokens": sum(m.tokens_captured for m in self.memories),
            "total_sessions_hijacked": sum(m.sessions_hijacked for m in self.memories),
            "total_findings": sum(m.findings_generated for m in self.memories),
            "average_effectiveness": sum(m.effectiveness_score for m in self.memories) / len(self.memories),
            "chains_triggered": len([m for m in self.memories if m.chain_triggered]),
            "unique_tools_used": len(set(m.tool_id for m in self.memories))
        }

    def export_memories(self) -> List[Dict[str, Any]]:
        """Export all memories as dictionaries."""
        return [m.to_dict() for m in self.memories]

    def import_memories(self, data: List[Dict[str, Any]]):
        """Import memories from dictionaries."""
        for item in data:
            memory = MITMMemoryEntry.from_dict(item)
            self.memories.append(memory)


# ============================================================================
# Chain-of-Thought Reasoning
# ============================================================================

class ReasoningStep(str, Enum):
    """Steps in the chain-of-thought reasoning process."""
    SITUATION_ANALYSIS = "situation_analysis"
    RECALL_EXPERIENCES = "recall_experiences"
    GENERATE_HYPOTHESES = "generate_hypotheses"
    EVALUATE_HYPOTHESES = "evaluate_hypotheses"
    DECIDE = "decide"


@dataclass
class ReasoningChain:
    """A complete chain-of-thought reasoning trace."""
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Input context
    attack_surface: Dict[str, Any] = field(default_factory=dict)
    current_phase: str = ""
    available_tools: List[str] = field(default_factory=list)

    # Reasoning steps
    situation_analysis: str = ""
    recalled_experiences: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    hypothesis_evaluations: List[Dict[str, Any]] = field(default_factory=list)

    # Decision
    selected_tool: Optional[str] = None
    confidence: float = 0.0
    reasoning_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


class MITMChainOfThoughtReasoner:
    """
    Chain-of-thought reasoning engine for attack decisions.

    5-step reasoning process:
    1. Situation Analysis - Analyze traffic, attack surface, security gaps
    2. Recall Experiences - What worked on similar targets?
    3. Generate Hypotheses - Which attacks could succeed?
    4. Evaluate Hypotheses - Score using Thompson sampling + context
    5. Decide - Select action with full reasoning trace
    """

    def __init__(self, memory: MITMAgentMemory):
        self.memory = memory
        self.reasoning_chains: List[ReasoningChain] = []
        self.min_confidence_threshold = 0.2  # Aggressive: execute at 20%

    def reason(
        self,
        attack_surface: Dict[str, Any],
        current_phase: str,
        available_tools: List[str],
        phase_relevant_tools: List[str],
        previous_findings: Optional[List[Dict[str, Any]]] = None,
        failed_tools: Optional[Dict[str, int]] = None
    ) -> ReasoningChain:
        """
        Execute full chain-of-thought reasoning.

        Args:
            attack_surface: Current attack surface analysis
            current_phase: Current attack phase
            available_tools: All available tools
            phase_relevant_tools: Tools relevant to current phase
            previous_findings: Findings from previously executed tools (enables contextual decisions)
            failed_tools: Dict of tool_id -> consecutive_failures (for cooldown/backoff)

        Returns a ReasoningChain with the selected tool and confidence.
        """
        chain = ReasoningChain(
            attack_surface=attack_surface,
            current_phase=current_phase,
            available_tools=available_tools
        )

        # Enrich attack surface with previous findings for contextual reasoning
        enriched_surface = dict(attack_surface)
        if previous_findings:
            enriched_surface["previous_findings"] = previous_findings
            enriched_surface["findings_count"] = len(previous_findings)
            # Extract key insights from findings
            finding_types = set()
            for f in previous_findings:
                if isinstance(f, dict):
                    finding_types.add(f.get("type", f.get("category", "unknown")))
            enriched_surface["finding_types"] = list(finding_types)

        # Track failed tools for backoff
        self._failed_tools = failed_tools or {}

        # Step 1: Situation Analysis (now includes findings context)
        chain.situation_analysis = self._analyze_situation(enriched_surface, current_phase)

        # Step 2: Recall Experiences
        target_type = attack_surface.get("target_type", "web_app")
        target_host = attack_surface.get("target_host", "unknown")
        similar = self.memory.get_similar_experiences(target_type, target_host, limit=5)
        chain.recalled_experiences = [
            {
                "tool_id": m.tool_id,
                "success": m.attack_succeeded,
                "effectiveness": m.effectiveness_score,
                "credentials_captured": m.credentials_captured
            }
            for m in similar
        ]

        # Step 3: Generate Hypotheses
        chain.hypotheses = self._generate_hypotheses(
            attack_surface,
            current_phase,
            phase_relevant_tools,
            chain.recalled_experiences
        )

        # Step 4: Evaluate Hypotheses
        chain.hypothesis_evaluations = self._evaluate_hypotheses(
            chain.hypotheses,
            target_type,
            attack_surface
        )

        # Step 5: Decide
        if chain.hypothesis_evaluations:
            best = chain.hypothesis_evaluations[0]
            chain.selected_tool = best["tool_id"]
            chain.confidence = best["final_score"]
            chain.reasoning_summary = self._generate_summary(chain)
        else:
            chain.selected_tool = None
            chain.confidence = 0.0
            chain.reasoning_summary = "No viable attack options identified."

        self.reasoning_chains.append(chain)
        return chain

    def _analyze_situation(self, attack_surface: Dict[str, Any], current_phase: str) -> str:
        """Step 1: Analyze the current attack situation."""
        analysis_parts = []

        # Traffic analysis
        traffic_count = attack_surface.get("traffic_count", 0)
        if traffic_count == 0:
            analysis_parts.append("No traffic captured yet - reconnaissance needed")
        elif traffic_count < 10:
            analysis_parts.append(f"Limited traffic ({traffic_count} requests) - building picture")
        else:
            analysis_parts.append(f"Good traffic volume ({traffic_count} requests) - attack surface visible")

        # Security posture
        missing_headers = attack_surface.get("missing_security_headers", [])
        if missing_headers:
            analysis_parts.append(f"Security gaps: missing {', '.join(missing_headers[:3])}")

        # Credentials visibility
        if attack_surface.get("credentials_visible"):
            analysis_parts.append("CRITICAL: Credentials visible in traffic")

        # Protocol weaknesses
        if attack_surface.get("http_only_traffic"):
            analysis_parts.append("HTTP-only traffic - SSL strip viable")

        if attack_surface.get("jwt_tokens_present"):
            analysis_parts.append("JWT tokens detected - token manipulation viable")

        # Phase context
        analysis_parts.append(f"Current phase: {current_phase}")

        return ". ".join(analysis_parts)

    def _generate_hypotheses(
        self,
        attack_surface: Dict[str, Any],
        current_phase: str,
        phase_relevant_tools: List[str],
        recalled_experiences: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Step 3: Generate attack hypotheses."""
        hypotheses = []

        # Get tools that match current triggers
        triggers = self._extract_triggers(attack_surface)

        for tool_id in phase_relevant_tools:
            # Base hypothesis
            hypothesis = {
                "tool_id": tool_id,
                "reason": f"Tool available for {current_phase} phase",
                "trigger_match": False,
                "experience_match": False
            }

            # Check if tool triggers match
            # This would be expanded with actual tool trigger checking
            if any(t in triggers for t in self._get_tool_triggers(tool_id)):
                hypothesis["trigger_match"] = True
                hypothesis["reason"] = f"Triggered by: {', '.join(triggers)}"

            # Check if tool worked before on similar targets
            for exp in recalled_experiences:
                if exp["tool_id"] == tool_id and exp["success"]:
                    hypothesis["experience_match"] = True
                    hypothesis["past_effectiveness"] = exp["effectiveness"]
                    break

            hypotheses.append(hypothesis)

        return hypotheses

    def _extract_triggers(self, attack_surface: Dict[str, Any]) -> List[str]:
        """Extract attack triggers from attack surface."""
        triggers = []

        if attack_surface.get("missing_security_headers"):
            missing = attack_surface["missing_security_headers"]
            if "strict-transport-security" in [h.lower() for h in missing]:
                triggers.append("missing_hsts")
            if "content-security-policy" in [h.lower() for h in missing]:
                triggers.append("missing_csp")

        if attack_surface.get("http_only_traffic"):
            triggers.append("http_traffic")
            triggers.append("no_https")

        if attack_surface.get("cookies_present"):
            triggers.append("cookies_detected")
            if not attack_surface.get("cookies_secure"):
                triggers.append("cookie_no_secure")
            if not attack_surface.get("cookies_httponly"):
                triggers.append("cookie_no_httponly")

        if attack_surface.get("jwt_tokens_present"):
            triggers.append("jwt_token_detected")

        if attack_surface.get("api_endpoints"):
            triggers.append("api_endpoints_detected")

        if attack_surface.get("websocket_traffic"):
            triggers.append("websocket_traffic_detected")

        if attack_surface.get("form_detected"):
            triggers.append("html_form_present")

        if attack_surface.get("login_page"):
            triggers.append("login_page_detected")

        return triggers

    def _get_tool_triggers(self, tool_id: str) -> List[str]:
        """Get triggers for a tool (would be loaded from tool registry)."""
        # Simplified trigger mapping - actual implementation would
        # query the tool registry
        trigger_map = {
            "sslstrip": ["missing_hsts", "http_traffic", "no_https"],
            "credential_sniffer": ["http_traffic", "form_detected", "login_page_detected"],
            "cookie_hijacker": ["cookies_detected", "cookie_no_secure", "cookie_no_httponly"],
            "csp_bypass": ["missing_csp"],
            "jwt_manipulator": ["jwt_token_detected"],
            "script_injector": ["missing_csp", "html_response"],
            "form_hijacker": ["html_form_present", "login_page_detected"],
            "websocket_hijacker": ["websocket_traffic_detected"],
            "api_param_tamper": ["api_endpoints_detected"],
        }
        return trigger_map.get(tool_id, [])

    def _evaluate_hypotheses(
        self,
        hypotheses: List[Dict[str, Any]],
        target_type: str,
        attack_surface: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Step 4: Evaluate hypotheses using Thompson sampling and context."""
        evaluated = []

        for hyp in hypotheses:
            tool_id = hyp["tool_id"]

            # Get Thompson sample from memory
            perf = self.memory.get_tool_performance(tool_id)
            if perf:
                thompson_score = perf.thompson_sample_for_target(target_type)
            else:
                # No data - high variance sample for exploration
                thompson_score = np.random.beta(1, 1)

            # Context modifiers
            context_bonus = 0.0

            if hyp.get("trigger_match"):
                context_bonus += 0.2

            if hyp.get("experience_match"):
                past_eff = hyp.get("past_effectiveness", 0)
                context_bonus += 0.1 + (past_eff * 0.1)

            # Attack surface bonuses
            if attack_surface.get("credentials_visible") and tool_id in ["credential_sniffer", "form_hijacker"]:
                context_bonus += 0.3

            if attack_surface.get("http_only_traffic") and tool_id == "sslstrip":
                context_bonus += 0.25

            # Findings-based bonuses (contextual tool selection based on previous findings)
            previous_findings = attack_surface.get("previous_findings", [])
            finding_types = attack_surface.get("finding_types", [])

            # Boost tools that can exploit previous findings
            if "jwt_detected" in finding_types and tool_id == "jwt_manipulator":
                context_bonus += 0.35
            if "websocket_detected" in finding_types and tool_id == "websocket_hijacker":
                context_bonus += 0.35
            if "api_endpoints" in finding_types and tool_id in ["api_param_tamper", "graphql_injector"]:
                context_bonus += 0.25
            if "cookies_captured" in finding_types and tool_id == "cookie_hijacker":
                context_bonus += 0.3
            if "csrf_missing" in finding_types and tool_id == "form_hijacker":
                context_bonus += 0.25

            # Penalty for recently failed tools (exponential backoff)
            failure_penalty = 0.0
            if hasattr(self, '_failed_tools') and self._failed_tools:
                failures = self._failed_tools.get(tool_id, 0)
                if failures > 0:
                    # Exponential penalty: 0.2 for 1 failure, 0.4 for 2, 0.6 for 3+
                    failure_penalty = min(0.6, 0.2 * failures)
                    logger.debug(f"Tool {tool_id} has {failures} recent failures, penalty: {failure_penalty}")

            # Final score
            final_score = max(0.0, min(1.0, thompson_score + context_bonus - failure_penalty))

            evaluated.append({
                "tool_id": tool_id,
                "thompson_score": thompson_score,
                "context_bonus": context_bonus,
                "final_score": final_score,
                "trigger_match": hyp.get("trigger_match", False),
                "experience_match": hyp.get("experience_match", False)
            })

        # Sort by final score descending
        evaluated.sort(key=lambda x: x["final_score"], reverse=True)
        return evaluated

    def _generate_summary(self, chain: ReasoningChain) -> str:
        """Generate human-readable reasoning summary."""
        if not chain.selected_tool:
            return "No attack selected - insufficient confidence in available options."

        parts = [
            f"Selected {chain.selected_tool} with {chain.confidence:.1%} confidence.",
            f"Situation: {chain.situation_analysis[:100]}..."
        ]

        if chain.recalled_experiences:
            successful = [e for e in chain.recalled_experiences if e["success"]]
            if successful:
                parts.append(f"Past success with similar targets using: {', '.join(e['tool_id'] for e in successful[:2])}")

        top_eval = chain.hypothesis_evaluations[0] if chain.hypothesis_evaluations else None
        if top_eval:
            if top_eval.get("trigger_match"):
                parts.append("Tool triggers matched current attack surface.")
            if top_eval.get("experience_match"):
                parts.append("Previous experience supports this choice.")

        return " ".join(parts)

    def should_execute(self, chain: ReasoningChain) -> bool:
        """Determine if we should execute the selected tool."""
        if not chain.selected_tool:
            return False

        # Aggressive: execute at low confidence threshold
        return chain.confidence >= self.min_confidence_threshold

    def get_reasoning_trace(self, chain_id: str) -> Optional[ReasoningChain]:
        """Get a reasoning chain by ID."""
        for chain in reversed(self.reasoning_chains):
            if chain.chain_id == chain_id:
                return chain
        return None

    def export_reasoning_chains(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Export recent reasoning chains."""
        return [c.to_dict() for c in self.reasoning_chains[-limit:]]


# ============================================================================
# Exploration Manager
# ============================================================================

class MITMExplorationManager:
    """
    Manages exploration vs exploitation balance.

    - Early in session: More exploration (try untested tools)
    - Later in session: More exploitation (use proven tools)
    - 30% random override chance during exploration mode
    """

    EXPLORATION_PHASE_THRESHOLD = 5  # First N attacks are exploration
    RANDOM_EXPLORATION_RATE = 0.3  # 30% chance to explore

    def __init__(self, memory: MITMAgentMemory):
        self.memory = memory
        self.attacks_executed = 0
        self.exploration_attacks = 0
        self.exploitation_attacks = 0

    @property
    def is_exploration_phase(self) -> bool:
        """Check if we're in the exploration phase."""
        return self.attacks_executed < self.EXPLORATION_PHASE_THRESHOLD

    @property
    def exploration_rate(self) -> float:
        """Get current exploration rate."""
        if self.is_exploration_phase:
            return 0.7  # High exploration early
        return self.RANDOM_EXPLORATION_RATE

    def should_explore(self) -> bool:
        """Decide whether to explore (try new tool) or exploit (use proven tool)."""
        if self.is_exploration_phase:
            return True
        return random.random() < self.RANDOM_EXPLORATION_RATE

    def select_tool(
        self,
        ranked_tools: List[Tuple[str, float]],
        available_untested: List[str]
    ) -> Tuple[str, str]:
        """
        Select a tool based on exploration/exploitation balance.

        Returns (tool_id, selection_reason).
        """
        if self.should_explore() and available_untested:
            # Exploration: pick random untested tool
            selected = random.choice(available_untested)
            self.exploration_attacks += 1
            reason = "exploration_random"
        else:
            # Exploitation: use top-ranked tool
            if ranked_tools:
                selected = ranked_tools[0][0]
                reason = "exploitation_thompson"
            elif available_untested:
                selected = random.choice(available_untested)
                reason = "fallback_random"
            else:
                return None, "no_tools_available"

        self.attacks_executed += 1
        return selected, reason

    def get_untested_tools(
        self,
        available_tools: List[str]
    ) -> List[str]:
        """Get tools that haven't been tested yet."""
        tested = set(self.memory.tool_performance.keys())
        return [t for t in available_tools if t not in tested]

    def get_stats(self) -> Dict[str, Any]:
        """Get exploration statistics."""
        return {
            "attacks_executed": self.attacks_executed,
            "exploration_attacks": self.exploration_attacks,
            "exploitation_attacks": self.exploitation_attacks,
            "is_exploration_phase": self.is_exploration_phase,
            "current_exploration_rate": self.exploration_rate
        }
