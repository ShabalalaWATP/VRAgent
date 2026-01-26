"""
Agentic Fuzzer Brain - True AI Decision Making

This module implements a truly agentic AI system for fuzzing that:
1. Makes real decisions using LLM reasoning (not hardcoded rules)
2. Maintains multi-turn memory across fuzzing cycles
3. Learns from past attempts and adapts strategies
4. Performs deep crash analysis with AI

The AI acts as an autonomous security researcher, reasoning about:
- What strategies to try next based on coverage patterns
- How to break through plateaus with creative approaches
- Which crashes are most promising for exploitation
- When to switch techniques vs when to persist
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from backend.core.config import settings

logger = logging.getLogger(__name__)

# Initialize Gemini client
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
        logger.info("Agentic Fuzzer Brain: Gemini AI initialized")
    except ImportError:
        logger.warning("google-genai not installed, Agentic AI disabled")
except Exception as e:
    logger.error(f"Failed to initialize Gemini: {e}")


class AgentMemoryType(str, Enum):
    """Types of memories the agent can store."""
    STRATEGY_TRIED = "strategy_tried"
    STRATEGY_SUCCESS = "strategy_success"
    STRATEGY_FAILED = "strategy_failed"
    CRASH_ANALYZED = "crash_analyzed"
    COVERAGE_MILESTONE = "coverage_milestone"
    INSIGHT = "insight"
    HYPOTHESIS = "hypothesis"


@dataclass
class AgentMemory:
    """A single memory entry for the agent."""
    memory_type: AgentMemoryType
    content: str
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    relevance_score: float = 1.0  # Decays over time

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.memory_type.value,
            "content": self.content,
            "context": self.context,
            "timestamp": self.timestamp,
            "age_minutes": (time.time() - self.timestamp) / 60,
        }


@dataclass
class CrashAnalysisResult:
    """Deep analysis result for a crash."""
    crash_id: str
    exploitability: str  # exploitable, probably_exploitable, probably_not, unknown
    confidence: float  # 0.0 - 1.0
    vulnerability_type: str
    root_cause: str
    attack_vector: str
    exploitation_steps: List[str]
    prerequisites: List[str]
    mitigations_to_bypass: List[str]
    difficulty: str  # trivial, easy, moderate, hard, very_hard
    similar_cves: List[str]
    poc_skeleton: str
    ai_reasoning: str  # The AI's chain of thought


@dataclass
class StrategicDecision:
    """A decision made by the agentic AI."""
    action: str
    priority: str  # critical, high, medium, low
    reasoning: str  # AI's explanation of why this action
    expected_outcome: str
    confidence: float
    alternatives_considered: List[str]
    context: Dict[str, Any] = field(default_factory=dict)


class AgenticFuzzerBrain:
    """
    The brain of the agentic fuzzer - makes autonomous decisions using AI.

    Unlike rule-based systems, this brain:
    - Reasons about fuzzing strategy using an LLM
    - Maintains memory of what's been tried and what worked
    - Adapts strategies based on results
    - Can explain its reasoning
    """

    def __init__(self, session_id: str, target_path: str):
        self.session_id = session_id
        self.target_path = target_path
        self.memories: List[AgentMemory] = []
        self.decision_history: List[StrategicDecision] = []
        self.cycle_count = 0
        self.total_runtime_seconds = 0
        self.best_coverage = 0
        self.total_crashes_found = 0
        self._memory_file = None

    def _get_memory_path(self) -> str:
        """Get path to persistent memory file."""
        memory_dir = os.path.join(
            os.environ.get("FUZZING_BASE_DIR", "/fuzzing"),
            "agent_memory"
        )
        os.makedirs(memory_dir, exist_ok=True)
        # Use hash of target path for memory file name
        target_hash = hashlib.md5(self.target_path.encode()).hexdigest()[:12]
        return os.path.join(memory_dir, f"{target_hash}_memory.json")

    def load_memory(self) -> None:
        """Load persistent memory from previous sessions."""
        memory_path = self._get_memory_path()
        if os.path.exists(memory_path):
            try:
                with open(memory_path, 'r') as f:
                    data = json.load(f)
                    self.memories = [
                        AgentMemory(
                            memory_type=AgentMemoryType(m["type"]),
                            content=m["content"],
                            context=m.get("context", {}),
                            timestamp=m.get("timestamp", time.time()),
                            relevance_score=m.get("relevance_score", 1.0)
                        )
                        for m in data.get("memories", [])
                    ]
                    self.cycle_count = data.get("cycle_count", 0)
                    self.best_coverage = data.get("best_coverage", 0)
                    logger.info(f"Loaded {len(self.memories)} memories from previous sessions")
            except Exception as e:
                logger.warning(f"Failed to load agent memory: {e}")

    def save_memory(self) -> None:
        """Persist memory to disk."""
        memory_path = self._get_memory_path()
        try:
            # Decay old memories and keep only relevant ones
            self._decay_memories()

            data = {
                "session_id": self.session_id,
                "target_path": self.target_path,
                "cycle_count": self.cycle_count,
                "best_coverage": self.best_coverage,
                "last_updated": datetime.utcnow().isoformat(),
                "memories": [m.to_dict() for m in self.memories[-100:]]  # Keep last 100
            }
            with open(memory_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save agent memory: {e}")

    def _decay_memories(self) -> None:
        """Decay relevance of old memories."""
        now = time.time()
        for memory in self.memories:
            age_hours = (now - memory.timestamp) / 3600
            # Decay by 10% per hour, minimum 0.1
            memory.relevance_score = max(0.1, memory.relevance_score * (0.9 ** age_hours))

        # Remove very old, low-relevance memories (keep at least last 20)
        if len(self.memories) > 20:
            self.memories = sorted(
                self.memories,
                key=lambda m: m.relevance_score * (1 if m.memory_type == AgentMemoryType.INSIGHT else 0.8),
                reverse=True
            )[:100]

    def add_memory(
        self,
        memory_type: AgentMemoryType,
        content: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add a new memory."""
        self.memories.append(AgentMemory(
            memory_type=memory_type,
            content=content,
            context=context or {},
        ))

    def get_relevant_memories(self, context: str, limit: int = 10) -> List[AgentMemory]:
        """Get memories most relevant to current context."""
        # Simple relevance: recent + high score + keyword match
        scored = []
        context_lower = context.lower()

        for memory in self.memories:
            score = memory.relevance_score
            # Boost if content matches context keywords
            if any(word in memory.content.lower() for word in context_lower.split()[:5]):
                score *= 1.5
            # Boost insights and successes
            if memory.memory_type in (AgentMemoryType.INSIGHT, AgentMemoryType.STRATEGY_SUCCESS):
                score *= 1.3
            scored.append((score, memory))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in scored[:limit]]

    def _format_memories_for_prompt(self, memories: List[AgentMemory]) -> str:
        """Format memories for inclusion in LLM prompt."""
        if not memories:
            return "No relevant memories from previous cycles."

        lines = ["## Relevant Memories from Previous Cycles:\n"]
        for i, m in enumerate(memories, 1):
            age = (time.time() - m.timestamp) / 60
            lines.append(f"{i}. [{m.memory_type.value}] (age: {age:.0f}min)")
            lines.append(f"   {m.content}")
            if m.context:
                lines.append(f"   Context: {json.dumps(m.context)}")
        return "\n".join(lines)

    async def make_strategic_decision(
        self,
        stats_history: List[Dict[str, Any]],
        current_crashes: List[Dict[str, Any]],
        corpus_info: Dict[str, Any],
        run_metadata: Dict[str, Any],
    ) -> List[StrategicDecision]:
        """
        Make strategic decisions about what to do next.

        This is the core of the agentic AI - it reasons about the fuzzing
        state and decides what actions to take, rather than following
        hardcoded rules.
        """
        if not genai_client:
            logger.warning("Gemini not available, falling back to heuristics")
            return self._fallback_decisions(stats_history, current_crashes, corpus_info)

        self.cycle_count += 1

        # Gather context
        latest_stats = stats_history[-1] if stats_history else {}
        coverage = latest_stats.get("paths_total", latest_stats.get("total_edges", 0))
        exec_speed = latest_stats.get("execs_per_sec", 0)
        crashes = latest_stats.get("unique_crashes", 0)

        # Track progress
        coverage_improved = coverage > self.best_coverage
        if coverage_improved:
            self.best_coverage = coverage
            self.add_memory(
                AgentMemoryType.COVERAGE_MILESTONE,
                f"Reached new coverage milestone: {coverage} edges",
                {"coverage": coverage, "cycle": self.cycle_count}
            )

        # Get relevant memories
        context_summary = f"coverage:{coverage} crashes:{crashes} speed:{exec_speed}"
        relevant_memories = self.get_relevant_memories(context_summary)

        # Build the reasoning prompt
        prompt = self._build_decision_prompt(
            stats_history=stats_history,
            current_crashes=current_crashes,
            corpus_info=corpus_info,
            run_metadata=run_metadata,
            relevant_memories=relevant_memories,
        )

        try:
            from google.genai import types
            response = await asyncio.to_thread(
                genai_client.models.generate_content,
                model="gemini-3-flash-preview",
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="high"),
                    max_output_tokens=4096,
                )
            )

            decisions = self._parse_decision_response(response.text)

            # Record what we decided
            for decision in decisions:
                self.decision_history.append(decision)
                self.add_memory(
                    AgentMemoryType.STRATEGY_TRIED,
                    f"Decided to: {decision.action} - {decision.reasoning[:100]}",
                    {"action": decision.action, "confidence": decision.confidence}
                )

            self.save_memory()
            return decisions

        except Exception as e:
            logger.exception(f"AI decision-making failed: {e}")
            return self._fallback_decisions(stats_history, current_crashes, corpus_info)

    def _build_decision_prompt(
        self,
        stats_history: List[Dict[str, Any]],
        current_crashes: List[Dict[str, Any]],
        corpus_info: Dict[str, Any],
        run_metadata: Dict[str, Any],
        relevant_memories: List[AgentMemory],
    ) -> str:
        """Build the prompt for strategic decision-making."""

        # Calculate trends
        latest = stats_history[-1] if stats_history else {}
        oldest = stats_history[0] if stats_history else {}

        coverage_now = latest.get("paths_total", latest.get("total_edges", 0))
        coverage_start = oldest.get("paths_total", oldest.get("total_edges", 0))
        coverage_delta = coverage_now - coverage_start

        crashes_now = latest.get("unique_crashes", 0)
        exec_speed = latest.get("execs_per_sec", 0)

        # Time since last new path
        last_path_time = latest.get("last_path_time")
        stagnation_time = "unknown"
        if last_path_time and last_path_time > 1_000_000_000:
            stagnation_time = f"{(time.time() - last_path_time) / 60:.1f} minutes"

        # Format crash summary
        crash_summary = "No crashes found yet."
        if current_crashes:
            crash_types = {}
            for c in current_crashes[:20]:
                ctype = c.get("crash_type", "unknown")
                crash_types[ctype] = crash_types.get(ctype, 0) + 1
            crash_summary = f"Found {len(current_crashes)} crashes: " + ", ".join(
                f"{v}x {k}" for k, v in crash_types.items()
            )

        # Build prompt
        prompt = f"""You are an expert security researcher and fuzzing specialist acting as an autonomous agent.
Your task is to analyze the current fuzzing campaign state and decide what strategic actions to take next.

## Current Campaign State

**Target Binary:** {self.target_path}
**Fuzzing Cycle:** #{self.cycle_count}
**Best Coverage Achieved:** {self.best_coverage} edges

### Current Statistics:
- Coverage: {coverage_now} edges (delta: {'+' if coverage_delta >= 0 else ''}{coverage_delta} since start)
- Unique Crashes: {crashes_now}
- Execution Speed: {exec_speed:.1f} exec/sec
- Time Since Last New Path: {stagnation_time}
- Corpus Size: {corpus_info.get('size', 'unknown')} inputs

### Crash Summary:
{crash_summary}

### Current Configuration:
- QEMU Mode: {run_metadata.get('use_qemu', False)}
- Dictionary: {'Yes' if run_metadata.get('dictionary_path') else 'No'}
- Timeout: {run_metadata.get('timeout_ms', 5000)}ms

{self._format_memories_for_prompt(relevant_memories)}

## Your Task

As an autonomous fuzzing agent, analyze this situation and decide what actions to take.
Think step by step:

1. **Assess the situation**: Is fuzzing progressing well? Are we stuck? What patterns do you see?
2. **Consider what's been tried**: Look at the memories - what worked? What didn't?
3. **Hypothesize**: What might help break through the current state?
4. **Decide**: Choose 1-3 concrete actions to take, prioritized by expected impact.

## Available Actions

You can recommend any of these actions:
- `generate_smart_seeds`: Use AI to generate targeted seed inputs
- `generate_dictionary`: Extract/generate a fuzzing dictionary
- `enable_compcov`: Enable comparison coverage (for QEMU mode)
- `increase_mutation_depth`: More aggressive mutations
- `reduce_timeout`: Lower timeout to increase throughput
- `focus_on_crashes`: Prioritize inputs near crash-inducing paths
- `try_structure_aware`: Switch to structure-aware mutation if format detected
- `restart_with_queue`: Restart using current queue as seeds
- `analyze_crashes`: Deep analysis of crashes for exploitation potential
- `custom`: Any other action you think would help (describe it)

## Response Format

Respond with a JSON array of decisions. Each decision should have:
- action: The action to take
- priority: "critical", "high", "medium", or "low"
- reasoning: Your step-by-step reasoning for this action (be specific!)
- expected_outcome: What you expect this action to achieve
- confidence: 0.0-1.0 how confident you are this will help
- alternatives_considered: What else you considered and why you rejected it

Example:
```json
[
  {{
    "action": "generate_smart_seeds",
    "priority": "high",
    "reasoning": "Coverage has stagnated for 15 minutes with only 234 edges. The corpus appears to be stuck in shallow code paths. Previous attempts with random mutation haven't helped (see memory #2). AI-generated seeds targeting deeper functionality may break through.",
    "expected_outcome": "Expect 10-20% coverage increase by targeting unexplored code regions",
    "confidence": 0.7,
    "alternatives_considered": ["increase_mutation_depth - rejected because we've been mutating heavily already", "reduce_timeout - rejected because exec/sec is already good"]
  }}
]
```

Now analyze the situation and provide your decisions:"""

        return prompt

    def _parse_decision_response(self, response_text: str) -> List[StrategicDecision]:
        """Parse the AI's decision response."""
        decisions = []

        # Extract JSON from response
        json_match = re.search(r'\[[\s\S]*\]', response_text)
        if not json_match:
            logger.warning("No JSON found in AI response")
            return decisions

        try:
            decision_data = json.loads(json_match.group())

            for d in decision_data:
                decisions.append(StrategicDecision(
                    action=d.get("action", "unknown"),
                    priority=d.get("priority", "medium"),
                    reasoning=d.get("reasoning", "No reasoning provided"),
                    expected_outcome=d.get("expected_outcome", "Unknown"),
                    confidence=float(d.get("confidence", 0.5)),
                    alternatives_considered=d.get("alternatives_considered", []),
                    context=d.get("context", {}),
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI decision JSON: {e}")

        return decisions

    def _fallback_decisions(
        self,
        stats_history: List[Dict[str, Any]],
        current_crashes: List[Dict[str, Any]],
        corpus_info: Dict[str, Any],
    ) -> List[StrategicDecision]:
        """Fallback heuristic decisions when AI is unavailable."""
        decisions = []

        latest = stats_history[-1] if stats_history else {}
        coverage = latest.get("paths_total", latest.get("total_edges", 0))

        # Simple heuristic: if coverage hasn't improved, try generating seeds
        if coverage <= self.best_coverage:
            decisions.append(StrategicDecision(
                action="generate_smart_seeds",
                priority="high",
                reasoning="[FALLBACK] Coverage not improving, trying new seeds",
                expected_outcome="May find new paths",
                confidence=0.5,
                alternatives_considered=[],
            ))

        return decisions

    async def analyze_crash_deeply(
        self,
        crash_data: Dict[str, Any],
        crash_input: bytes,
        binary_info: Optional[Dict[str, Any]] = None,
    ) -> CrashAnalysisResult:
        """
        Perform deep AI-powered analysis of a crash.

        This goes beyond simple keyword matching to actually reason
        about the crash context, registers, memory state, and
        potential exploitation paths.
        """
        crash_id = crash_data.get("id", f"crash_{int(time.time())}")

        if not genai_client:
            return self._fallback_crash_analysis(crash_id, crash_data)

        prompt = self._build_crash_analysis_prompt(crash_data, crash_input, binary_info)

        try:
            from google.genai import types
            response = await asyncio.to_thread(
                genai_client.models.generate_content,
                model="gemini-3-flash-preview",
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="medium"),
                    max_output_tokens=4096,
                )
            )

            result = self._parse_crash_analysis(crash_id, response.text)

            # Store insight from analysis
            self.add_memory(
                AgentMemoryType.CRASH_ANALYZED,
                f"Analyzed crash {crash_id}: {result.vulnerability_type} - {result.exploitability}",
                {
                    "crash_id": crash_id,
                    "exploitability": result.exploitability,
                    "confidence": result.confidence,
                }
            )

            return result

        except Exception as e:
            logger.exception(f"Deep crash analysis failed: {e}")
            return self._fallback_crash_analysis(crash_id, crash_data)

    def _build_crash_analysis_prompt(
        self,
        crash_data: Dict[str, Any],
        crash_input: bytes,
        binary_info: Optional[Dict[str, Any]],
    ) -> str:
        """Build prompt for deep crash analysis."""

        # Format registers
        registers = crash_data.get("registers", {})
        reg_str = "\n".join(f"  {k}: {v}" for k, v in registers.items()) if registers else "Not available"

        # Format stack trace
        stack_trace = crash_data.get("stack_trace", [])
        stack_str = "\n".join(f"  {i}: {frame}" for i, frame in enumerate(stack_trace[:20])) if stack_trace else "Not available"

        # Format input preview
        input_preview = crash_input[:256].hex() if crash_input else "Not available"

        # Format binary info
        binary_context = ""
        if binary_info:
            binary_context = f"""
### Binary Information:
- Architecture: {binary_info.get('architecture', 'unknown')}
- Security Features: {', '.join(binary_info.get('security_features', []))}
- Dangerous Functions: {', '.join(binary_info.get('dangerous_functions', [])[:10])}
"""

        prompt = f"""You are an expert vulnerability researcher analyzing a crash from a fuzzing campaign.
Your task is to perform deep analysis and assess the exploitability of this crash.

## Crash Information

**Crash Type:** {crash_data.get('crash_type', 'unknown')}
**Signal:** {crash_data.get('signal', 'unknown')}
**Faulting Address:** {crash_data.get('fault_address', 'unknown')}

### Register State:
{reg_str}

### Stack Trace:
{stack_str}

### Crashing Input (hex, first 256 bytes):
{input_preview}

{binary_context}

## Analysis Task

Perform a thorough security analysis:

1. **Root Cause Analysis**: What is the actual bug? (buffer overflow, use-after-free, integer overflow, etc.)

2. **Exploitability Assessment**:
   - Can an attacker gain code execution?
   - What primitives does this bug provide? (arbitrary write, controlled jump, info leak)
   - What mitigations would need to be bypassed?

3. **Exploitation Path**:
   - What are the concrete steps to exploit this?
   - What prerequisites are needed?
   - How difficult would exploitation be?

4. **Similar Vulnerabilities**: Are there known CVEs with similar patterns?

5. **PoC Skeleton**: Provide a skeleton of what a proof-of-concept exploit might look like.

## Response Format

Respond with a JSON object:
```json
{{
  "exploitability": "exploitable|probably_exploitable|probably_not_exploitable|unknown",
  "confidence": 0.0-1.0,
  "vulnerability_type": "buffer_overflow|use_after_free|integer_overflow|format_string|etc",
  "root_cause": "Detailed explanation of the bug",
  "attack_vector": "How an attacker would trigger this",
  "exploitation_steps": ["Step 1", "Step 2", ...],
  "prerequisites": ["What attacker needs"],
  "mitigations_to_bypass": ["ASLR", "Stack canary", etc],
  "difficulty": "trivial|easy|moderate|hard|very_hard",
  "similar_cves": ["CVE-XXXX-XXXX"],
  "poc_skeleton": "Python/C code skeleton for PoC",
  "reasoning": "Your detailed chain of thought analysis"
}}
```

Now analyze this crash:"""

        return prompt

    def _parse_crash_analysis(self, crash_id: str, response_text: str) -> CrashAnalysisResult:
        """Parse the crash analysis response."""
        # Extract JSON
        json_match = re.search(r'\{[\s\S]*\}', response_text)
        if not json_match:
            return self._fallback_crash_analysis(crash_id, {})

        try:
            data = json.loads(json_match.group())

            return CrashAnalysisResult(
                crash_id=crash_id,
                exploitability=data.get("exploitability", "unknown"),
                confidence=float(data.get("confidence", 0.5)),
                vulnerability_type=data.get("vulnerability_type", "unknown"),
                root_cause=data.get("root_cause", "Unknown"),
                attack_vector=data.get("attack_vector", "Unknown"),
                exploitation_steps=data.get("exploitation_steps", []),
                prerequisites=data.get("prerequisites", []),
                mitigations_to_bypass=data.get("mitigations_to_bypass", []),
                difficulty=data.get("difficulty", "unknown"),
                similar_cves=data.get("similar_cves", []),
                poc_skeleton=data.get("poc_skeleton", ""),
                ai_reasoning=data.get("reasoning", ""),
            )

        except json.JSONDecodeError:
            return self._fallback_crash_analysis(crash_id, {})

    def _fallback_crash_analysis(self, crash_id: str, crash_data: Dict[str, Any]) -> CrashAnalysisResult:
        """Fallback crash analysis using heuristics."""
        crash_type = str(crash_data.get("crash_type", "")).lower()

        # Simple heuristic classification
        if "write" in crash_type or "heap" in crash_type:
            exploitability = "probably_exploitable"
            confidence = 0.6
            vuln_type = "heap_corruption"
        elif "use_after_free" in crash_type or "uaf" in crash_type:
            exploitability = "exploitable"
            confidence = 0.7
            vuln_type = "use_after_free"
        elif "stack" in crash_type:
            exploitability = "probably_exploitable"
            confidence = 0.5
            vuln_type = "stack_buffer_overflow"
        else:
            exploitability = "unknown"
            confidence = 0.3
            vuln_type = "unknown"

        return CrashAnalysisResult(
            crash_id=crash_id,
            exploitability=exploitability,
            confidence=confidence,
            vulnerability_type=vuln_type,
            root_cause="[FALLBACK] Unable to perform deep analysis without AI",
            attack_vector="Unknown - requires manual analysis",
            exploitation_steps=[],
            prerequisites=[],
            mitigations_to_bypass=[],
            difficulty="unknown",
            similar_cves=[],
            poc_skeleton="",
            ai_reasoning="Fallback heuristic analysis - AI unavailable",
        )

    def record_strategy_outcome(
        self,
        action: str,
        success: bool,
        details: str,
        metrics_before: Dict[str, Any],
        metrics_after: Dict[str, Any],
    ) -> None:
        """Record the outcome of a strategy for learning."""
        memory_type = AgentMemoryType.STRATEGY_SUCCESS if success else AgentMemoryType.STRATEGY_FAILED

        coverage_delta = metrics_after.get("coverage", 0) - metrics_before.get("coverage", 0)
        crashes_delta = metrics_after.get("crashes", 0) - metrics_before.get("crashes", 0)

        content = f"Action '{action}' {'succeeded' if success else 'failed'}: {details}"
        if coverage_delta != 0:
            content += f" (coverage: {'+' if coverage_delta > 0 else ''}{coverage_delta})"
        if crashes_delta != 0:
            content += f" (crashes: +{crashes_delta})"

        self.add_memory(
            memory_type,
            content,
            {
                "action": action,
                "success": success,
                "coverage_delta": coverage_delta,
                "crashes_delta": crashes_delta,
            }
        )

        # If we learned something useful, add an insight
        if success and (coverage_delta > 10 or crashes_delta > 0):
            self.add_memory(
                AgentMemoryType.INSIGHT,
                f"Strategy '{action}' was effective for this target (+{coverage_delta} coverage, +{crashes_delta} crashes)",
                {"action": action}
            )

        self.save_memory()


# Global brain instances (per session)
_agent_brains: Dict[str, AgenticFuzzerBrain] = {}


def get_or_create_brain(session_id: str, target_path: str) -> AgenticFuzzerBrain:
    """Get or create an agent brain for a session."""
    if session_id not in _agent_brains:
        brain = AgenticFuzzerBrain(session_id, target_path)
        brain.load_memory()
        _agent_brains[session_id] = brain
    return _agent_brains[session_id]


def clear_brain(session_id: str) -> None:
    """Clear the brain for a session."""
    if session_id in _agent_brains:
        _agent_brains[session_id].save_memory()
        del _agent_brains[session_id]


async def make_agentic_decision(
    session_id: str,
    target_path: str,
    stats_history: List[Dict[str, Any]],
    current_crashes: List[Dict[str, Any]],
    corpus_info: Dict[str, Any],
    run_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Main entry point for agentic decision-making.

    Returns a dict with:
    - decisions: List of StrategicDecision objects
    - ai_available: Whether AI was used
    - reasoning_summary: High-level summary of the AI's thinking
    """
    brain = get_or_create_brain(session_id, target_path)

    decisions = await brain.make_strategic_decision(
        stats_history=stats_history,
        current_crashes=current_crashes,
        corpus_info=corpus_info,
        run_metadata=run_metadata,
    )

    return {
        "decisions": [
            {
                "action": d.action,
                "priority": d.priority,
                "reasoning": d.reasoning,
                "expected_outcome": d.expected_outcome,
                "confidence": d.confidence,
                "alternatives_considered": d.alternatives_considered,
            }
            for d in decisions
        ],
        "ai_available": genai_client is not None,
        "cycle_count": brain.cycle_count,
        "best_coverage": brain.best_coverage,
        "memory_count": len(brain.memories),
        "reasoning_summary": decisions[0].reasoning if decisions else "No decisions made",
    }


async def analyze_crash_with_ai(
    session_id: str,
    target_path: str,
    crash_data: Dict[str, Any],
    crash_input: bytes,
    binary_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main entry point for deep crash analysis.
    """
    brain = get_or_create_brain(session_id, target_path)

    result = await brain.analyze_crash_deeply(
        crash_data=crash_data,
        crash_input=crash_input,
        binary_info=binary_info,
    )

    return {
        "crash_id": result.crash_id,
        "exploitability": result.exploitability,
        "confidence": result.confidence,
        "vulnerability_type": result.vulnerability_type,
        "root_cause": result.root_cause,
        "attack_vector": result.attack_vector,
        "exploitation_steps": result.exploitation_steps,
        "prerequisites": result.prerequisites,
        "mitigations_to_bypass": result.mitigations_to_bypass,
        "difficulty": result.difficulty,
        "similar_cves": result.similar_cves,
        "poc_skeleton": result.poc_skeleton,
        "ai_reasoning": result.ai_reasoning,
        "ai_available": genai_client is not None,
    }
