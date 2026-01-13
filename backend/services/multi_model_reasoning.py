"""
Multi-Model Reasoning Engine for Agentic Fuzzing

Orchestrates multiple specialized LLM models for different fuzzing tasks:
- Payload Generation Model: Creates context-aware attack payloads
- Response Analysis Model: Analyzes responses for vulnerability indicators
- Correlation Model: Connects findings and identifies attack chains
- Exploitation Model: Develops PoCs and exploitation strategies
- Remediation Model: Generates fix recommendations

Supports model-specific prompts, caching, and fallback strategies.
"""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Callable, Tuple
from enum import Enum
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)


class ModelRole(str, Enum):
    """Specialized roles for different models."""
    PAYLOAD_GENERATOR = "payload_generator"
    RESPONSE_ANALYZER = "response_analyzer"
    CORRELATION = "correlation"
    EXPLOITATION = "exploitation"
    REMEDIATION = "remediation"
    ORCHESTRATOR = "orchestrator"  # Main decision maker


class ModelProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"
    AZURE_OPENAI = "azure_openai"
    OLLAMA = "ollama"
    GROQ = "groq"


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    role: ModelRole
    provider: ModelProvider
    model_name: str
    temperature: float = 0.7
    max_tokens: int = 2048
    system_prompt: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 60.0
    retry_count: int = 3
    cache_ttl: int = 3600  # Cache responses for 1 hour
    priority: int = 1  # Lower = higher priority
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["role"] = self.role.value
        result["provider"] = self.provider.value
        # Don't expose API key
        if result.get("api_key"):
            result["api_key"] = "***"
        return result


@dataclass
class ModelResponse:
    """Response from a model invocation."""
    role: ModelRole
    provider: ModelProvider
    model_name: str
    content: str
    tokens_used: int
    latency_ms: float
    cached: bool = False
    error: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "role": self.role.value,
            "provider": self.provider.value,
        }


@dataclass
class ReasoningStep:
    """A single step in the reasoning chain."""
    step_id: str
    role: ModelRole
    input_context: str
    output: str
    confidence: float
    latency_ms: float
    model_used: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "role": self.role.value,
        }


@dataclass
class ReasoningChain:
    """Complete reasoning chain across multiple models."""
    chain_id: str
    task: str
    steps: List[ReasoningStep] = field(default_factory=list)
    final_output: str = ""
    total_latency_ms: float = 0.0
    total_tokens: int = 0
    success: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "steps": [s.to_dict() for s in self.steps],
        }


# =============================================================================
# SYSTEM PROMPTS FOR SPECIALIZED MODELS
# =============================================================================

PAYLOAD_GENERATOR_PROMPT = """You are an expert security payload generator. Your role is to create highly effective attack payloads based on:
1. Target technology stack (language, framework, database)
2. Vulnerability type being tested
3. Previous responses and indicators
4. WAF/IDS evasion requirements

Guidelines:
- Generate payloads that are contextually relevant to the technology
- Include encoding/obfuscation when WAF is detected
- Vary payloads to test different edge cases
- Consider both blind and error-based variations
- Include polyglot payloads when appropriate

Output JSON format:
{
    "payloads": ["payload1", "payload2", ...],
    "reasoning": "why these payloads were chosen",
    "evasion_techniques": ["technique1", ...],
    "expected_indicators": ["indicator1", ...]
}"""

RESPONSE_ANALYZER_PROMPT = """You are an expert security response analyzer. Your role is to analyze HTTP responses and identify:
1. Vulnerability indicators (errors, timing, behavior changes)
2. Technology leaks (stack traces, headers, comments)
3. WAF/IDS blocking patterns
4. Potential attack vectors
5. Confidence level for findings

Be precise and avoid false positives. Consider:
- Response timing anomalies
- Status code patterns
- Body content differences
- Header variations
- Error message contents

Output JSON format:
{
    "vulnerability_detected": true/false,
    "confidence": 0.0-1.0,
    "indicators": ["indicator1", ...],
    "technology_detected": {"server": "...", "framework": "...", ...},
    "waf_detected": true/false,
    "next_steps": ["suggestion1", ...],
    "reasoning": "detailed analysis"
}"""

CORRELATION_PROMPT = """You are an expert vulnerability correlator. Your role is to:
1. Connect related findings across different endpoints
2. Identify root cause vulnerabilities
3. Discover attack chain opportunities
4. Prioritize findings by actual exploitability
5. Reduce false positives through cross-validation

Consider:
- Same vulnerability in multiple locations = systemic issue
- Multiple low-severity findings that chain to high impact
- Findings that enable other attacks
- Patterns indicating architectural weaknesses

Output JSON format:
{
    "correlations": [
        {"findings": ["id1", "id2"], "relationship": "...", "combined_impact": "..."}
    ],
    "attack_chains": [
        {"steps": ["finding1 -> finding2 -> ..."], "final_impact": "...", "likelihood": 0.0-1.0}
    ],
    "root_causes": ["cause1", ...],
    "priority_ranking": [{"finding_id": "...", "priority": 1, "reason": "..."}]
}"""

EXPLOITATION_PROMPT = """You are an expert exploit developer. Your role is to:
1. Develop working proof-of-concept exploits
2. Determine real-world exploitability
3. Assess actual impact of vulnerabilities
4. Create demonstration scenarios
5. Identify exploitation prerequisites

Generate PoCs that:
- Are safe and controlled
- Demonstrate the vulnerability clearly
- Include step-by-step instructions
- Note any prerequisites or conditions
- Can be used for verification testing

Output JSON format:
{
    "exploitable": true/false,
    "prerequisites": ["prereq1", ...],
    "poc_code": "...",
    "poc_steps": ["step1", ...],
    "impact_demonstration": "what the attacker can achieve",
    "real_world_scenario": "...",
    "exploitation_difficulty": "trivial/easy/moderate/difficult/expert"
}"""

REMEDIATION_PROMPT = """You are an expert security remediation advisor. Your role is to:
1. Provide specific, actionable fix recommendations
2. Prioritize remediations by risk and effort
3. Suggest both quick fixes and long-term solutions
4. Consider the technology stack for implementation details
5. Provide code examples when helpful

Recommendations should:
- Be technology-specific (e.g., Django vs Flask for Python)
- Include code snippets where applicable
- Consider backward compatibility
- Note testing requirements
- Reference security best practices

Output JSON format:
{
    "remediations": [
        {
            "priority": "critical/high/medium/low",
            "title": "...",
            "description": "...",
            "implementation": "code or steps",
            "effort": "hours/days/weeks",
            "testing": "how to verify the fix"
        }
    ],
    "quick_wins": ["immediate action1", ...],
    "long_term": ["architectural change1", ...],
    "references": ["link1", ...]
}"""


# =============================================================================
# MODEL CLIENTS
# =============================================================================

class ModelClient(ABC):
    """Abstract base class for model clients."""
    
    @abstractmethod
    async def invoke(
        self,
        messages: List[Dict[str, str]],
        config: ModelConfig,
    ) -> ModelResponse:
        """Invoke the model with messages."""
        pass


class OpenAIClient(ModelClient):
    """OpenAI API client."""
    
    async def invoke(
        self,
        messages: List[Dict[str, str]],
        config: ModelConfig,
    ) -> ModelResponse:
        import httpx
        
        start_time = time.time()
        
        headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }
        
        payload = {
            "model": config.model_name,
            "messages": messages,
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        }
        
        try:
            async with httpx.AsyncClient(timeout=config.timeout) as client:
                response = await client.post(
                    f"{config.base_url or 'https://api.openai.com'}/v1/chat/completions",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                tokens = data.get("usage", {}).get("total_tokens", 0)
                
                return ModelResponse(
                    role=config.role,
                    provider=config.provider,
                    model_name=config.model_name,
                    content=content,
                    tokens_used=tokens,
                    latency_ms=(time.time() - start_time) * 1000,
                    raw_response=data,
                )
                
        except Exception as e:
            return ModelResponse(
                role=config.role,
                provider=config.provider,
                model_name=config.model_name,
                content="",
                tokens_used=0,
                latency_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )


class AnthropicClient(ModelClient):
    """Anthropic Claude API client."""
    
    async def invoke(
        self,
        messages: List[Dict[str, str]],
        config: ModelConfig,
    ) -> ModelResponse:
        import httpx
        
        start_time = time.time()
        
        headers = {
            "x-api-key": config.api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        
        # Convert messages format for Anthropic
        system_msg = ""
        conversation = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                conversation.append(msg)
        
        payload = {
            "model": config.model_name,
            "max_tokens": config.max_tokens,
            "messages": conversation,
        }
        if system_msg:
            payload["system"] = system_msg
        
        try:
            async with httpx.AsyncClient(timeout=config.timeout) as client:
                response = await client.post(
                    f"{config.base_url or 'https://api.anthropic.com'}/v1/messages",
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                
                data = response.json()
                content = data["content"][0]["text"]
                tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)
                
                return ModelResponse(
                    role=config.role,
                    provider=config.provider,
                    model_name=config.model_name,
                    content=content,
                    tokens_used=tokens,
                    latency_ms=(time.time() - start_time) * 1000,
                    raw_response=data,
                )
                
        except Exception as e:
            return ModelResponse(
                role=config.role,
                provider=config.provider,
                model_name=config.model_name,
                content="",
                tokens_used=0,
                latency_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )


class OllamaClient(ModelClient):
    """Ollama local model client."""
    
    async def invoke(
        self,
        messages: List[Dict[str, str]],
        config: ModelConfig,
    ) -> ModelResponse:
        import httpx
        
        start_time = time.time()
        
        payload = {
            "model": config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": config.temperature,
            },
        }
        
        try:
            async with httpx.AsyncClient(timeout=config.timeout) as client:
                response = await client.post(
                    f"{config.base_url or 'http://localhost:11434'}/api/chat",
                    json=payload,
                )
                response.raise_for_status()
                
                data = response.json()
                content = data.get("message", {}).get("content", "")
                
                return ModelResponse(
                    role=config.role,
                    provider=config.provider,
                    model_name=config.model_name,
                    content=content,
                    tokens_used=data.get("eval_count", 0),
                    latency_ms=(time.time() - start_time) * 1000,
                    raw_response=data,
                )
                
        except Exception as e:
            return ModelResponse(
                role=config.role,
                provider=config.provider,
                model_name=config.model_name,
                content="",
                tokens_used=0,
                latency_ms=(time.time() - start_time) * 1000,
                error=str(e),
            )


# =============================================================================
# RESPONSE CACHE
# =============================================================================

class ResponseCache:
    """Cache for model responses to reduce API calls."""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: Dict[str, Tuple[ModelResponse, float]] = {}
    
    def _generate_key(
        self,
        role: ModelRole,
        messages: List[Dict[str, str]],
    ) -> str:
        """Generate cache key from role and messages."""
        content = json.dumps({"role": role.value, "messages": messages}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(
        self,
        role: ModelRole,
        messages: List[Dict[str, str]],
        ttl: int = 3600,
    ) -> Optional[ModelResponse]:
        """Get cached response if valid."""
        key = self._generate_key(role, messages)
        
        if key in self._cache:
            response, timestamp = self._cache[key]
            if time.time() - timestamp < ttl:
                response.cached = True
                return response
            else:
                del self._cache[key]
        
        return None
    
    def set(
        self,
        role: ModelRole,
        messages: List[Dict[str, str]],
        response: ModelResponse,
    ):
        """Cache a response."""
        # Evict oldest if at capacity
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        
        key = self._generate_key(role, messages)
        self._cache[key] = (response, time.time())
    
    def clear(self):
        """Clear the cache."""
        self._cache.clear()
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
        }


# =============================================================================
# MULTI-MODEL REASONING ENGINE
# =============================================================================

class MultiModelReasoningEngine:
    """
    Orchestrates multiple specialized LLM models for intelligent fuzzing decisions.
    """
    
    def __init__(self):
        self._models: Dict[ModelRole, List[ModelConfig]] = {}
        self._clients: Dict[ModelProvider, ModelClient] = {
            ModelProvider.OPENAI: OpenAIClient(),
            ModelProvider.ANTHROPIC: AnthropicClient(),
            ModelProvider.OLLAMA: OllamaClient(),
        }
        self._cache = ResponseCache()
        self._reasoning_history: List[ReasoningChain] = []
        self._stats = {
            "total_invocations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
            "total_tokens": 0,
            "total_latency_ms": 0,
        }
        
        # Initialize with default system prompts
        self._system_prompts = {
            ModelRole.PAYLOAD_GENERATOR: PAYLOAD_GENERATOR_PROMPT,
            ModelRole.RESPONSE_ANALYZER: RESPONSE_ANALYZER_PROMPT,
            ModelRole.CORRELATION: CORRELATION_PROMPT,
            ModelRole.EXPLOITATION: EXPLOITATION_PROMPT,
            ModelRole.REMEDIATION: REMEDIATION_PROMPT,
        }
    
    def register_model(self, config: ModelConfig):
        """Register a model for a specific role."""
        if config.role not in self._models:
            self._models[config.role] = []
        
        # Set default system prompt if not provided
        if not config.system_prompt and config.role in self._system_prompts:
            config.system_prompt = self._system_prompts[config.role]
        
        self._models[config.role].append(config)
        
        # Sort by priority
        self._models[config.role].sort(key=lambda x: x.priority)
        
        logger.info(f"Registered model {config.model_name} for role {config.role.value}")
    
    def _get_client(self, provider: ModelProvider) -> Optional[ModelClient]:
        """Get client for provider."""
        return self._clients.get(provider)
    
    async def _invoke_model(
        self,
        config: ModelConfig,
        messages: List[Dict[str, str]],
        use_cache: bool = True,
    ) -> ModelResponse:
        """Invoke a specific model."""
        # Check cache first
        if use_cache:
            cached = self._cache.get(config.role, messages, config.cache_ttl)
            if cached:
                self._stats["cache_hits"] += 1
                return cached
            self._stats["cache_misses"] += 1
        
        # Get client
        client = self._get_client(config.provider)
        if not client:
            return ModelResponse(
                role=config.role,
                provider=config.provider,
                model_name=config.model_name,
                content="",
                tokens_used=0,
                latency_ms=0,
                error=f"No client for provider {config.provider.value}",
            )
        
        # Invoke with retries
        last_error = None
        for attempt in range(config.retry_count):
            response = await client.invoke(messages, config)
            
            if not response.error:
                # Cache successful response
                if use_cache:
                    self._cache.set(config.role, messages, response)
                
                self._stats["total_invocations"] += 1
                self._stats["total_tokens"] += response.tokens_used
                self._stats["total_latency_ms"] += response.latency_ms
                
                return response
            
            last_error = response.error
            logger.warning(f"Model invocation attempt {attempt + 1} failed: {last_error}")
            
            if attempt < config.retry_count - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        self._stats["errors"] += 1
        return ModelResponse(
            role=config.role,
            provider=config.provider,
            model_name=config.model_name,
            content="",
            tokens_used=0,
            latency_ms=0,
            error=last_error,
        )
    
    async def invoke_role(
        self,
        role: ModelRole,
        context: str,
        use_cache: bool = True,
    ) -> ModelResponse:
        """
        Invoke a model for a specific role with fallback to other models.
        """
        if role not in self._models or not self._models[role]:
            return ModelResponse(
                role=role,
                provider=ModelProvider.LOCAL,
                model_name="none",
                content="",
                tokens_used=0,
                latency_ms=0,
                error=f"No models registered for role {role.value}",
            )
        
        # Try each model in priority order
        for config in self._models[role]:
            messages = []
            
            if config.system_prompt:
                messages.append({"role": "system", "content": config.system_prompt})
            
            messages.append({"role": "user", "content": context})
            
            response = await self._invoke_model(config, messages, use_cache)
            
            if not response.error:
                return response
            
            logger.warning(f"Model {config.model_name} failed, trying next...")
        
        # All models failed
        return ModelResponse(
            role=role,
            provider=self._models[role][0].provider,
            model_name="fallback",
            content="",
            tokens_used=0,
            latency_ms=0,
            error="All models for this role failed",
        )
    
    async def generate_payloads(
        self,
        technique: str,
        target_info: Dict[str, Any],
        previous_responses: List[Dict[str, Any]] = None,
        waf_detected: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate attack payloads using the payload generator model.
        """
        context = f"""Generate attack payloads for the following scenario:

Technique: {technique}
Target Information:
{json.dumps(target_info, indent=2)}

Previous Responses: {len(previous_responses or [])} available
WAF Detected: {waf_detected}

{f"WAF evasion required - use encoding and obfuscation." if waf_detected else ""}

Based on the target technology and previous responses, generate the most effective payloads."""

        if previous_responses:
            context += f"\n\nLast 3 responses:\n{json.dumps(previous_responses[-3:], indent=2)}"
        
        response = await self.invoke_role(ModelRole.PAYLOAD_GENERATOR, context)
        
        if response.error:
            return {
                "payloads": [],
                "error": response.error,
            }
        
        # Parse JSON response
        try:
            result = json.loads(self._extract_json(response.content))
            return result
        except json.JSONDecodeError:
            # Try to extract payloads from text
            payloads = re.findall(r'"([^"]+)"', response.content)
            return {
                "payloads": payloads[:10],
                "reasoning": response.content,
            }
    
    async def analyze_response(
        self,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any],
        baseline_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a response for vulnerability indicators.
        """
        context = f"""Analyze the following HTTP response for security vulnerabilities:

Request:
{json.dumps(request_info, indent=2)}

Response:
{json.dumps(response_info, indent=2)}

{f"Baseline Response:{chr(10)}{json.dumps(baseline_info, indent=2)}" if baseline_info else ""}

Identify any vulnerability indicators, technology leaks, or anomalies."""

        response = await self.invoke_role(ModelRole.RESPONSE_ANALYZER, context)
        
        if response.error:
            return {
                "vulnerability_detected": False,
                "error": response.error,
            }
        
        try:
            return json.loads(self._extract_json(response.content))
        except json.JSONDecodeError:
            return {
                "vulnerability_detected": False,
                "analysis": response.content,
            }
    
    async def correlate_findings(
        self,
        findings: List[Dict[str, Any]],
        target_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Correlate findings to identify root causes and attack chains.
        """
        context = f"""Analyze and correlate the following security findings:

Findings:
{json.dumps(findings, indent=2)}

Target Information:
{json.dumps(target_info, indent=2)}

Identify:
1. Related findings that indicate the same root cause
2. Findings that can be chained for higher impact
3. Priority ranking based on real exploitability
4. Any false positives based on cross-validation"""

        response = await self.invoke_role(ModelRole.CORRELATION, context)
        
        if response.error:
            return {
                "correlations": [],
                "error": response.error,
            }
        
        try:
            return json.loads(self._extract_json(response.content))
        except json.JSONDecodeError:
            return {
                "analysis": response.content,
            }
    
    async def develop_exploit(
        self,
        finding: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Develop proof-of-concept exploit for a finding.
        """
        context = f"""Develop a proof-of-concept exploit for the following vulnerability:

Finding:
{json.dumps(finding, indent=2)}

Target Information:
{json.dumps(target_info, indent=2)}

Create a safe, demonstrable PoC that proves the vulnerability exists."""

        response = await self.invoke_role(ModelRole.EXPLOITATION, context)
        
        if response.error:
            return {
                "exploitable": False,
                "error": response.error,
            }
        
        try:
            return json.loads(self._extract_json(response.content))
        except json.JSONDecodeError:
            return {
                "poc_description": response.content,
            }
    
    async def generate_remediation(
        self,
        findings: List[Dict[str, Any]],
        target_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Generate remediation recommendations for findings.
        """
        context = f"""Generate remediation recommendations for the following vulnerabilities:

Findings:
{json.dumps(findings, indent=2)}

Target Technology:
{json.dumps(target_info, indent=2)}

Provide specific, actionable fixes with code examples where applicable."""

        response = await self.invoke_role(ModelRole.REMEDIATION, context)
        
        if response.error:
            return {
                "remediations": [],
                "error": response.error,
            }
        
        try:
            return json.loads(self._extract_json(response.content))
        except json.JSONDecodeError:
            return {
                "recommendations": response.content,
            }
    
    async def reason_chain(
        self,
        task: str,
        context: Dict[str, Any],
        steps: List[ModelRole] = None,
    ) -> ReasoningChain:
        """
        Execute a multi-step reasoning chain across different models.
        
        Args:
            task: Description of the reasoning task
            context: Initial context data
            steps: Sequence of model roles to invoke (default: analysis -> correlation -> exploitation)
        """
        import uuid
        
        if steps is None:
            steps = [
                ModelRole.RESPONSE_ANALYZER,
                ModelRole.CORRELATION,
                ModelRole.EXPLOITATION,
            ]
        
        chain = ReasoningChain(
            chain_id=str(uuid.uuid4())[:8],
            task=task,
        )
        
        current_context = json.dumps(context, indent=2)
        
        for i, role in enumerate(steps):
            step_context = f"""Task: {task}
Step {i + 1}/{len(steps)}: {role.value}

Context from previous steps:
{current_context}

Previous reasoning:
{chr(10).join(f"- {s.role.value}: {s.output[:200]}..." for s in chain.steps[-3:])}

Provide your analysis for this step."""

            start_time = time.time()
            response = await self.invoke_role(role, step_context)
            latency = (time.time() - start_time) * 1000
            
            step = ReasoningStep(
                step_id=f"{chain.chain_id}_{i}",
                role=role,
                input_context=step_context[:500],
                output=response.content,
                confidence=0.8 if not response.error else 0.0,
                latency_ms=latency,
                model_used=response.model_name,
            )
            
            chain.steps.append(step)
            chain.total_latency_ms += latency
            chain.total_tokens += response.tokens_used
            
            if response.error:
                chain.success = False
                chain.final_output = f"Failed at step {i + 1}: {response.error}"
                break
            
            # Update context for next step
            current_context = response.content
        else:
            chain.success = True
            chain.final_output = chain.steps[-1].output if chain.steps else ""
        
        self._reasoning_history.append(chain)
        return chain
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from model response text."""
        # Try to find JSON block
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', text)
        if json_match:
            return json_match.group(1)
        
        # Try to find raw JSON
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            return json_match.group(0)
        
        return text
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            **self._stats,
            "registered_models": {
                role.value: len(configs) 
                for role, configs in self._models.items()
            },
            "cache_stats": self._cache.stats(),
            "reasoning_chains": len(self._reasoning_history),
        }
    
    def get_reasoning_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent reasoning chains."""
        return [c.to_dict() for c in self._reasoning_history[-limit:]]
    
    def clear_cache(self):
        """Clear the response cache."""
        self._cache.clear()
    
    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "total_invocations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
            "total_tokens": 0,
            "total_latency_ms": 0,
        }


# =============================================================================
# RULE-BASED FALLBACK
# =============================================================================

class RuleBasedFallback:
    """
    Rule-based fallback when LLM models are unavailable.
    Provides deterministic payload generation and response analysis.
    """
    
    def __init__(self):
        self._payload_patterns = {
            "sql_injection": [
                "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE--",
                "' UNION SELECT NULL--", "' AND '1'='1",
            ],
            "xss": [
                "<script>alert(1)</script>", "javascript:alert(1)",
                "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
            ],
            "command_injection": [
                "; id", "| whoami", "&& cat /etc/passwd",
                "`id`", "$(whoami)",
            ],
            "path_traversal": [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32",
                "%2e%2e%2f%2e%2e%2fetc/passwd",
            ],
        }
        
        self._vulnerability_indicators = {
            "sql_injection": [
                "sql syntax", "mysql", "sqlite", "postgresql",
                "ora-", "microsoft ole db", "odbc drivers",
            ],
            "xss": [
                "<script", "onerror=", "javascript:",
            ],
            "command_injection": [
                "uid=", "root:", "bin/bash",
            ],
            "path_traversal": [
                "root:x:", "[fonts]", "boot.ini",
            ],
        }
    
    def generate_payloads(self, technique: str) -> List[str]:
        """Generate payloads for technique."""
        return self._payload_patterns.get(technique.lower(), [])
    
    def analyze_response(
        self,
        technique: str,
        response_body: str,
    ) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators."""
        indicators = self._vulnerability_indicators.get(technique.lower(), [])
        found = []
        
        body_lower = response_body.lower()
        for indicator in indicators:
            if indicator.lower() in body_lower:
                found.append(indicator)
        
        return {
            "vulnerability_detected": len(found) > 0,
            "confidence": min(len(found) * 0.3, 1.0),
            "indicators": found,
        }


# Global engine instance
_reasoning_engine = MultiModelReasoningEngine()
_rule_fallback = RuleBasedFallback()


def get_reasoning_engine() -> MultiModelReasoningEngine:
    """Get the global reasoning engine."""
    return _reasoning_engine


def configure_reasoning_engine(
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    ollama_url: Optional[str] = None,
):
    """
    Configure the reasoning engine with model configurations.
    """
    engine = get_reasoning_engine()
    
    if openai_key:
        # Register GPT-4 for complex reasoning
        engine.register_model(ModelConfig(
            role=ModelRole.CORRELATION,
            provider=ModelProvider.OPENAI,
            model_name="gpt-4-turbo-preview",
            api_key=openai_key,
            priority=1,
        ))
        engine.register_model(ModelConfig(
            role=ModelRole.EXPLOITATION,
            provider=ModelProvider.OPENAI,
            model_name="gpt-4-turbo-preview",
            api_key=openai_key,
            priority=1,
        ))
        
        # Register GPT-3.5 for simpler tasks
        engine.register_model(ModelConfig(
            role=ModelRole.PAYLOAD_GENERATOR,
            provider=ModelProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key=openai_key,
            priority=1,
        ))
        engine.register_model(ModelConfig(
            role=ModelRole.RESPONSE_ANALYZER,
            provider=ModelProvider.OPENAI,
            model_name="gpt-3.5-turbo",
            api_key=openai_key,
            priority=1,
        ))
    
    if anthropic_key:
        # Register Claude for high-quality analysis
        engine.register_model(ModelConfig(
            role=ModelRole.REMEDIATION,
            provider=ModelProvider.ANTHROPIC,
            model_name="claude-3-opus-20240229",
            api_key=anthropic_key,
            priority=1,
        ))
    
    if ollama_url:
        # Register local models as fallback
        for role in ModelRole:
            engine.register_model(ModelConfig(
                role=role,
                provider=ModelProvider.OLLAMA,
                model_name="llama2",
                base_url=ollama_url,
                priority=10,  # Low priority fallback
            ))
    
    logger.info("Reasoning engine configured")
