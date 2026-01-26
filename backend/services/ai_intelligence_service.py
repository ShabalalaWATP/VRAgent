"""
AI Intelligence Service - Deep Learning for Malware Analysis

Adds real AI intelligence using LLMs:
1. Gemini/Claude for malware classification
2. Deep code understanding
3. Threat actor attribution
4. Exploit potential assessment
5. Remediation recommendations
"""

import json
import logging
from typing import Any, Dict, List, Optional

from backend.core.config import settings

logger = logging.getLogger(__name__)


class AIIntelligenceService:
    """
    AI-powered intelligence for malware analysis.

    Uses LLMs (Gemini/Claude) for deep analysis and classification.
    """

    def __init__(self):
        self.model_name = "gemini-3-flash-preview"
        self.gemini_client = None
        self._init_gemini()

    def _init_gemini(self):
        """Initialize Gemini AI client."""
        try:
            from google import genai
            self.gemini_client = genai.Client(api_key=settings.gemini_api_key)
            logger.info(f"Gemini AI initialized with model: {self.model_name}")
        except Exception as e:
            logger.warning(f"Gemini AI not available: {e}")

    async def classify_malware(
        self,
        binary_info: Dict[str, Any],
        static_findings: Dict[str, Any],
        dynamic_findings: Dict[str, Any],
        behavioral_findings: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform AI-powered malware classification.

        Args:
            binary_info: Binary metadata
            static_findings: Static analysis results
            dynamic_findings: Dynamic analysis results
            behavioral_findings: Behavioral analysis results

        Returns:
            AI classification with family, confidence, and reasoning
        """
        if not self.gemini_client:
            logger.warning("Gemini not available, falling back to heuristics")
            return self._heuristic_classification(static_findings, dynamic_findings, behavioral_findings)

        try:
            prompt = self._build_classification_prompt(
                binary_info, static_findings, dynamic_findings, behavioral_findings
            )

            response = self.gemini_client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            result = self._parse_classification_response(response.text)

            logger.info(f"AI Classification: {result.get('malware_family')} (confidence: {result.get('confidence')})")
            return result

        except Exception as e:
            logger.error(f"AI classification failed: {e}")
            return self._heuristic_classification(static_findings, dynamic_findings, behavioral_findings)

    def _build_classification_prompt(
        self,
        binary_info: Dict,
        static_findings: Dict,
        dynamic_findings: Dict,
        behavioral_findings: Dict
    ) -> str:
        """Build prompt for AI classification."""
        prompt = f"""You are an expert malware analyst. Analyze the following malware sample and provide a comprehensive classification.

**Binary Information:**
- Name: {binary_info.get('name', 'unknown')}
- Hash (SHA256): {binary_info.get('hash', 'unknown')}
- Size: {binary_info.get('size', 0)} bytes
- Platform: {binary_info.get('platform', 'unknown')}
- Architecture: {binary_info.get('architecture', 'unknown')}

**Static Analysis Findings:**
- Packed: {static_findings.get('packer_info', {}).get('is_packed', False)}
- Packer: {static_findings.get('packer_info', {}).get('packer_name', 'None')}
- Entropy: {static_findings.get('packer_info', {}).get('entropy', 0.0):.2f}
- YARA Matches: {len(static_findings.get('yara_matches', []))}
  {self._format_yara_matches(static_findings.get('yara_matches', []))}

**Dynamic Analysis Findings:**
- Executed: {dynamic_findings.get('executed', False)}
- API Calls: {dynamic_findings.get('api_calls_count', 0)}
- Network Connections: {dynamic_findings.get('network_connections', 0)}
- Files Accessed: {dynamic_findings.get('files_accessed', 0)}
- Registry Modified: {dynamic_findings.get('registry_modified', 0)}

**Behavioral Analysis Findings:**
- C2 Beacons: {len(behavioral_findings.get('c2_beacons', []))}
  {self._format_c2_beacons(behavioral_findings.get('c2_beacons', []))}
- Persistence Mechanisms: {len(behavioral_findings.get('persistence_mechanisms', []))}
  {self._format_persistence(behavioral_findings.get('persistence_mechanisms', []))}
- Privilege Escalations: {len(behavioral_findings.get('privilege_escalations', []))}
  {self._format_privilege_esc(behavioral_findings.get('privilege_escalations', []))}
- Lateral Movements: {len(behavioral_findings.get('lateral_movements', []))}

**Task:**
Provide a comprehensive malware classification in JSON format:

{{
  "is_malicious": true/false,
  "confidence": 0.0-1.0,
  "malware_family": "ransomware|trojan|backdoor|infostealer|worm|rootkit|downloader|dropper|cryptominer|adware|spyware|apt|unknown",
  "malware_categories": ["category1", "category2"],
  "threat_score": 0-100,
  "severity": "low|medium|high|critical",
  "threat_actor": "optional threat actor attribution",
  "campaign": "optional campaign name",
  "reasoning": "detailed explanation of classification",
  "capabilities": ["capability1", "capability2"],
  "mitre_tactics": ["TA0001", "TA0002"],
  "mitre_techniques": ["T1547.001", "T1055"],
  "iocs": {{
    "ips": ["1.2.3.4"],
    "domains": ["evil.com"],
    "urls": ["http://evil.com/payload"],
    "file_hashes": ["abc123..."],
    "registry_keys": ["HKLM\\\\..."],
    "mutexes": ["malware_mutex"]
  }},
  "remediation": "step-by-step remediation recommendations",
  "similar_samples": ["known similar malware families or campaigns"]
}}

**Important:**
- Base classification on the evidence provided
- Consider YARA matches as strong indicators
- C2 beacons and persistence are high-confidence malicious indicators
- Provide detailed reasoning for your classification
- Be specific about threat actor attribution if patterns match known groups
- Include all relevant MITRE ATT&CK techniques observed
"""
        return prompt

    def _format_yara_matches(self, matches: List[Dict]) -> str:
        """Format YARA matches for prompt."""
        if not matches:
            return "  None"
        return "\n".join([f"  - {m.get('rule', 'unknown')}: {', '.join(m.get('tags', []))}" for m in matches[:5]])

    def _format_c2_beacons(self, beacons: List[Dict]) -> str:
        """Format C2 beacons for prompt."""
        if not beacons:
            return "  None"
        return "\n".join([
            f"  - {b.get('type', 'unknown')}: {b.get('server', 'unknown')} (interval: {b.get('interval', 0)}s)"
            for b in beacons[:3]
        ])

    def _format_persistence(self, mechanisms: List[Dict]) -> str:
        """Format persistence mechanisms for prompt."""
        if not mechanisms:
            return "  None"
        return "\n".join([
            f"  - {m.get('type', 'unknown')}: {m.get('location', 'unknown')}"
            for m in mechanisms[:3]
        ])

    def _format_privilege_esc(self, escalations: List[Dict]) -> str:
        """Format privilege escalations for prompt."""
        if not escalations:
            return "  None"
        return "\n".join([
            f"  - {e.get('technique', 'unknown')}"
            for e in escalations[:3]
        ])

    def _parse_classification_response(self, response_text: str) -> Dict[str, Any]:
        """Parse AI classification response."""
        try:
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            if json_start != -1 and json_end != -1:
                json_str = response_text[json_start:json_end]
                result = json.loads(json_str)
                return result
            else:
                logger.warning("No JSON found in AI response")
                return self._default_classification()
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return self._default_classification()

    def _heuristic_classification(
        self,
        static_findings: Dict,
        dynamic_findings: Dict,
        behavioral_findings: Dict
    ) -> Dict[str, Any]:
        """Fallback heuristic classification when AI is unavailable."""
        score = 0
        is_malicious = False
        family = "unknown"
        categories = []

        # Track number of distinct suspicious behaviors
        suspicious_count = 0
        critical_indicators = []

        # YARA matches (WEIGHTED - not instant malicious)
        yara_matches = static_findings.get('yara_matches', [])
        for match in yara_matches:
            rule_name = match.get('rule', '')

            # Critical rules (high confidence)
            if 'Ransomware' in rule_name or 'Worm' in rule_name:
                critical_indicators.append(rule_name)
                score += 35
                family = 'ransomware' if 'Ransomware' in rule_name else 'worm'
                categories.append(family)
                suspicious_count += 1
            # Medium severity
            elif 'Trojan' in rule_name or 'RAT' in rule_name or 'Backdoor' in rule_name:
                score += 25
                suspicious_count += 1
                if not family or family == 'unknown':
                    family = 'trojan' if 'Trojan' in rule_name else 'backdoor'
                    categories.append(family)
            # Low severity (common in legitimate software - debuggers, installers)
            elif 'AntiAnalysis' in rule_name or 'ProcessInjection' in rule_name:
                score += 5  # Very low weight
                # Don't increment suspicious_count - these are common in legitimate software
            else:
                score += 15
                suspicious_count += 1

        # C2 beacons (STRONG indicator - rare in legitimate software)
        c2_beacons = behavioral_findings.get('c2_beacons', [])
        if c2_beacons:
            critical_indicators.append('C2 beacons')
            score += 40
            suspicious_count += 1
            if not family or family == 'unknown':
                family = 'trojan'
                categories.append('trojan')

        # Persistence (WEIGHTED - common in legitimate installers)
        persistence = behavioral_findings.get('persistence_mechanisms', [])
        if persistence:
            # Only suspicious if combined with other indicators
            if suspicious_count > 0:
                score += len(persistence) * 12
                suspicious_count += 1
            else:
                # Alone, just add minimal score (installers use persistence)
                score += len(persistence) * 3

        # Privilege escalation (MEDIUM indicator)
        priv_esc = behavioral_findings.get('privilege_escalations', [])
        if priv_esc:
            score += len(priv_esc) * 20
            suspicious_count += 1

        # Lateral movement (STRONG indicator - very suspicious)
        lateral = behavioral_findings.get('lateral_movements', [])
        if lateral:
            critical_indicators.append('lateral movement')
            score += 35
            suspicious_count += 1

        score = min(score, 100)

        # DECISION LOGIC: Require multiple indicators OR one critical indicator
        # This prevents false positives on legitimate software
        if len(critical_indicators) > 0:
            # Critical indicators = high confidence malicious
            is_malicious = True
        elif suspicious_count >= 3:
            # Multiple corroborating indicators = likely malicious
            is_malicious = True
        elif score >= 60:
            # High score with multiple behaviors
            is_malicious = True
        else:
            # Single low-severity indicator = NOT malicious
            is_malicious = False

        # Adjust confidence based on evidence strength
        confidence = min(score / 100.0, 0.95)
        if suspicious_count == 1 and len(critical_indicators) == 0:
            confidence = min(confidence, 0.50)  # Low confidence with single non-critical indicator
        elif suspicious_count == 2 and len(critical_indicators) == 0:
            confidence = min(confidence, 0.70)  # Medium confidence

        reasoning = f"Heuristic classification: {suspicious_count} suspicious behaviors detected. "
        if critical_indicators:
            reasoning += f"Critical indicators: {', '.join(critical_indicators)}. "
        if suspicious_count == 0:
            reasoning += "No significant malicious indicators found. "
        elif suspicious_count == 1:
            reasoning += "Single indicator only - insufficient for high-confidence classification. "

        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'malware_family': family,
            'malware_categories': list(set(categories)),
            'threat_score': score,
            'severity': 'critical' if score > 75 else 'high' if score > 50 else 'medium' if score > 25 else 'low',
            'reasoning': reasoning,
            'capabilities': [],
            'mitre_tactics': [],
            'mitre_techniques': [],
            'suspicious_behavior_count': suspicious_count,
            'critical_indicator_count': len(critical_indicators)
        }

    def _default_classification(self) -> Dict[str, Any]:
        """Default classification when parsing fails."""
        return {
            'is_malicious': False,
            'confidence': 0.5,
            'malware_family': 'unknown',
            'malware_categories': [],
            'threat_score': 0,
            'severity': 'low',
            'reasoning': 'Classification unavailable',
            'capabilities': [],
            'mitre_tactics': [],
            'mitre_techniques': []
        }

    async def explain_behavior(
        self,
        api_calls: List[Dict],
        network_activity: List[Dict],
        file_operations: List[Dict]
    ) -> str:
        """
        Generate natural language explanation of malware behavior.

        Args:
            api_calls: List of API calls
            network_activity: Network connections
            file_operations: File operations

        Returns:
            Natural language explanation
        """
        if not self.gemini_client:
            return self._heuristic_explanation(api_calls, network_activity, file_operations)

        try:
            prompt = f"""Explain the behavior of this malware in clear, non-technical language:

**API Calls (first 20):**
{json.dumps(api_calls[:20], indent=2)}

**Network Activity:**
{json.dumps(network_activity, indent=2)}

**File Operations (first 10):**
{json.dumps(file_operations[:10], indent=2)}

Provide a concise 3-4 sentence explanation of what the malware is doing, suitable for a security report.
Focus on the impact and intent, not technical details."""

            response = self.gemini_client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text.strip()

        except Exception as e:
            logger.error(f"Behavior explanation failed: {e}")
            return self._heuristic_explanation(api_calls, network_activity, file_operations)

    def _heuristic_explanation(
        self,
        api_calls: List[Dict],
        network_activity: List[Dict],
        file_operations: List[Dict]
    ) -> str:
        """Generate heuristic behavior explanation."""
        behaviors = []

        if network_activity:
            behaviors.append(f"establishes {len(network_activity)} network connection(s)")

        if file_operations:
            write_count = sum(1 for f in file_operations if 'write' in str(f).lower())
            if write_count > 0:
                behaviors.append(f"modifies {write_count} file(s)")

        if api_calls:
            registry_ops = sum(1 for api in api_calls if 'reg' in str(api.get('api', '')).lower())
            if registry_ops > 0:
                behaviors.append(f"makes {registry_ops} registry modification(s)")

        if not behaviors:
            return "The malware exhibits limited observable behavior."

        return f"The malware {', '.join(behaviors)}. This pattern suggests malicious intent."

    async def suggest_remediation(
        self,
        malware_family: str,
        persistence_mechanisms: List[Dict],
        iocs: Dict[str, List[str]]
    ) -> List[str]:
        """
        Generate remediation recommendations.

        Args:
            malware_family: Identified malware family
            persistence_mechanisms: Persistence mechanisms found
            iocs: Indicators of Compromise

        Returns:
            List of remediation steps
        """
        if not self.gemini_client:
            return self._heuristic_remediation(malware_family, persistence_mechanisms, iocs)

        try:
            prompt = f"""Generate step-by-step remediation instructions for this malware:

**Malware Family:** {malware_family}

**Persistence Mechanisms:**
{json.dumps(persistence_mechanisms, indent=2)}

**IOCs:**
{json.dumps(iocs, indent=2)}

Provide 5-8 specific, actionable remediation steps in order of priority.
Format as a numbered list."""

            response = self.gemini_client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            # Parse numbered list
            steps = []
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                    # Remove numbering
                    clean_line = line.lstrip('0123456789.-* ')
                    if clean_line:
                        steps.append(clean_line)

            return steps if steps else self._heuristic_remediation(malware_family, persistence_mechanisms, iocs)

        except Exception as e:
            logger.error(f"Remediation generation failed: {e}")
            return self._heuristic_remediation(malware_family, persistence_mechanisms, iocs)

    def _heuristic_remediation(
        self,
        malware_family: str,
        persistence_mechanisms: List[Dict],
        iocs: Dict[str, List[str]]
    ) -> List[str]:
        """Generate heuristic remediation steps."""
        steps = []

        # Generic first steps
        steps.append("Isolate the infected system from the network immediately")
        steps.append("Boot into Safe Mode or use a clean OS to perform remediation")

        # Remove persistence
        for mechanism in persistence_mechanisms:
            mech_type = mechanism.get('type', 'unknown')
            location = mechanism.get('location', '')

            if mech_type == 'registry':
                steps.append(f"Delete registry key: {location}")
            elif mech_type == 'service':
                steps.append(f"Stop and delete malicious service: {location}")
            elif mech_type == 'scheduled_task':
                steps.append(f"Delete scheduled task: {location}")
            elif mech_type == 'startup_folder':
                steps.append(f"Remove file from startup folder: {location}")

        # Block IOCs
        if iocs.get('ips'):
            steps.append(f"Block IP addresses in firewall: {', '.join(iocs['ips'][:3])}")
        if iocs.get('domains'):
            steps.append(f"Block domains in DNS: {', '.join(iocs['domains'][:3])}")

        # Generic final steps
        steps.append("Run full antivirus/EDR scan")
        steps.append("Review event logs for additional indicators")
        steps.append("Consider full system reimaging if infection is severe")

        return steps
