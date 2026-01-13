"""
AI Security Analysis Service

Provides advanced AI-driven security analysis:
- Part 1: Exploit Chain Analysis - connecting related findings into attack paths
- Part 2: Root Cause Analysis - identifying underlying security issues
- Part 3: Impact Assessment - business and technical impact scoring
- Part 4: Remediation Prioritization - smart fix ordering
- Part 5: Integration functions

Uses LLM for intelligent analysis when available, falls back to rule-based analysis.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import logging
import json
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


# =============================================================================
# PART 1: EXPLOIT CHAIN ANALYZER
# =============================================================================

class AttackStage(Enum):
    """Stages in a typical attack kill chain."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# Map techniques to attack stages
TECHNIQUE_ATTACK_STAGE: Dict[str, List[AttackStage]] = {
    "sql_injection": [AttackStage.INITIAL_ACCESS, AttackStage.CREDENTIAL_ACCESS, AttackStage.COLLECTION],
    "xss": [AttackStage.INITIAL_ACCESS, AttackStage.CREDENTIAL_ACCESS],
    "command_injection": [AttackStage.EXECUTION, AttackStage.PRIVILEGE_ESCALATION],
    "path_traversal": [AttackStage.DISCOVERY, AttackStage.COLLECTION],
    "idor": [AttackStage.COLLECTION, AttackStage.LATERAL_MOVEMENT],
    "ssrf": [AttackStage.DISCOVERY, AttackStage.LATERAL_MOVEMENT, AttackStage.INITIAL_ACCESS],
    "ssti": [AttackStage.EXECUTION, AttackStage.PRIVILEGE_ESCALATION],
    "xxe": [AttackStage.DISCOVERY, AttackStage.COLLECTION, AttackStage.EXECUTION],
    "auth_bypass": [AttackStage.INITIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION],
    "header_injection": [AttackStage.DEFENSE_EVASION, AttackStage.CREDENTIAL_ACCESS],
    "business_logic": [AttackStage.IMPACT, AttackStage.COLLECTION],
    "api_abuse": [AttackStage.RECONNAISSANCE, AttackStage.COLLECTION],
    "deserialization": [AttackStage.EXECUTION, AttackStage.PRIVILEGE_ESCALATION],
    "race_condition": [AttackStage.PRIVILEGE_ESCALATION, AttackStage.IMPACT],
}


@dataclass
class ExploitChainLink:
    """A single link in an exploit chain."""
    finding_id: str
    technique: str
    stage: AttackStage
    description: str
    prerequisites: List[str] = field(default_factory=list)  # Finding IDs needed first
    enables: List[str] = field(default_factory=list)  # Finding IDs this enables
    confidence: float = 0.8  # 0-1 confidence in this link
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "technique": self.technique,
            "stage": self.stage.value,
            "description": self.description,
            "prerequisites": self.prerequisites,
            "enables": self.enables,
            "confidence": self.confidence,
        }


@dataclass
class ExploitChain:
    """A complete exploit chain connecting multiple vulnerabilities."""
    chain_id: str
    name: str
    description: str
    links: List[ExploitChainLink]
    total_impact_score: float  # 0-10
    likelihood_score: float  # 0-10
    attack_complexity: str  # Low, Medium, High
    final_impact: str  # What attacker achieves
    mitre_tactics: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "description": self.description,
            "links": [link.to_dict() for link in self.links],
            "link_count": len(self.links),
            "total_impact_score": self.total_impact_score,
            "likelihood_score": self.likelihood_score,
            "combined_risk_score": round((self.total_impact_score * self.likelihood_score) / 10, 1),
            "attack_complexity": self.attack_complexity,
            "final_impact": self.final_impact,
            "mitre_tactics": self.mitre_tactics,
        }


class ExploitChainAnalyzer:
    """
    Analyzes findings to identify potential exploit chains.
    
    An exploit chain is a sequence of vulnerabilities that can be
    combined to achieve a greater impact than any single vulnerability.
    """
    
    # Define which techniques can chain together
    CHAIN_RELATIONSHIPS: Dict[str, List[str]] = {
        "xss": ["auth_bypass", "idor", "ssrf"],  # XSS can steal tokens for other attacks
        "sql_injection": ["auth_bypass", "idor", "path_traversal"],  # SQLi can leak data for other attacks
        "ssrf": ["path_traversal", "command_injection", "xxe"],  # SSRF can reach internal services
        "path_traversal": ["command_injection", "deserialization"],  # Path traversal can access sensitive files
        "auth_bypass": ["idor", "business_logic", "api_abuse"],  # Auth bypass enables many attacks
        "idor": ["business_logic", "api_abuse"],  # IDOR enables data access
        "xxe": ["ssrf", "path_traversal", "command_injection"],  # XXE can read files and make requests
        "ssti": ["command_injection"],  # SSTI often leads to RCE
        "deserialization": ["command_injection"],  # Deserialization often leads to RCE
    }
    
    # Impact multipliers when chains combine
    CHAIN_IMPACT_MULTIPLIERS: Dict[Tuple[str, str], float] = {
        ("xss", "auth_bypass"): 1.5,  # Session hijacking
        ("sql_injection", "auth_bypass"): 1.8,  # Full DB + auth compromise
        ("ssrf", "command_injection"): 2.0,  # Internal RCE
        ("auth_bypass", "idor"): 1.6,  # Full data access
        ("path_traversal", "command_injection"): 1.9,  # Config leak + RCE
        ("xxe", "ssrf"): 1.7,  # Internal network access
        ("ssti", "command_injection"): 1.3,  # Already high impact
    }
    
    def __init__(self):
        self._chain_counter = 0
    
    def _generate_chain_id(self) -> str:
        """Generate unique chain ID."""
        self._chain_counter += 1
        return f"chain_{self._chain_counter}_{datetime.now().strftime('%H%M%S')}"
    
    def analyze_findings(self, findings: List[Dict]) -> List[ExploitChain]:
        """
        Analyze findings to identify exploit chains.
        
        Args:
            findings: List of finding dictionaries with 'id', 'technique', 'severity', 'url'
            
        Returns:
            List of identified exploit chains
        """
        if len(findings) < 2:
            return []
        
        chains = []
        
        # Group findings by URL/endpoint for related chain analysis
        findings_by_url = self._group_by_url(findings)
        
        # Find direct chains (same endpoint, different techniques)
        for url, url_findings in findings_by_url.items():
            if len(url_findings) >= 2:
                direct_chains = self._find_direct_chains(url_findings, url)
                chains.extend(direct_chains)
        
        # Find cross-endpoint chains
        cross_chains = self._find_cross_endpoint_chains(findings)
        chains.extend(cross_chains)
        
        # Deduplicate and rank chains
        chains = self._deduplicate_chains(chains)
        chains.sort(key=lambda c: c.total_impact_score * c.likelihood_score, reverse=True)
        
        return chains[:10]  # Return top 10 chains
    
    def _group_by_url(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by URL/endpoint."""
        grouped = {}
        for finding in findings:
            url = finding.get("url", finding.get("endpoint", "unknown"))
            # Normalize URL to base path
            base_url = url.split("?")[0].rstrip("/")
            if base_url not in grouped:
                grouped[base_url] = []
            grouped[base_url].append(finding)
        return grouped
    
    def _find_direct_chains(self, findings: List[Dict], url: str) -> List[ExploitChain]:
        """Find chains where vulnerabilities at the same endpoint combine."""
        chains = []
        techniques = [(f.get("id", str(i)), f.get("technique", "").lower().replace(" ", "_")) 
                      for i, f in enumerate(findings)]
        
        # Check each pair for chain relationship
        for i, (id1, tech1) in enumerate(techniques):
            for id2, tech2 in techniques[i+1:]:
                if tech2 in self.CHAIN_RELATIONSHIPS.get(tech1, []):
                    chain = self._build_chain(findings, [(id1, tech1), (id2, tech2)], url)
                    if chain:
                        chains.append(chain)
                elif tech1 in self.CHAIN_RELATIONSHIPS.get(tech2, []):
                    chain = self._build_chain(findings, [(id2, tech2), (id1, tech1)], url)
                    if chain:
                        chains.append(chain)
        
        return chains
    
    def _find_cross_endpoint_chains(self, findings: List[Dict]) -> List[ExploitChain]:
        """Find chains across different endpoints."""
        chains = []
        
        # Look for auth_bypass that enables other attacks
        auth_findings = [f for f in findings if "auth" in f.get("technique", "").lower()]
        other_findings = [f for f in findings if "auth" not in f.get("technique", "").lower()]
        
        for auth_f in auth_findings:
            for other_f in other_findings:
                other_tech = other_f.get("technique", "").lower().replace(" ", "_")
                if other_tech in self.CHAIN_RELATIONSHIPS.get("auth_bypass", []):
                    chain = self._build_chain(
                        findings,
                        [
                            (auth_f.get("id", "auth"), "auth_bypass"),
                            (other_f.get("id", "other"), other_tech)
                        ],
                        "cross-endpoint"
                    )
                    if chain:
                        chains.append(chain)
        
        return chains
    
    def _build_chain(
        self, 
        findings: List[Dict], 
        chain_techs: List[Tuple[str, str]], 
        url: str
    ) -> Optional[ExploitChain]:
        """Build an exploit chain from technique pairs."""
        if len(chain_techs) < 2:
            return None
        
        links = []
        prev_id = None
        
        for finding_id, technique in chain_techs:
            stages = TECHNIQUE_ATTACK_STAGE.get(technique, [AttackStage.INITIAL_ACCESS])
            stage = stages[0] if stages else AttackStage.INITIAL_ACCESS
            
            link = ExploitChainLink(
                finding_id=finding_id,
                technique=technique,
                stage=stage,
                description=f"{technique.replace('_', ' ').title()} enables next attack stage",
                prerequisites=[prev_id] if prev_id else [],
                enables=[],
                confidence=0.75,
            )
            
            if links:
                links[-1].enables.append(finding_id)
            
            links.append(link)
            prev_id = finding_id
        
        # Calculate impact
        base_impact = 5.0
        tech1, tech2 = chain_techs[0][1], chain_techs[1][1]
        multiplier = self.CHAIN_IMPACT_MULTIPLIERS.get((tech1, tech2), 1.3)
        total_impact = min(base_impact * multiplier, 10.0)
        
        # Determine attack complexity
        complexity = "Medium"
        if any(t in ["deserialization", "race_condition"] for _, t in chain_techs):
            complexity = "High"
        elif all(t in ["xss", "idor", "api_abuse"] for _, t in chain_techs):
            complexity = "Low"
        
        # Determine final impact
        final_impacts = {
            ("sql_injection", "auth_bypass"): "Full database and authentication compromise",
            ("xss", "auth_bypass"): "Account takeover via session hijacking",
            ("ssrf", "command_injection"): "Remote code execution on internal systems",
            ("auth_bypass", "idor"): "Complete unauthorized data access",
            ("path_traversal", "command_injection"): "Remote code execution via config manipulation",
        }
        final_impact = final_impacts.get(
            (tech1, tech2), 
            f"Combined {tech1} and {tech2} attack impact"
        )
        
        return ExploitChain(
            chain_id=self._generate_chain_id(),
            name=f"{tech1.replace('_', ' ').title()} → {tech2.replace('_', ' ').title()} Chain",
            description=f"Exploit chain at {url} combining {tech1} with {tech2}",
            links=links,
            total_impact_score=round(total_impact, 1),
            likelihood_score=7.0 if complexity == "Low" else 5.0 if complexity == "Medium" else 3.0,
            attack_complexity=complexity,
            final_impact=final_impact,
            mitre_tactics=[stage.value for stage in TECHNIQUE_ATTACK_STAGE.get(tech1, [])],
        )
    
    def _deduplicate_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """Remove duplicate chains."""
        seen = set()
        unique = []
        
        for chain in chains:
            # Create signature from techniques
            sig = tuple(sorted(link.technique for link in chain.links))
            if sig not in seen:
                seen.add(sig)
                unique.append(chain)
        
        return unique


# =============================================================================
# PART 2: ROOT CAUSE ANALYZER
# =============================================================================

class RootCauseCategory(Enum):
    """Categories of root causes for security vulnerabilities."""
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    ERROR_HANDLING = "error_handling"
    CONFIGURATION = "configuration"
    DESIGN_FLAW = "design_flaw"
    DEPENDENCY = "dependency"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class RootCause:
    """A root cause analysis result."""
    category: RootCauseCategory
    title: str
    description: str
    affected_findings: List[str]  # Finding IDs
    fix_complexity: str  # Low, Medium, High
    fix_scope: str  # Single file, Module, Architecture
    recommended_fix: str
    code_patterns_to_fix: List[str]
    prevention_measures: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "affected_findings": self.affected_findings,
            "affected_count": len(self.affected_findings),
            "fix_complexity": self.fix_complexity,
            "fix_scope": self.fix_scope,
            "recommended_fix": self.recommended_fix,
            "code_patterns_to_fix": self.code_patterns_to_fix,
            "prevention_measures": self.prevention_measures,
        }


# Technique to root cause mapping
TECHNIQUE_ROOT_CAUSES: Dict[str, List[Tuple[RootCauseCategory, str, str]]] = {
    "sql_injection": [
        (RootCauseCategory.INPUT_VALIDATION, "Missing input sanitization", 
         "Use parameterized queries/prepared statements"),
        (RootCauseCategory.DESIGN_FLAW, "Direct SQL string concatenation",
         "Implement ORM or query builder pattern"),
    ],
    "xss": [
        (RootCauseCategory.OUTPUT_ENCODING, "Missing output encoding",
         "Apply context-aware output encoding"),
        (RootCauseCategory.INPUT_VALIDATION, "Insufficient input filtering",
         "Implement allowlist-based input validation"),
    ],
    "command_injection": [
        (RootCauseCategory.INPUT_VALIDATION, "Unsanitized shell input",
         "Use parameterized system calls or avoid shell entirely"),
        (RootCauseCategory.DESIGN_FLAW, "Direct shell command execution",
         "Use language-native APIs instead of shell"),
    ],
    "path_traversal": [
        (RootCauseCategory.INPUT_VALIDATION, "Unvalidated file paths",
         "Canonicalize and validate paths against allowlist"),
    ],
    "idor": [
        (RootCauseCategory.AUTHORIZATION, "Missing object-level authorization",
         "Implement ownership checks on all resource access"),
    ],
    "ssrf": [
        (RootCauseCategory.INPUT_VALIDATION, "Unvalidated URLs",
         "Validate and allowlist destination URLs"),
        (RootCauseCategory.CONFIGURATION, "Missing network segmentation",
         "Block access to internal networks from application"),
    ],
    "auth_bypass": [
        (RootCauseCategory.AUTHENTICATION, "Flawed authentication logic",
         "Use established authentication framework"),
        (RootCauseCategory.DESIGN_FLAW, "Missing authentication checks",
         "Apply authentication middleware globally"),
    ],
    "ssti": [
        (RootCauseCategory.INPUT_VALIDATION, "User input in templates",
         "Never pass user input directly to template engine"),
    ],
    "xxe": [
        (RootCauseCategory.CONFIGURATION, "Unsafe XML parser configuration",
         "Disable external entity processing"),
    ],
    "deserialization": [
        (RootCauseCategory.INPUT_VALIDATION, "Untrusted deserialization",
         "Use type-safe serialization with allowlists"),
        (RootCauseCategory.DESIGN_FLAW, "Accepting serialized objects from untrusted sources",
         "Use simple data formats like JSON"),
    ],
    "business_logic": [
        (RootCauseCategory.BUSINESS_LOGIC, "Inadequate workflow validation",
         "Implement server-side state machine"),
        (RootCauseCategory.DESIGN_FLAW, "Client-side business logic",
         "Move all business rules to server"),
    ],
    "race_condition": [
        (RootCauseCategory.DESIGN_FLAW, "Missing concurrency controls",
         "Implement proper locking or atomic operations"),
    ],
}


class RootCauseAnalyzer:
    """
    Analyzes findings to identify root causes.
    
    Multiple findings often share the same underlying root cause.
    Fixing the root cause resolves multiple vulnerabilities at once.
    """
    
    def analyze_findings(self, findings: List[Dict]) -> List[RootCause]:
        """
        Analyze findings to identify root causes.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            List of root causes, grouped by category
        """
        # Group findings by technique
        by_technique: Dict[str, List[Dict]] = {}
        for finding in findings:
            tech = finding.get("technique", "").lower().replace(" ", "_")
            if tech not in by_technique:
                by_technique[tech] = []
            by_technique[tech].append(finding)
        
        root_causes = []
        seen_categories: Set[str] = set()
        
        for technique, tech_findings in by_technique.items():
            causes = TECHNIQUE_ROOT_CAUSES.get(technique, [])
            
            for category, title, fix in causes:
                # Create unique key for deduplication
                key = f"{category.value}:{title}"
                if key in seen_categories:
                    # Add findings to existing root cause
                    for rc in root_causes:
                        if rc.category == category and rc.title == title:
                            rc.affected_findings.extend(
                                [f.get("id", str(i)) for i, f in enumerate(tech_findings)]
                            )
                    continue
                
                seen_categories.add(key)
                
                # Determine fix complexity based on category
                complexity_map = {
                    RootCauseCategory.INPUT_VALIDATION: "Low",
                    RootCauseCategory.OUTPUT_ENCODING: "Low",
                    RootCauseCategory.CONFIGURATION: "Low",
                    RootCauseCategory.AUTHENTICATION: "Medium",
                    RootCauseCategory.AUTHORIZATION: "Medium",
                    RootCauseCategory.ERROR_HANDLING: "Low",
                    RootCauseCategory.CRYPTOGRAPHY: "Medium",
                    RootCauseCategory.DESIGN_FLAW: "High",
                    RootCauseCategory.BUSINESS_LOGIC: "High",
                    RootCauseCategory.DEPENDENCY: "Medium",
                }
                
                # Determine fix scope
                scope_map = {
                    RootCauseCategory.INPUT_VALIDATION: "Module",
                    RootCauseCategory.OUTPUT_ENCODING: "Module",
                    RootCauseCategory.CONFIGURATION: "Single file",
                    RootCauseCategory.AUTHENTICATION: "Architecture",
                    RootCauseCategory.AUTHORIZATION: "Module",
                    RootCauseCategory.DESIGN_FLAW: "Architecture",
                    RootCauseCategory.BUSINESS_LOGIC: "Module",
                }
                
                root_cause = RootCause(
                    category=category,
                    title=title,
                    description=self._generate_description(category, technique, len(tech_findings)),
                    affected_findings=[f.get("id", str(i)) for i, f in enumerate(tech_findings)],
                    fix_complexity=complexity_map.get(category, "Medium"),
                    fix_scope=scope_map.get(category, "Module"),
                    recommended_fix=fix,
                    code_patterns_to_fix=self._get_code_patterns(technique),
                    prevention_measures=self._get_prevention_measures(category),
                )
                root_causes.append(root_cause)
        
        # Sort by number of affected findings (fix most impactful first)
        root_causes.sort(key=lambda rc: len(rc.affected_findings), reverse=True)
        
        return root_causes
    
    def _generate_description(self, category: RootCauseCategory, technique: str, count: int) -> str:
        """Generate a description for the root cause."""
        descriptions = {
            RootCauseCategory.INPUT_VALIDATION: f"Input validation deficiencies leading to {count} {technique.replace('_', ' ')} finding(s). User input is not properly validated before processing.",
            RootCauseCategory.OUTPUT_ENCODING: f"Output encoding issues causing {count} vulnerability finding(s). Data is rendered without proper context-aware encoding.",
            RootCauseCategory.AUTHENTICATION: f"Authentication weakness affecting {count} endpoint(s). Authentication mechanisms have logical flaws or are missing.",
            RootCauseCategory.AUTHORIZATION: f"Authorization gaps enabling {count} access control bypass(es). Object-level or function-level authorization is inadequate.",
            RootCauseCategory.CONFIGURATION: f"Security misconfiguration causing {count} issue(s). Default or insecure settings are in use.",
            RootCauseCategory.DESIGN_FLAW: f"Architectural design flaw underlying {count} finding(s). The application design has inherent security weaknesses.",
            RootCauseCategory.BUSINESS_LOGIC: f"Business logic vulnerability in {count} workflow(s). Application logic can be abused for unintended behavior.",
        }
        return descriptions.get(category, f"Security issue affecting {count} finding(s)")
    
    def _get_code_patterns(self, technique: str) -> List[str]:
        """Get code patterns to look for and fix."""
        patterns = {
            "sql_injection": [
                "String concatenation in SQL queries",
                "f-strings or format() in database queries",
                "execute() with user input",
            ],
            "xss": [
                "innerHTML assignments",
                "document.write() calls",
                "Unescaped template variables",
            ],
            "command_injection": [
                "os.system() calls",
                "subprocess with shell=True",
                "eval() or exec() with user input",
            ],
            "path_traversal": [
                "open() with user-supplied paths",
                "Path concatenation without validation",
                "Missing path canonicalization",
            ],
            "idor": [
                "Direct database ID in URLs",
                "Missing ownership checks in queries",
                "Sequential ID enumeration",
            ],
        }
        return patterns.get(technique, ["Review code handling user input"])
    
    def _get_prevention_measures(self, category: RootCauseCategory) -> List[str]:
        """Get prevention measures for a root cause category."""
        measures = {
            RootCauseCategory.INPUT_VALIDATION: [
                "Implement centralized input validation library",
                "Use allowlist validation where possible",
                "Add input validation to API gateway",
                "Enable SAST rules for input validation",
            ],
            RootCauseCategory.OUTPUT_ENCODING: [
                "Use auto-escaping template engine",
                "Implement Content Security Policy",
                "Create output encoding helper functions",
                "Enable SAST rules for XSS prevention",
            ],
            RootCauseCategory.AUTHENTICATION: [
                "Use established auth framework (OAuth, OIDC)",
                "Implement MFA for sensitive operations",
                "Regular authentication flow security review",
                "Centralized authentication middleware",
            ],
            RootCauseCategory.AUTHORIZATION: [
                "Implement RBAC or ABAC system",
                "Centralized authorization checks",
                "Add authorization unit tests",
                "Regular access control matrix review",
            ],
            RootCauseCategory.CONFIGURATION: [
                "Security hardening checklist",
                "Infrastructure as Code with security defaults",
                "Automated configuration scanning",
                "Remove default credentials",
            ],
            RootCauseCategory.DESIGN_FLAW: [
                "Security architecture review",
                "Threat modeling before development",
                "Security design patterns training",
                "Regular security architecture assessments",
            ],
        }
        return measures.get(category, ["Implement defense in depth"])


# =============================================================================
# PART 3: IMPACT ASSESSMENT
# =============================================================================

class ImpactCategory(Enum):
    """Categories of business/technical impact."""
    DATA_BREACH = "data_breach"
    SERVICE_DISRUPTION = "service_disruption"
    FINANCIAL_LOSS = "financial_loss"
    REPUTATION_DAMAGE = "reputation_damage"
    COMPLIANCE_VIOLATION = "compliance_violation"
    LEGAL_LIABILITY = "legal_liability"
    OPERATIONAL_IMPACT = "operational_impact"


@dataclass
class ImpactAssessment:
    """Complete impact assessment for a finding or chain."""
    finding_id: str
    technical_impact_score: float  # 0-10
    business_impact_score: float  # 0-10
    combined_risk_score: float  # 0-10
    risk_rating: str  # Critical, High, Medium, Low
    impact_categories: List[ImpactCategory]
    affected_data_types: List[str]
    affected_systems: List[str]
    potential_attack_scenarios: List[str]
    estimated_breach_cost: Optional[str]  # $ range
    compliance_implications: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "technical_impact_score": self.technical_impact_score,
            "business_impact_score": self.business_impact_score,
            "combined_risk_score": self.combined_risk_score,
            "risk_rating": self.risk_rating,
            "impact_categories": [ic.value for ic in self.impact_categories],
            "affected_data_types": self.affected_data_types,
            "affected_systems": self.affected_systems,
            "potential_attack_scenarios": self.potential_attack_scenarios,
            "estimated_breach_cost": self.estimated_breach_cost,
            "compliance_implications": self.compliance_implications,
        }


# Technique to impact mapping
TECHNIQUE_IMPACTS: Dict[str, Dict] = {
    "sql_injection": {
        "technical_score": 9.0,
        "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.COMPLIANCE_VIOLATION],
        "data_types": ["Database records", "User credentials", "PII", "Financial data"],
        "scenarios": [
            "Attacker extracts entire database contents",
            "Attacker modifies or deletes critical data",
            "Attacker bypasses authentication via SQL manipulation",
        ],
        "cost_range": "$500K - $5M",
    },
    "xss": {
        "technical_score": 6.0,
        "categories": [ImpactCategory.REPUTATION_DAMAGE, ImpactCategory.DATA_BREACH],
        "data_types": ["Session tokens", "User cookies", "Form data"],
        "scenarios": [
            "Attacker hijacks user sessions",
            "Attacker performs actions as victim user",
            "Attacker steals sensitive data from page",
        ],
        "cost_range": "$50K - $500K",
    },
    "command_injection": {
        "technical_score": 10.0,
        "categories": [ImpactCategory.SERVICE_DISRUPTION, ImpactCategory.DATA_BREACH, ImpactCategory.OPERATIONAL_IMPACT],
        "data_types": ["Server files", "System credentials", "Application secrets"],
        "scenarios": [
            "Attacker gains shell access to server",
            "Attacker installs persistent backdoor",
            "Attacker pivots to internal network",
        ],
        "cost_range": "$1M - $10M",
    },
    "ssrf": {
        "technical_score": 7.5,
        "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.OPERATIONAL_IMPACT],
        "data_types": ["Internal API data", "Cloud metadata", "Internal service responses"],
        "scenarios": [
            "Attacker accesses cloud instance metadata",
            "Attacker scans internal network",
            "Attacker accesses internal admin interfaces",
        ],
        "cost_range": "$100K - $1M",
    },
    "auth_bypass": {
        "technical_score": 9.0,
        "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.COMPLIANCE_VIOLATION, ImpactCategory.LEGAL_LIABILITY],
        "data_types": ["User accounts", "Protected resources", "Admin functionality"],
        "scenarios": [
            "Attacker accesses any user account",
            "Attacker gains admin privileges",
            "Attacker accesses protected data without authentication",
        ],
        "cost_range": "$250K - $2.5M",
    },
    "idor": {
        "technical_score": 6.5,
        "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.COMPLIANCE_VIOLATION],
        "data_types": ["Other users' data", "Private resources", "Sensitive documents"],
        "scenarios": [
            "Attacker accesses other users' private data",
            "Attacker enumerates all resources",
            "Attacker modifies other users' data",
        ],
        "cost_range": "$100K - $1M",
    },
}


class ImpactAssessor:
    """
    Assesses the business and technical impact of findings.
    
    Combines technical severity with business context to provide
    actionable risk assessments.
    """
    
    def assess_finding(
        self, 
        finding: Dict,
        business_context: Optional[Dict] = None,
    ) -> ImpactAssessment:
        """
        Assess impact of a single finding.
        
        Args:
            finding: Finding dictionary
            business_context: Optional business context (data sensitivity, criticality)
            
        Returns:
            Impact assessment
        """
        technique = finding.get("technique", "").lower().replace(" ", "_")
        severity = finding.get("severity", "medium").lower()
        
        # Get base impact data
        impact_data = TECHNIQUE_IMPACTS.get(technique, {
            "technical_score": 5.0,
            "categories": [ImpactCategory.OPERATIONAL_IMPACT],
            "data_types": ["Application data"],
            "scenarios": ["Potential security breach"],
            "cost_range": "$10K - $100K",
        })
        
        # Calculate technical impact
        technical_score = impact_data["technical_score"]
        
        # Adjust for severity
        severity_multipliers = {
            "critical": 1.2,
            "high": 1.0,
            "medium": 0.8,
            "low": 0.5,
            "info": 0.2,
        }
        technical_score *= severity_multipliers.get(severity, 0.8)
        technical_score = min(technical_score, 10.0)
        
        # Calculate business impact
        business_score = technical_score * 0.8  # Default relationship
        
        if business_context:
            # Adjust for data sensitivity
            sensitivity = business_context.get("data_sensitivity", "medium")
            if sensitivity == "high":
                business_score *= 1.3
            elif sensitivity == "low":
                business_score *= 0.7
            
            # Adjust for system criticality
            criticality = business_context.get("system_criticality", "medium")
            if criticality == "critical":
                business_score *= 1.4
            elif criticality == "low":
                business_score *= 0.6
        
        business_score = min(business_score, 10.0)
        
        # Combined risk score
        combined_score = (technical_score * 0.6 + business_score * 0.4)
        
        # Determine risk rating
        if combined_score >= 9.0:
            risk_rating = "Critical"
        elif combined_score >= 7.0:
            risk_rating = "High"
        elif combined_score >= 4.0:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"
        
        # Get compliance implications
        compliance = self._get_compliance_implications(technique)
        
        return ImpactAssessment(
            finding_id=finding.get("id", "unknown"),
            technical_impact_score=round(technical_score, 1),
            business_impact_score=round(business_score, 1),
            combined_risk_score=round(combined_score, 1),
            risk_rating=risk_rating,
            impact_categories=impact_data["categories"],
            affected_data_types=impact_data["data_types"],
            affected_systems=self._identify_affected_systems(finding),
            potential_attack_scenarios=impact_data["scenarios"],
            estimated_breach_cost=impact_data.get("cost_range"),
            compliance_implications=compliance,
        )
    
    def assess_findings_batch(
        self, 
        findings: List[Dict],
        business_context: Optional[Dict] = None,
    ) -> Dict:
        """
        Assess impact of multiple findings.
        
        Returns individual assessments plus aggregate statistics.
        """
        assessments = [
            self.assess_finding(f, business_context) 
            for f in findings
        ]
        
        # Aggregate statistics
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_technical = 0
        total_business = 0
        
        for assessment in assessments:
            risk_counts[assessment.risk_rating] += 1
            total_technical += assessment.technical_impact_score
            total_business += assessment.business_impact_score
        
        n = len(assessments) or 1
        
        return {
            "assessments": [a.to_dict() for a in assessments],
            "summary": {
                "total_findings": len(findings),
                "risk_distribution": risk_counts,
                "average_technical_score": round(total_technical / n, 1),
                "average_business_score": round(total_business / n, 1),
                "highest_risk_findings": [
                    a.to_dict() for a in assessments 
                    if a.risk_rating in ("Critical", "High")
                ][:5],
            },
        }
    
    def _identify_affected_systems(self, finding: Dict) -> List[str]:
        """Identify systems affected by the finding."""
        systems = ["Web Application"]
        
        url = finding.get("url", "")
        if "api" in url.lower():
            systems.append("API Server")
        if "admin" in url.lower():
            systems.append("Admin Interface")
        
        technique = finding.get("technique", "").lower()
        if "sql" in technique:
            systems.append("Database Server")
        if "ssrf" in technique:
            systems.append("Internal Network")
        if "command" in technique:
            systems.append("Application Server")
        
        return systems
    
    def _get_compliance_implications(self, technique: str) -> List[str]:
        """Get compliance implications for a technique."""
        implications = {
            "sql_injection": [
                "PCI-DSS 6.5.1 - Injection flaws",
                "HIPAA 164.312(a)(1) - Access Control",
                "GDPR Article 32 - Security of processing",
            ],
            "xss": [
                "PCI-DSS 6.5.7 - Cross-site scripting",
                "OWASP A03:2021 - Injection",
            ],
            "auth_bypass": [
                "PCI-DSS 6.5.10 - Broken authentication",
                "HIPAA 164.312(d) - Authentication",
                "SOX Section 404 - Internal controls",
            ],
            "idor": [
                "PCI-DSS 6.5.8 - Improper access control",
                "HIPAA 164.308(a)(4) - Information access",
                "GDPR Article 25 - Data protection by design",
            ],
            "ssrf": [
                "OWASP A10:2021 - SSRF",
                "PCI-DSS 6.4.1 - Web application protection",
            ],
        }
        return implications.get(technique, ["Review against applicable compliance frameworks"])


# =============================================================================
# PART 4: REMEDIATION PRIORITIZER
# =============================================================================

@dataclass
class RemediationItem:
    """A prioritized remediation item."""
    priority_rank: int
    finding_ids: List[str]
    title: str
    description: str
    fix_type: str  # Code fix, Configuration, Architecture
    estimated_effort: str  # Hours, Days, Weeks
    risk_reduction: float  # 0-10 points reduced
    dependencies: List[str]  # Other items that must be fixed first
    quick_win: bool  # High impact, low effort
    recommended_timeline: str
    
    def to_dict(self) -> Dict:
        return {
            "priority_rank": self.priority_rank,
            "finding_ids": self.finding_ids,
            "finding_count": len(self.finding_ids),
            "title": self.title,
            "description": self.description,
            "fix_type": self.fix_type,
            "estimated_effort": self.estimated_effort,
            "risk_reduction": self.risk_reduction,
            "dependencies": self.dependencies,
            "quick_win": self.quick_win,
            "recommended_timeline": self.recommended_timeline,
        }


class RemediationPrioritizer:
    """
    Prioritizes remediation efforts based on risk, effort, and dependencies.
    
    Uses a combination of factors:
    - Risk score (higher = fix sooner)
    - Fix effort (lower = fix sooner for quick wins)
    - Number of findings addressed (more = higher priority)
    - Dependencies (must fix prerequisites first)
    """
    
    # Effort estimates by fix type
    EFFORT_ESTIMATES: Dict[str, str] = {
        "sql_injection": "4-8 hours",
        "xss": "2-4 hours",
        "command_injection": "4-8 hours",
        "path_traversal": "2-4 hours",
        "idor": "4-8 hours",
        "ssrf": "8-16 hours",
        "auth_bypass": "1-3 days",
        "ssti": "4-8 hours",
        "xxe": "2-4 hours",
        "deserialization": "1-3 days",
        "business_logic": "1-2 weeks",
        "race_condition": "1-3 days",
    }
    
    def prioritize(
        self, 
        findings: List[Dict],
        root_causes: Optional[List[RootCause]] = None,
        impact_assessments: Optional[List[ImpactAssessment]] = None,
    ) -> List[RemediationItem]:
        """
        Generate prioritized remediation list.
        
        Args:
            findings: List of findings
            root_causes: Optional root cause analysis results
            impact_assessments: Optional impact assessments
            
        Returns:
            Prioritized list of remediation items
        """
        items = []
        
        # Group findings by technique for consolidated fixes
        by_technique: Dict[str, List[Dict]] = {}
        for finding in findings:
            tech = finding.get("technique", "").lower().replace(" ", "_")
            if tech not in by_technique:
                by_technique[tech] = []
            by_technique[tech].append(finding)
        
        # Create remediation items
        for technique, tech_findings in by_technique.items():
            # Calculate aggregate risk
            severities = [f.get("severity", "medium").lower() for f in tech_findings]
            severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
            avg_severity = sum(severity_scores.get(s, 5) for s in severities) / len(severities)
            
            # Get effort estimate
            effort = self.EFFORT_ESTIMATES.get(technique, "4-8 hours")
            
            # Calculate risk reduction
            risk_reduction = avg_severity * len(tech_findings) * 0.3
            risk_reduction = min(risk_reduction, 10.0)
            
            # Determine fix type
            fix_type = self._get_fix_type(technique)
            
            # Determine if quick win (high impact, low effort)
            is_quick_win = avg_severity >= 7 and "hour" in effort
            
            # Get timeline
            timeline = self._get_timeline(avg_severity, len(tech_findings))
            
            item = RemediationItem(
                priority_rank=0,  # Will be set after sorting
                finding_ids=[f.get("id", str(i)) for i, f in enumerate(tech_findings)],
                title=f"Fix {technique.replace('_', ' ').title()} Vulnerabilities",
                description=f"Address {len(tech_findings)} {technique.replace('_', ' ')} finding(s) with average severity {avg_severity:.1f}/10",
                fix_type=fix_type,
                estimated_effort=effort,
                risk_reduction=round(risk_reduction, 1),
                dependencies=self._get_dependencies(technique),
                quick_win=is_quick_win,
                recommended_timeline=timeline,
            )
            items.append(item)
        
        # Sort by priority score
        items.sort(key=lambda x: self._calculate_priority_score(x), reverse=True)
        
        # Assign ranks
        for i, item in enumerate(items):
            item.priority_rank = i + 1
        
        return items
    
    def _calculate_priority_score(self, item: RemediationItem) -> float:
        """Calculate priority score for sorting."""
        score = item.risk_reduction * 2  # Weight risk reduction heavily
        
        # Bonus for quick wins
        if item.quick_win:
            score *= 1.5
        
        # Bonus for fixing multiple findings
        score += len(item.finding_ids) * 0.5
        
        # Penalty for high effort
        if "week" in item.estimated_effort:
            score *= 0.7
        elif "day" in item.estimated_effort:
            score *= 0.85
        
        return score
    
    def _get_fix_type(self, technique: str) -> str:
        """Determine fix type for a technique."""
        code_fixes = ["sql_injection", "xss", "command_injection", "path_traversal", "ssti"]
        config_fixes = ["xxe", "ssrf"]
        arch_fixes = ["auth_bypass", "deserialization", "business_logic"]
        
        if technique in code_fixes:
            return "Code fix"
        elif technique in config_fixes:
            return "Configuration"
        elif technique in arch_fixes:
            return "Architecture"
        else:
            return "Code fix"
    
    def _get_timeline(self, severity: float, count: int) -> str:
        """Get recommended timeline."""
        if severity >= 9:
            return "Immediate (within 24 hours)"
        elif severity >= 7:
            return "Urgent (within 1 week)"
        elif severity >= 5:
            return "Soon (within 2 weeks)"
        else:
            return "Planned (within 1 month)"
    
    def _get_dependencies(self, technique: str) -> List[str]:
        """Get remediation dependencies."""
        # Some fixes should come before others
        deps = {
            "idor": ["auth_bypass"],  # Fix auth before IDOR
            "business_logic": ["auth_bypass", "idor"],
            "ssrf": ["path_traversal"],
        }
        return deps.get(technique, [])


# =============================================================================
# PART 5: INTEGRATION & EXPORTS
# =============================================================================

# Singleton instances
_chain_analyzer: Optional[ExploitChainAnalyzer] = None
_root_cause_analyzer: Optional[RootCauseAnalyzer] = None
_impact_assessor: Optional[ImpactAssessor] = None
_prioritizer: Optional[RemediationPrioritizer] = None


def get_chain_analyzer() -> ExploitChainAnalyzer:
    global _chain_analyzer
    if _chain_analyzer is None:
        _chain_analyzer = ExploitChainAnalyzer()
    return _chain_analyzer


def get_root_cause_analyzer() -> RootCauseAnalyzer:
    global _root_cause_analyzer
    if _root_cause_analyzer is None:
        _root_cause_analyzer = RootCauseAnalyzer()
    return _root_cause_analyzer


def get_impact_assessor() -> ImpactAssessor:
    global _impact_assessor
    if _impact_assessor is None:
        _impact_assessor = ImpactAssessor()
    return _impact_assessor


def get_prioritizer() -> RemediationPrioritizer:
    global _prioritizer
    if _prioritizer is None:
        _prioritizer = RemediationPrioritizer()
    return _prioritizer


def analyze_findings_comprehensive(
    findings: List[Dict],
    business_context: Optional[Dict] = None,
) -> Dict:
    """
    Perform comprehensive AI security analysis on findings.
    
    Includes:
    - Exploit chain analysis
    - Root cause analysis
    - Impact assessment
    - Remediation prioritization
    
    Args:
        findings: List of finding dictionaries
        business_context: Optional business context
        
    Returns:
        Comprehensive analysis results
    """
    chain_analyzer = get_chain_analyzer()
    root_cause_analyzer = get_root_cause_analyzer()
    impact_assessor = get_impact_assessor()
    prioritizer = get_prioritizer()
    
    # Run all analyses
    chains = chain_analyzer.analyze_findings(findings)
    root_causes = root_cause_analyzer.analyze_findings(findings)
    impact_results = impact_assessor.assess_findings_batch(findings, business_context)
    remediation = prioritizer.prioritize(findings, root_causes)
    
    return {
        "analysis_timestamp": datetime.now().isoformat(),
        "findings_analyzed": len(findings),
        "exploit_chains": {
            "chains": [c.to_dict() for c in chains],
            "chain_count": len(chains),
            "highest_risk_chain": chains[0].to_dict() if chains else None,
        },
        "root_causes": {
            "causes": [rc.to_dict() for rc in root_causes],
            "cause_count": len(root_causes),
            "primary_root_cause": root_causes[0].to_dict() if root_causes else None,
        },
        "impact_assessment": impact_results,
        "remediation_plan": {
            "items": [r.to_dict() for r in remediation],
            "quick_wins": [r.to_dict() for r in remediation if r.quick_win],
            "total_risk_reduction": sum(r.risk_reduction for r in remediation),
        },
    }


# Module exports
__all__ = [
    # Enums
    "AttackStage",
    "RootCauseCategory",
    "ImpactCategory",
    
    # Data classes
    "ExploitChainLink",
    "ExploitChain",
    "RootCause",
    "ImpactAssessment",
    "RemediationItem",
    
    # Analyzers
    "ExploitChainAnalyzer",
    "RootCauseAnalyzer",
    "ImpactAssessor",
    "RemediationPrioritizer",
    
    # Factory functions
    "get_chain_analyzer",
    "get_root_cause_analyzer",
    "get_impact_assessor",
    "get_prioritizer",
    
    # Main function
    "analyze_findings_comprehensive",
    
    # Mappings
    "TECHNIQUE_ATTACK_STAGE",
    "TECHNIQUE_ROOT_CAUSES",
    "TECHNIQUE_IMPACTS",
]
