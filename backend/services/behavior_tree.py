"""
Behavior Tree - Guided Malware Analysis

Implements a decision tree for systematic malware analysis:
1. Initial triage (static analysis)
2. Execution strategy selection
3. Dynamic analysis with adaptive hooks
4. Behavioral classification
5. Advanced techniques (unpacking, anti-evasion)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class NodeType(Enum):
    """Behavior tree node type."""
    SEQUENCE = "sequence"  # Execute children in order
    SELECTOR = "selector"  # Try children until one succeeds
    CONDITION = "condition"  # Check condition
    ACTION = "action"  # Perform action
    PARALLEL = "parallel"  # Execute children in parallel


class NodeStatus(Enum):
    """Node execution status."""
    SUCCESS = "success"
    FAILURE = "failure"
    RUNNING = "running"
    PENDING = "pending"


class AnalysisStrategy(Enum):
    """Analysis strategy based on triage."""
    QUICK = "quick"  # Basic analysis (5 min)
    STANDARD = "standard"  # Standard analysis (15 min)
    DEEP = "deep"  # Deep analysis (30 min)
    EXHAUSTIVE = "exhaustive"  # Exhaustive analysis (60 min)


class ThreatLevel(Enum):
    """Threat level assessment."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    HIGHLY_MALICIOUS = "highly_malicious"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AnalysisContext:
    """Shared context for behavior tree."""
    # Binary information
    binary_hash: str
    binary_name: str
    platform: str
    architecture: str
    file_size: int

    # Static analysis results
    is_packed: bool = False
    packer_type: Optional[str] = None
    entropy: float = 0.0
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    sections: List[Dict] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)

    # Dynamic analysis results
    executed: bool = False
    execution_time: float = 0.0
    api_calls: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    registry_modified: List[str] = field(default_factory=list)
    processes_created: List[str] = field(default_factory=list)

    # Classification
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    malware_family: Optional[str] = None
    capabilities: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)

    # Analysis metadata
    strategy: AnalysisStrategy = AnalysisStrategy.STANDARD
    needs_unpacking: bool = False
    needs_anti_evasion: bool = False
    needs_deep_inspection: bool = False

    # Confidence scores
    confidence_score: float = 0.0
    threat_score: int = 0


@dataclass
class BehaviorNode:
    """Behavior tree node."""
    name: str
    node_type: NodeType
    status: NodeStatus = NodeStatus.PENDING
    children: List['BehaviorNode'] = field(default_factory=list)
    condition_func: Optional[Any] = None  # Callable[[AnalysisContext], bool]
    action_func: Optional[Any] = None  # Callable[[AnalysisContext], NodeStatus]
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Behavior Tree Builder
# ============================================================================

class BehaviorTree:
    """
    Behavior tree for guided malware analysis.

    Tree structure:
    Root (Sequence)
    ├─ Static Triage (Sequence)
    │  ├─ Calculate Entropy
    │  ├─ Detect Packing
    │  ├─ Extract Imports
    │  └─ Determine Strategy
    ├─ Dynamic Analysis (Selector)
    │  ├─ Quick Analysis (if not suspicious)
    │  ├─ Standard Analysis (default)
    │  └─ Deep Analysis (if highly suspicious)
    ├─ Advanced Techniques (Selector)
    │  ├─ Unpacking (if packed)
    │  ├─ Anti-Evasion (if evasive)
    │  └─ Deep Inspection (if needed)
    └─ Classification (Sequence)
       ├─ Behavioral Analysis
       ├─ MITRE ATT&CK Mapping
       └─ Threat Scoring
    """

    def __init__(self):
        self.root = self._build_tree()
        self.context: Optional[AnalysisContext] = None

    def _build_tree(self) -> BehaviorNode:
        """Build the complete behavior tree."""
        root = BehaviorNode(
            name="Root",
            node_type=NodeType.SEQUENCE,
            children=[
                self._build_static_triage(),
                self._build_dynamic_analysis(),
                self._build_advanced_techniques(),
                self._build_classification()
            ]
        )
        return root

    def _build_static_triage(self) -> BehaviorNode:
        """Build static triage subtree."""
        return BehaviorNode(
            name="Static Triage",
            node_type=NodeType.SEQUENCE,
            children=[
                BehaviorNode(
                    name="Calculate Entropy",
                    node_type=NodeType.ACTION,
                    action_func=self._calculate_entropy
                ),
                BehaviorNode(
                    name="Detect Packing",
                    node_type=NodeType.ACTION,
                    action_func=self._detect_packing
                ),
                BehaviorNode(
                    name="Extract Imports",
                    node_type=NodeType.ACTION,
                    action_func=self._extract_imports
                ),
                BehaviorNode(
                    name="Analyze Strings",
                    node_type=NodeType.ACTION,
                    action_func=self._analyze_strings
                ),
                BehaviorNode(
                    name="Determine Strategy",
                    node_type=NodeType.ACTION,
                    action_func=self._determine_strategy
                )
            ]
        )

    def _build_dynamic_analysis(self) -> BehaviorNode:
        """Build dynamic analysis subtree."""
        return BehaviorNode(
            name="Dynamic Analysis",
            node_type=NodeType.SELECTOR,
            children=[
                BehaviorNode(
                    name="Quick Analysis",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Check Low Threat",
                            node_type=NodeType.CONDITION,
                            condition_func=lambda ctx: ctx.threat_level == ThreatLevel.BENIGN
                        ),
                        BehaviorNode(
                            name="Execute Quick",
                            node_type=NodeType.ACTION,
                            action_func=self._execute_quick
                        )
                    ]
                ),
                BehaviorNode(
                    name="Standard Analysis",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Check Standard Threat",
                            node_type=NodeType.CONDITION,
                            condition_func=lambda ctx: ctx.threat_level in [ThreatLevel.SUSPICIOUS, ThreatLevel.BENIGN]
                        ),
                        BehaviorNode(
                            name="Execute Standard",
                            node_type=NodeType.ACTION,
                            action_func=self._execute_standard
                        )
                    ]
                ),
                BehaviorNode(
                    name="Deep Analysis",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Execute Deep",
                            node_type=NodeType.ACTION,
                            action_func=self._execute_deep
                        )
                    ]
                )
            ]
        )

    def _build_advanced_techniques(self) -> BehaviorNode:
        """Build advanced techniques subtree."""
        return BehaviorNode(
            name="Advanced Techniques",
            node_type=NodeType.SELECTOR,
            children=[
                BehaviorNode(
                    name="Unpacking",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Check Packed",
                            node_type=NodeType.CONDITION,
                            condition_func=lambda ctx: ctx.needs_unpacking
                        ),
                        BehaviorNode(
                            name="Unpack Binary",
                            node_type=NodeType.ACTION,
                            action_func=self._unpack_binary
                        )
                    ]
                ),
                BehaviorNode(
                    name="Anti-Evasion",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Check Evasive",
                            node_type=NodeType.CONDITION,
                            condition_func=lambda ctx: ctx.needs_anti_evasion
                        ),
                        BehaviorNode(
                            name="Apply Anti-Evasion",
                            node_type=NodeType.ACTION,
                            action_func=self._apply_anti_evasion
                        )
                    ]
                ),
                BehaviorNode(
                    name="Deep Inspection",
                    node_type=NodeType.SEQUENCE,
                    children=[
                        BehaviorNode(
                            name="Check Deep Needed",
                            node_type=NodeType.CONDITION,
                            condition_func=lambda ctx: ctx.needs_deep_inspection
                        ),
                        BehaviorNode(
                            name="Perform Deep Inspection",
                            node_type=NodeType.ACTION,
                            action_func=self._deep_inspection
                        )
                    ]
                )
            ]
        )

    def _build_classification(self) -> BehaviorNode:
        """Build classification subtree."""
        return BehaviorNode(
            name="Classification",
            node_type=NodeType.SEQUENCE,
            children=[
                BehaviorNode(
                    name="Behavioral Analysis",
                    node_type=NodeType.ACTION,
                    action_func=self._behavioral_analysis
                ),
                BehaviorNode(
                    name="MITRE ATT&CK Mapping",
                    node_type=NodeType.ACTION,
                    action_func=self._mitre_mapping
                ),
                BehaviorNode(
                    name="Threat Scoring",
                    node_type=NodeType.ACTION,
                    action_func=self._threat_scoring
                )
            ]
        )

    # ========================================================================
    # Action Functions
    # ========================================================================

    def _calculate_entropy(self, ctx: AnalysisContext) -> NodeStatus:
        """Calculate file entropy to detect packing/encryption."""
        logger.info(f"Calculating entropy for {ctx.binary_name}")
        # Placeholder - would calculate actual entropy
        ctx.entropy = 7.2  # Mock value (high entropy suggests packing)

        if ctx.entropy > 7.0:
            ctx.threat_level = ThreatLevel.SUSPICIOUS
            ctx.needs_unpacking = True
            logger.warning(f"High entropy detected: {ctx.entropy}")

        return NodeStatus.SUCCESS

    def _detect_packing(self, ctx: AnalysisContext) -> NodeStatus:
        """Detect if binary is packed."""
        logger.info("Detecting packing")

        # Check entropy threshold
        if ctx.entropy > 7.0:
            ctx.is_packed = True
            ctx.needs_unpacking = True

            # Try to identify packer
            packer_signatures = {
                "UPX": ["UPX0", "UPX1"],
                "VMProtect": [".vmp0", ".vmp1"],
                "Themida": [".themida"],
                "ASPack": [".aspack"]
            }

            section_names = [s.get("name", "") for s in ctx.sections]
            for packer, signatures in packer_signatures.items():
                if any(sig in "".join(section_names) for sig in signatures):
                    ctx.packer_type = packer
                    logger.info(f"Detected packer: {packer}")
                    break

        return NodeStatus.SUCCESS

    def _extract_imports(self, ctx: AnalysisContext) -> NodeStatus:
        """Extract and analyze imports."""
        logger.info("Extracting imports")

        # Placeholder - imports would be extracted by binary parser
        # Check for suspicious imports
        suspicious_apis = {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",  # Process injection
            "RegOpenKeyEx", "RegSetValueEx",  # Registry manipulation
            "InternetOpenUrl", "HttpSendRequest",  # Network activity
            "CryptEncrypt", "CryptDecrypt",  # Encryption
            "CreateMutex", "CreateEvent"  # Synchronization
        }

        suspicious_count = sum(1 for api in ctx.imports if api in suspicious_apis)
        if suspicious_count > 5:
            ctx.threat_level = ThreatLevel.SUSPICIOUS
            logger.warning(f"Found {suspicious_count} suspicious imports")

        return NodeStatus.SUCCESS

    def _analyze_strings(self, ctx: AnalysisContext) -> NodeStatus:
        """Analyze strings for indicators."""
        logger.info("Analyzing strings")

        # Check for suspicious strings
        suspicious_patterns = [
            "cmd.exe", "powershell", "reg add", "schtasks",  # Commands
            "http://", "https://", "ftp://",  # URLs
            ".dll", ".exe", ".bat", ".ps1",  # File extensions
            "password", "keylog", "backdoor", "exploit"  # Keywords
        ]

        suspicious_strings = [s for s in ctx.strings if any(p in s.lower() for p in suspicious_patterns)]
        if len(suspicious_strings) > 10:
            ctx.threat_level = ThreatLevel.MALICIOUS
            logger.warning(f"Found {len(suspicious_strings)} suspicious strings")

        return NodeStatus.SUCCESS

    def _determine_strategy(self, ctx: AnalysisContext) -> NodeStatus:
        """Determine analysis strategy based on triage."""
        logger.info("Determining analysis strategy")

        if ctx.threat_level == ThreatLevel.BENIGN and not ctx.is_packed:
            ctx.strategy = AnalysisStrategy.QUICK
        elif ctx.threat_level == ThreatLevel.SUSPICIOUS:
            ctx.strategy = AnalysisStrategy.STANDARD
        elif ctx.threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.HIGHLY_MALICIOUS]:
            ctx.strategy = AnalysisStrategy.DEEP
        else:
            ctx.strategy = AnalysisStrategy.STANDARD

        logger.info(f"Selected strategy: {ctx.strategy.value}")
        return NodeStatus.SUCCESS

    def _execute_quick(self, ctx: AnalysisContext) -> NodeStatus:
        """Execute quick analysis (5 minutes)."""
        logger.info("Executing quick analysis")
        ctx.executed = True
        ctx.execution_time = 300  # 5 minutes
        # Mock execution - would trigger actual Frida analysis
        return NodeStatus.SUCCESS

    def _execute_standard(self, ctx: AnalysisContext) -> NodeStatus:
        """Execute standard analysis (15 minutes)."""
        logger.info("Executing standard analysis")
        ctx.executed = True
        ctx.execution_time = 900  # 15 minutes
        return NodeStatus.SUCCESS

    def _execute_deep(self, ctx: AnalysisContext) -> NodeStatus:
        """Execute deep analysis (30 minutes)."""
        logger.info("Executing deep analysis")
        ctx.executed = True
        ctx.execution_time = 1800  # 30 minutes
        ctx.needs_deep_inspection = True
        return NodeStatus.SUCCESS

    def _unpack_binary(self, ctx: AnalysisContext) -> NodeStatus:
        """Unpack packed binary."""
        logger.info(f"Unpacking binary (packer: {ctx.packer_type})")

        # Unpacking strategies
        if ctx.packer_type == "UPX":
            logger.info("Using UPX unpacker")
            # Would execute: upx -d binary
        elif ctx.packer_type:
            logger.info(f"Using generic unpacker for {ctx.packer_type}")
            # Would use memory dumping after OEP detection

        return NodeStatus.SUCCESS

    def _apply_anti_evasion(self, ctx: AnalysisContext) -> NodeStatus:
        """Apply anti-evasion techniques."""
        logger.info("Applying anti-evasion techniques")

        # Would enable anti-debug, anti-VM bypasses
        ctx.capabilities.add("evasion_detected")

        return NodeStatus.SUCCESS

    def _deep_inspection(self, ctx: AnalysisContext) -> NodeStatus:
        """Perform deep inspection."""
        logger.info("Performing deep inspection")

        # Enable all monitoring hooks
        # Enable code coverage with Stalker
        # Extended execution time

        return NodeStatus.SUCCESS

    def _behavioral_analysis(self, ctx: AnalysisContext) -> NodeStatus:
        """Analyze behavior patterns."""
        logger.info("Analyzing behavior patterns")

        # Analyze API calls for patterns
        if ctx.api_calls:
            # Check for persistence
            persistence_apis = ["RegSetValueEx", "CreateService", "CopyFile"]
            if any(api in str(ctx.api_calls) for api in persistence_apis):
                ctx.capabilities.add("persistence")

            # Check for process injection
            injection_apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
            if any(api in str(ctx.api_calls) for api in injection_apis):
                ctx.capabilities.add("process_injection")

            # Check for network communication
            if ctx.network_connections:
                ctx.capabilities.add("network_communication")

        return NodeStatus.SUCCESS

    def _mitre_mapping(self, ctx: AnalysisContext) -> NodeStatus:
        """Map behaviors to MITRE ATT&CK."""
        logger.info("Mapping to MITRE ATT&CK")

        # Map capabilities to techniques
        capability_to_technique = {
            "persistence": "T1547",  # Boot or Logon Autostart Execution
            "process_injection": "T1055",  # Process Injection
            "network_communication": "T1071",  # Application Layer Protocol
            "registry_modification": "T1112",  # Modify Registry
            "file_manipulation": "T1106",  # Native API
        }

        for capability in ctx.capabilities:
            if capability in capability_to_technique:
                ctx.mitre_techniques.add(capability_to_technique[capability])

        logger.info(f"Mapped {len(ctx.mitre_techniques)} MITRE techniques")
        return NodeStatus.SUCCESS

    def _threat_scoring(self, ctx: AnalysisContext) -> NodeStatus:
        """Calculate final threat score."""
        logger.info("Calculating threat score")

        score = 0

        # Entropy contribution (0-15 points)
        if ctx.entropy > 7.5:
            score += 15
        elif ctx.entropy > 7.0:
            score += 10
        elif ctx.entropy > 6.5:
            score += 5

        # Packing contribution (0-10 points)
        if ctx.is_packed:
            score += 10

        # Capabilities contribution (0-40 points)
        score += min(len(ctx.capabilities) * 8, 40)

        # MITRE techniques contribution (0-30 points)
        score += min(len(ctx.mitre_techniques) * 6, 30)

        # Network activity contribution (0-5 points)
        if ctx.network_connections:
            score += 5

        ctx.threat_score = min(score, 100)

        # Determine final threat level
        if ctx.threat_score > 75:
            ctx.threat_level = ThreatLevel.HIGHLY_MALICIOUS
            ctx.confidence_score = 0.9
        elif ctx.threat_score > 50:
            ctx.threat_level = ThreatLevel.MALICIOUS
            ctx.confidence_score = 0.75
        elif ctx.threat_score > 25:
            ctx.threat_level = ThreatLevel.SUSPICIOUS
            ctx.confidence_score = 0.6
        else:
            ctx.threat_level = ThreatLevel.BENIGN
            ctx.confidence_score = 0.5

        logger.info(f"Final threat score: {ctx.threat_score}/100 ({ctx.threat_level.value})")
        return NodeStatus.SUCCESS

    # ========================================================================
    # Tree Execution
    # ========================================================================

    def execute(self, context: AnalysisContext) -> AnalysisContext:
        """
        Execute the behavior tree.

        Args:
            context: Analysis context

        Returns:
            Updated context with analysis results
        """
        self.context = context
        logger.info(f"Starting behavior tree execution for {context.binary_name}")

        self._execute_node(self.root, context)

        logger.info(f"Behavior tree execution complete. Threat: {context.threat_level.value}")
        return context

    def _execute_node(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute a single node."""
        logger.debug(f"Executing node: {node.name} ({node.node_type.value})")

        if node.node_type == NodeType.SEQUENCE:
            return self._execute_sequence(node, context)
        elif node.node_type == NodeType.SELECTOR:
            return self._execute_selector(node, context)
        elif node.node_type == NodeType.CONDITION:
            return self._execute_condition(node, context)
        elif node.node_type == NodeType.ACTION:
            return self._execute_action(node, context)
        elif node.node_type == NodeType.PARALLEL:
            return self._execute_parallel(node, context)

        return NodeStatus.FAILURE

    def _execute_sequence(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute sequence node (all children must succeed)."""
        for child in node.children:
            status = self._execute_node(child, context)
            if status == NodeStatus.FAILURE:
                node.status = NodeStatus.FAILURE
                return NodeStatus.FAILURE

        node.status = NodeStatus.SUCCESS
        return NodeStatus.SUCCESS

    def _execute_selector(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute selector node (first successful child succeeds)."""
        for child in node.children:
            status = self._execute_node(child, context)
            if status == NodeStatus.SUCCESS:
                node.status = NodeStatus.SUCCESS
                return NodeStatus.SUCCESS

        node.status = NodeStatus.FAILURE
        return NodeStatus.FAILURE

    def _execute_condition(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute condition node."""
        if node.condition_func and node.condition_func(context):
            node.status = NodeStatus.SUCCESS
            return NodeStatus.SUCCESS

        node.status = NodeStatus.FAILURE
        return NodeStatus.FAILURE

    def _execute_action(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute action node."""
        if node.action_func:
            status = node.action_func(context)
            node.status = status
            return status

        node.status = NodeStatus.FAILURE
        return NodeStatus.FAILURE

    def _execute_parallel(self, node: BehaviorNode, context: AnalysisContext) -> NodeStatus:
        """Execute parallel node (all children execute simultaneously)."""
        # Simplified - would use asyncio for true parallelism
        statuses = [self._execute_node(child, context) for child in node.children]

        if all(s == NodeStatus.SUCCESS for s in statuses):
            node.status = NodeStatus.SUCCESS
            return NodeStatus.SUCCESS

        node.status = NodeStatus.FAILURE
        return NodeStatus.FAILURE

    def get_execution_path(self) -> List[str]:
        """Get the execution path through the tree."""
        path = []
        self._collect_execution_path(self.root, path)
        return path

    def _collect_execution_path(self, node: BehaviorNode, path: List[str]):
        """Recursively collect execution path."""
        if node.status == NodeStatus.SUCCESS:
            path.append(node.name)
            for child in node.children:
                self._collect_execution_path(child, path)
