from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector

from backend.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")  # 'user' or 'admin'
    status = Column(String, nullable=False, default="pending")  # 'pending', 'approved', 'suspended'
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Profile fields
    bio = Column(Text, nullable=True)
    avatar_url = Column(String, nullable=True)

    projects = relationship("Project", back_populates="owner")
    
    # Friendship relationships
    sent_friend_requests = relationship(
        "FriendRequest",
        foreign_keys="FriendRequest.sender_id",
        back_populates="sender",
        cascade="all, delete-orphan"
    )
    received_friend_requests = relationship(
        "FriendRequest",
        foreign_keys="FriendRequest.receiver_id",
        back_populates="receiver",
        cascade="all, delete-orphan"
    )
    
    # Friendships (user is user1)
    friendships_as_user1 = relationship(
        "Friendship",
        foreign_keys="Friendship.user1_id",
        back_populates="user1",
        cascade="all, delete-orphan"
    )
    friendships_as_user2 = relationship(
        "Friendship",
        foreign_keys="Friendship.user2_id",
        back_populates="user2",
        cascade="all, delete-orphan"
    )
    
    # Messages sent
    sent_messages = relationship(
        "Message",
        foreign_keys="Message.sender_id",
        back_populates="sender",
        cascade="all, delete-orphan"
    )
    
    # Conversation participants
    conversations = relationship(
        "ConversationParticipant",
        foreign_keys="ConversationParticipant.user_id",
        back_populates="user",
        cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    git_url = Column(String, nullable=True)
    upload_path = Column(String, nullable=True)
    is_shared = Column(String, nullable=False, default="false")  # 'true' or 'false' - whether project is shared
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    owner = relationship("User", back_populates="projects")
    code_chunks = relationship("CodeChunk", back_populates="project")
    dependencies = relationship("Dependency", back_populates="project")
    vulnerabilities = relationship("Vulnerability", back_populates="project")
    scan_runs = relationship("ScanRun", back_populates="project")
    findings = relationship("Finding", back_populates="project")
    reports = relationship("Report", back_populates="project")
    network_analysis_reports = relationship("NetworkAnalysisReport", back_populates="project")
    fuzzing_sessions = relationship("FuzzingSession", back_populates="project")
    reverse_engineering_reports = relationship("ReverseEngineeringReport", back_populates="project")
    project_notes = relationship("ProjectNote", back_populates="project", cascade="all, delete-orphan")
    collaborators = relationship("ProjectCollaborator", back_populates="project", cascade="all, delete-orphan")


class ProjectCollaborator(Base):
    """Tracks users who have access to shared projects."""
    __tablename__ = "project_collaborators"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, nullable=False, default="editor")  # 'viewer', 'editor', 'admin'
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    added_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    project = relationship("Project", back_populates="collaborators")
    user = relationship("User", foreign_keys=[user_id], backref="project_collaborations")
    inviter = relationship("User", foreign_keys=[added_by])

    __table_args__ = (
        UniqueConstraint('project_id', 'user_id', name='uq_project_collaborator'),
    )


class CodeChunk(Base):
    __tablename__ = "code_chunks"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    file_path = Column(String, nullable=False)
    language = Column(String, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    code = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    embedding = Column(Vector(768), nullable=True)  # text-embedding-004 produces 768-dim vectors

    project = relationship("Project", back_populates="code_chunks")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    ecosystem = Column(String, nullable=True)
    manifest_path = Column(String, nullable=True)

    project = relationship("Project", back_populates="dependencies")
    vulnerabilities = relationship("Vulnerability", back_populates="dependency")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    dependency_id = Column(Integer, ForeignKey("dependencies.id"), nullable=True)
    source = Column(String, nullable=False)
    external_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)

    project = relationship("Project", back_populates="vulnerabilities")
    dependency = relationship("Dependency", back_populates="vulnerabilities")
    findings = relationship("Finding", back_populates="linked_vulnerability")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    status = Column(String, nullable=False, default="queued")
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    options = Column(JSON, nullable=True)  # Scan options like include_agentic

    project = relationship("Project", back_populates="scan_runs")
    findings = relationship("Finding", back_populates="scan_run")
    reports = relationship("Report", back_populates="scan_run")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "scan_run_id", "id"),)

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), index=True)
    type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    file_path = Column(String, nullable=True)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    summary = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    linked_vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True)

    project = relationship("Project", back_populates="findings")
    scan_run = relationship("ScanRun", back_populates="findings")
    linked_vulnerability = relationship("Vulnerability", back_populates="findings")
    exploit_scenarios = relationship("ExploitScenario", back_populates="finding")
    notes = relationship("FindingNote", back_populates="finding", cascade="all, delete-orphan")


class FindingNote(Base):
    """User notes on findings for tracking remediation, analysis, and comments."""
    __tablename__ = "finding_notes"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Optional, for multi-user support
    
    content = Column(Text, nullable=False)
    note_type = Column(String, nullable=False, default="comment")  # comment, remediation, false_positive, accepted_risk, in_progress
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Optional extra data
    extra_data = Column(JSON, nullable=True)  # For additional structured data like tags, priority, etc.
    
    finding = relationship("Finding", back_populates="notes")
    user = relationship("User")


class ProjectNote(Base):
    """General project-level notes not tied to specific findings."""
    __tablename__ = "project_notes"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    title = Column(String, nullable=True)
    content = Column(Text, nullable=False)
    note_type = Column(String, nullable=False, default="general")  # general, todo, important, reference
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    extra_data = Column(JSON, nullable=True)
    
    project = relationship("Project", back_populates="project_notes")
    user = relationship("User")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    overall_risk_score = Column(Float, nullable=True)
    data = Column(JSON, nullable=True)

    project = relationship("Project", back_populates="reports")
    scan_run = relationship("ScanRun", back_populates="reports")
    exploit_scenarios = relationship("ExploitScenario", back_populates="report")


class ExploitScenario(Base):
    __tablename__ = "exploit_scenarios"

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=True)  # Null for executive summaries
    severity = Column(String, nullable=True)
    title = Column(String, nullable=False)
    narrative = Column(Text, nullable=True)
    preconditions = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    poc_outline = Column(Text, nullable=True)
    poc_scripts = Column(JSON, nullable=True)  # Executable POC scripts by language
    attack_complexity = Column(String, nullable=True)  # Low, Medium, High
    exploit_maturity = Column(String, nullable=True)  # Proof of Concept, Functional, High
    mitigation_notes = Column(Text, nullable=True)

    report = relationship("Report", back_populates="exploit_scenarios")
    finding = relationship("Finding", back_populates="exploit_scenarios")


class NetworkAnalysisReport(Base):
    """Stores network analysis reports (PCAP, Nmap, DNS, etc.)."""
    __tablename__ = "network_analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)  # Optional project association
    analysis_type = Column(String, nullable=False)  # 'pcap', 'nmap', 'dns'
    report_type = Column(String, nullable=True)  # Alternative categorization (dns, pcap, nmap)
    title = Column(String, nullable=False)
    filename = Column(String, nullable=True)  # Original uploaded filename(s)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Risk assessment
    risk_level = Column(String, nullable=True)  # Critical, High, Medium, Low
    risk_score = Column(Integer, nullable=True)  # 0-100
    
    # Summary data
    summary_data = Column(JSON, nullable=True)  # Protocol stats, top talkers, etc.
    
    # Findings
    findings_data = Column(JSON, nullable=True)  # List of security findings
    
    # AI Analysis - structured report
    ai_report = Column(JSON, nullable=True)  # Full structured AI report
    
    # Generic report data (for DNS and other report types)
    report_data = Column(JSON, nullable=True)  # Flexible data storage
    
    # Export metadata
    last_exported_at = Column(DateTime(timezone=True), nullable=True)
    export_formats = Column(JSON, nullable=True)  # List of formats exported
    
    # Relationship
    project = relationship("Project", back_populates="network_analysis_reports")


class FuzzingSession(Base):
    """Stores fuzzing session data including config, results, and analysis."""
    __tablename__ = "fuzzing_sessions"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)  # Optional project association
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    target_url = Column(String, nullable=False, index=True)
    method = Column(String, nullable=False, default="GET")
    status = Column(String, nullable=False, default="created", index=True)  # created, running, paused, completed, failed
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    
    # Configuration stored as JSON
    config = Column(JSON, nullable=True)
    
    # Statistics
    total_requests = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    interesting_count = Column(Integer, default=0)
    avg_response_time = Column(Float, nullable=True)
    
    # Results stored as JSON
    results = Column(JSON, nullable=True)
    
    # Findings from smart detection
    findings = Column(JSON, nullable=True)
    
    # Analysis results (WAF, rate limiting, etc.)
    analysis = Column(JSON, nullable=True)
    
    # Tags for organization
    tags = Column(JSON, nullable=True)
    
    # Relationship
    project = relationship("Project", back_populates="fuzzing_sessions")


class ReverseEngineeringReport(Base):
    """Stores reverse engineering analysis reports (Binary, APK, Docker)."""
    __tablename__ = "reverse_engineering_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)
    
    # Report metadata
    analysis_type = Column(String, nullable=False, index=True)  # 'binary', 'apk', 'docker'
    title = Column(String, nullable=False)
    filename = Column(String, nullable=True)  # Original filename analyzed
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Risk assessment from AI
    risk_level = Column(String, nullable=True)  # Critical, High, Medium, Low, Clean
    risk_score = Column(Integer, nullable=True)  # 0-100
    
    # For binary analysis
    file_type = Column(String, nullable=True)
    architecture = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    is_packed = Column(String, nullable=True)
    packer_name = Column(String, nullable=True)
    
    # For APK analysis
    package_name = Column(String, nullable=True)
    version_name = Column(String, nullable=True)
    min_sdk = Column(Integer, nullable=True)
    target_sdk = Column(Integer, nullable=True)
    
    # For Docker analysis
    image_name = Column(String, nullable=True)
    image_id = Column(String, nullable=True)
    total_layers = Column(Integer, nullable=True)
    base_image = Column(String, nullable=True)
    
    # Analysis data (JSON)
    strings_count = Column(Integer, nullable=True)
    imports_count = Column(Integer, nullable=True)
    exports_count = Column(Integer, nullable=True)
    secrets_count = Column(Integer, nullable=True)
    suspicious_indicators = Column(JSON, nullable=True)  # List of suspicious findings
    permissions = Column(JSON, nullable=True)  # For APK
    security_issues = Column(JSON, nullable=True)  # Common findings
    
    # Full analysis data (for detailed view)
    full_analysis_data = Column(JSON, nullable=True)
    
    # AI Analysis - both raw and structured
    ai_analysis_raw = Column(Text, nullable=True)  # Original AI response
    ai_analysis_structured = Column(JSON, nullable=True)  # Parsed structured analysis
    
    # JADX Full Scan Data
    jadx_total_classes = Column(Integer, nullable=True)
    jadx_total_files = Column(Integer, nullable=True)
    jadx_data = Column(JSON, nullable=True)  # Contains classes sample, security issues, etc.
    
    # AI-Generated Reports (Deep Analysis)
    ai_functionality_report = Column(Text, nullable=True)
    ai_security_report = Column(Text, nullable=True)
    ai_privacy_report = Column(Text, nullable=True)
    ai_architecture_diagram = Column(Text, nullable=True)  # Mermaid diagram
    ai_threat_model = Column(JSON, nullable=True)
    ai_vuln_scan_result = Column(JSON, nullable=True)
    ai_chat_history = Column(JSON, nullable=True)
    ai_attack_surface_map = Column(Text, nullable=True)  # Mermaid attack tree diagram
    
    # Library CVE Analysis
    detected_libraries = Column(JSON, nullable=True)  # Libraries detected in APK
    library_cves = Column(JSON, nullable=True)  # CVEs found in libraries
    
    # Dynamic Analysis / Frida Scripts
    dynamic_analysis = Column(JSON, nullable=True)  # Frida scripts, detection flags, commands
    
    # Decompiled Code Analysis Results (Pattern-based scanners)
    decompiled_code_findings = Column(JSON, nullable=True)  # Security findings from decompiled code
    decompiled_code_summary = Column(JSON, nullable=True)  # Summary by severity/scanner/category
    
    # CVE Scan Results
    cve_scan_results = Column(JSON, nullable=True)  # CVE database lookup results
    
    # Vulnerability-specific Frida Hooks
    vulnerability_frida_hooks = Column(JSON, nullable=True)  # Auto-generated hooks for discovered vulns
    
    # Manifest Visualization (component graph, deep links, AI analysis)
    manifest_visualization = Column(JSON, nullable=True)
    
    # Obfuscation Analysis (detection, deobfuscation strategies, Frida hooks)
    obfuscation_analysis = Column(JSON, nullable=True)
    
    # AI Finding Verification Results (confidence scores, attack chains, FP filtering)
    verification_results = Column(JSON, nullable=True)
    
    # Sensitive Data Discovery (AI-verified passwords, API keys, emails, phone numbers, PII)
    sensitive_data_findings = Column(JSON, nullable=True)
    
    # Tags and notes
    tags = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Relationship
    project = relationship("Project", back_populates="reverse_engineering_reports")


# ============================================================================
# Social / Messaging Models
# ============================================================================

class FriendRequest(Base):
    """Friend/contact request between users."""
    __tablename__ = "friend_requests"
    __table_args__ = (
        UniqueConstraint("sender_id", "receiver_id", name="unique_friend_request"),
    )

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String, nullable=False, default="pending", index=True)  # pending, accepted, rejected
    message = Column(Text, nullable=True)  # Optional message with request
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    responded_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_friend_requests")
    receiver = relationship("User", foreign_keys=[receiver_id], back_populates="received_friend_requests")


class Friendship(Base):
    """Established friendship between two users."""
    __tablename__ = "friendships"
    __table_args__ = (
        UniqueConstraint("user1_id", "user2_id", name="unique_friendship"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user1_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    user2_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user1 = relationship("User", foreign_keys=[user1_id], back_populates="friendships_as_user1")
    user2 = relationship("User", foreign_keys=[user2_id], back_populates="friendships_as_user2")


class Conversation(Base):
    """A conversation (can be 1-on-1 or group chat)."""
    __tablename__ = "conversations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)  # For group chats
    is_group = Column(String, nullable=False, default="false")  # "true" or "false" for group chats
    description = Column(Text, nullable=True)  # Group description
    avatar_url = Column(String, nullable=True)  # Group avatar
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)  # Group creator
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)  # For project team chats
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_message_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    participants = relationship("ConversationParticipant", back_populates="conversation", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])
    project = relationship("Project", foreign_keys=[project_id])


class ConversationParticipant(Base):
    """Links users to conversations with role management."""
    __tablename__ = "conversation_participants"
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="unique_conversation_participant"),
    )

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    joined_at = Column(DateTime(timezone=True), server_default=func.now())
    last_read_at = Column(DateTime(timezone=True), nullable=True)  # For tracking unread messages
    role = Column(String, nullable=False, default="member")  # "owner", "admin", "member"
    added_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    nickname = Column(String, nullable=True)  # Custom nickname in group
    is_muted = Column(String, nullable=False, default="false")  # Mute notifications
    muted_until = Column(DateTime(timezone=True), nullable=True)  # Null = forever if is_muted, timestamp = until then
    
    # Relationships
    conversation = relationship("Conversation", back_populates="participants")
    user = relationship("User", foreign_keys=[user_id], back_populates="conversations")
    added_by_user = relationship("User", foreign_keys=[added_by])


class Message(Base):
    """A message in a conversation."""
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    message_type = Column(String, nullable=False, default="text")  # text, file, image, report_share
    attachment_data = Column(JSON, nullable=True)  # {filename, file_url, file_size, mime_type, thumbnail_url}
    reply_to_id = Column(Integer, ForeignKey("messages.id", ondelete="SET NULL"), nullable=True)  # For reply threading
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_edited = Column(String, nullable=False, default="false")
    is_deleted = Column(String, nullable=False, default="false")
    
    # Relationships
    conversation = relationship("Conversation", back_populates="messages")
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    reply_to = relationship("Message", remote_side=[id], backref="replies")
    reactions = relationship("MessageReaction", back_populates="message", cascade="all, delete-orphan")


class MessageReaction(Base):
    """Emoji reactions on messages."""
    __tablename__ = "message_reactions"
    __table_args__ = (
        UniqueConstraint("message_id", "user_id", "emoji", name="unique_message_reaction"),
    )

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    emoji = Column(String(32), nullable=False)  # Unicode emoji or shortcode
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    message = relationship("Message", back_populates="reactions")
    user = relationship("User", backref="message_reactions")


class PinnedMessage(Base):
    """Pinned messages in a conversation."""
    __tablename__ = "pinned_messages"
    __table_args__ = (
        UniqueConstraint("conversation_id", "message_id", name="unique_pinned_message"),
    )

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    pinned_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    pinned_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    conversation = relationship("Conversation", backref="pinned_messages")
    message = relationship("Message", backref="pinned_in")
    pinned_by_user = relationship("User", backref="messages_pinned")


class MessageReadReceipt(Base):
    """Track which users have read which messages."""
    __tablename__ = "message_read_receipts"
    __table_args__ = (
        UniqueConstraint("conversation_id", "user_id", name="unique_read_receipt"),
    )

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    last_read_message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False)
    read_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    conversation = relationship("Conversation", backref="read_receipts")
    user = relationship("User", backref="read_receipts")
    last_read_message = relationship("Message", backref="read_by")


class UserNote(Base):
    """Personal notes on a user's profile - private to the note owner."""
    __tablename__ = "user_notes"
    __table_args__ = (
        UniqueConstraint("owner_id", "subject_id", name="unique_user_note"),
    )

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)  # Who wrote the note
    subject_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)  # About whom
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    owner = relationship("User", foreign_keys=[owner_id], backref="notes_written")
    subject = relationship("User", foreign_keys=[subject_id], backref="notes_about")


class Poll(Base):
    """A poll in a conversation."""
    __tablename__ = "polls"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=True, index=True)  # Associated message
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    question = Column(Text, nullable=False)
    poll_type = Column(String, nullable=False, default="single")  # "single" or "multiple" choice
    is_anonymous = Column(String, nullable=False, default="false")  # Hide who voted
    allow_add_options = Column(String, nullable=False, default="false")  # Let users add options
    closes_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration
    is_closed = Column(String, nullable=False, default="false")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    conversation = relationship("Conversation", backref="polls")
    message = relationship("Message", backref="poll")
    creator = relationship("User", backref="created_polls")
    options = relationship("PollOption", back_populates="poll", cascade="all, delete-orphan")


class PollOption(Base):
    """An option in a poll."""
    __tablename__ = "poll_options"

    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(Integer, ForeignKey("polls.id", ondelete="CASCADE"), nullable=False, index=True)
    text = Column(String(500), nullable=False)
    added_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    poll = relationship("Poll", back_populates="options")
    added_by_user = relationship("User", backref="poll_options_added")
    votes = relationship("PollVote", back_populates="option", cascade="all, delete-orphan")


class PollVote(Base):
    """A vote on a poll option."""
    __tablename__ = "poll_votes"
    __table_args__ = (
        UniqueConstraint("option_id", "user_id", name="unique_poll_vote"),
    )

    id = Column(Integer, primary_key=True, index=True)
    option_id = Column(Integer, ForeignKey("poll_options.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    voted_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    option = relationship("PollOption", back_populates="votes")
    user = relationship("User", backref="poll_votes")


class MessageBookmark(Base):
    """User bookmarks for messages - personal to each user."""
    __tablename__ = "message_bookmarks"
    __table_args__ = (
        UniqueConstraint("user_id", "message_id", name="unique_message_bookmark"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    note = Column(Text, nullable=True)  # Optional note for the bookmark
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", backref="bookmarks")
    message = relationship("Message", backref="bookmarked_by")


class MessageEditHistory(Base):
    """Tracks edit history for messages."""
    __tablename__ = "message_edit_history"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    previous_content = Column(Text, nullable=False)  # Content before the edit
    edited_at = Column(DateTime(timezone=True), server_default=func.now())
    edit_number = Column(Integer, nullable=False, default=1)  # Which edit this was (1st, 2nd, etc.)
    
    # Relationships
    message = relationship("Message", backref="edit_history")


# ============================================================================
# Project Files & Documents
# ============================================================================

class ProjectFile(Base):
    """Files uploaded to a project for storage."""
    __tablename__ = "project_files"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    uploaded_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_url = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)  # bytes
    mime_type = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    folder = Column(String, nullable=True, default="")  # Virtual folder path
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    project = relationship("Project", backref="files")
    uploader = relationship("User", backref="uploaded_files")


class DocumentAnalysisReport(Base):
    """A report containing analysis of one or more documents."""
    __tablename__ = "document_analysis_reports"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # User-provided context for AI analysis
    custom_prompt = Column(Text, nullable=True)  # Additional instructions for AI
    
    # Combined analysis results (for multi-doc analysis)
    combined_summary = Column(Text, nullable=True)
    combined_key_points = Column(JSON, nullable=True)
    
    # Processing status
    status = Column(String, nullable=False, default="pending")  # pending, processing, completed, failed
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    project = relationship("Project", backref="analysis_reports")
    creator = relationship("User", backref="created_analysis_reports")
    documents = relationship("ProjectDocument", back_populates="report", cascade="all, delete-orphan")
    chat_messages = relationship("ReportChatMessage", back_populates="report", cascade="all, delete-orphan")


class ProjectDocument(Base):
    """Documents uploaded for AI analysis and summarization."""
    __tablename__ = "project_documents"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    report_id = Column(Integer, ForeignKey("document_analysis_reports.id", ondelete="CASCADE"), nullable=True, index=True)
    uploaded_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_url = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String, nullable=True)
    
    # Extracted content and AI analysis
    extracted_text = Column(Text, nullable=True)  # Full text content
    text_chunks = Column(ARRAY(Text), nullable=True)  # Chunked text for embeddings
    summary = Column(Text, nullable=True)  # AI-generated summary
    key_points = Column(ARRAY(Text), nullable=True)  # Key takeaways as PostgreSQL array
    
    # Processing status
    status = Column(String, nullable=False, default="pending")  # pending, processing, completed, failed
    error_message = Column(Text, nullable=True)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    project = relationship("Project", backref="documents")
    report = relationship("DocumentAnalysisReport", back_populates="documents")
    uploader = relationship("User", backref="uploaded_documents")
    chat_messages = relationship("DocumentChatMessage", back_populates="document", cascade="all, delete-orphan")


class DocumentChatMessage(Base):
    """Chat messages for document Q&A."""
    __tablename__ = "document_chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("project_documents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    role = Column(String, nullable=False)  # "user" or "assistant"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    document = relationship("ProjectDocument", back_populates="chat_messages")
    user = relationship("User", backref="document_chats")


class ReportChatMessage(Base):
    """Chat messages for analysis report Q&A (multi-document context)."""
    __tablename__ = "report_chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("document_analysis_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    role = Column(String, nullable=False)  # "user" or "assistant"
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    report = relationship("DocumentAnalysisReport", back_populates="chat_messages")
    user = relationship("User", backref="report_chats")
