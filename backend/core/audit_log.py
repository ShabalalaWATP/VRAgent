"""
Audit Logging for VRAgent
Comprehensive audit trail for security and compliance
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
from functools import wraps
import inspect

from backend.core.config import settings


class AuditEventType(Enum):
    """Audit event types"""
    # Authentication
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILED = "auth.login.failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_CREATED = "auth.token.created"
    AUTH_TOKEN_REVOKED = "auth.token.revoked"

    # Authorization
    AUTHZ_ACCESS_GRANTED = "authz.access.granted"
    AUTHZ_ACCESS_DENIED = "authz.access.denied"

    # File Operations
    FILE_UPLOADED = "file.uploaded"
    FILE_DOWNLOADED = "file.downloaded"
    FILE_DELETED = "file.deleted"

    # Binary Analysis
    BINARY_ANALYZED = "binary.analyzed"
    BINARY_ANALYSIS_FAILED = "binary.analysis.failed"

    # Fuzzing
    FUZZING_STARTED = "fuzzing.started"
    FUZZING_STOPPED = "fuzzing.stopped"
    FUZZING_CRASH_FOUND = "fuzzing.crash.found"

    # Android
    ANDROID_DEVICE_CONNECTED = "android.device.connected"
    ANDROID_APK_ANALYZED = "android.apk.analyzed"

    # Data Access
    DATA_ACCESSED = "data.accessed"
    DATA_MODIFIED = "data.modified"
    DATA_DELETED = "data.deleted"
    DATA_EXPORTED = "data.exported"

    # Admin Actions
    ADMIN_USER_CREATED = "admin.user.created"
    ADMIN_USER_DELETED = "admin.user.deleted"
    ADMIN_USER_MODIFIED = "admin.user.modified"
    ADMIN_ROLE_CHANGED = "admin.role.changed"
    ADMIN_CONFIG_CHANGED = "admin.config.changed"

    # Security Events
    SECURITY_SUSPICIOUS_ACTIVITY = "security.suspicious.activity"
    SECURITY_RATE_LIMIT_EXCEEDED = "security.rate_limit.exceeded"
    SECURITY_RESOURCE_LIMIT_EXCEEDED = "security.resource_limit.exceeded"

    # System Events
    SYSTEM_STARTED = "system.started"
    SYSTEM_STOPPED = "system.stopped"
    SYSTEM_ERROR = "system.error"


class AuditSeverity(Enum):
    """Audit event severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditLogger:
    """
    Centralized audit logging system.

    Features:
    - Structured JSON logging
    - Event categorization
    - User tracking
    - IP address tracking
    - Request ID correlation
    - Compliance reporting
    """

    def __init__(self, logger_name: str = "vragent.audit"):
        self.logger = logging.getLogger(logger_name)

        # Configure audit log handler
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/audit.log')
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _create_audit_entry(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create structured audit log entry"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "severity": severity.value,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "request_id": request_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "result": result,
            "details": details or {},
            "error": error,
            "environment": settings.environment
        }

        # Remove None values for cleaner logs
        return {k: v for k, v in entry.items() if v is not None}

    def log(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity = AuditSeverity.INFO,
        **kwargs
    ):
        """
        Log an audit event.

        Args:
            event_type: Type of event
            severity: Event severity
            **kwargs: Additional audit fields (user_id, ip_address, etc.)
        """
        entry = self._create_audit_entry(event_type, severity, **kwargs)

        # Log as JSON
        self.logger.info(json.dumps(entry))

        # Also log to main logger for critical events
        if severity in [AuditSeverity.ERROR, AuditSeverity.CRITICAL]:
            main_logger = logging.getLogger(__name__)
            main_logger.error(f"AUDIT: {event_type.value} - {entry.get('details', {})}")

    # Convenience methods for common events

    def log_login(self, username: str, success: bool, ip_address: str, reason: Optional[str] = None):
        """Log authentication attempt"""
        event_type = AuditEventType.AUTH_LOGIN_SUCCESS if success else AuditEventType.AUTH_LOGIN_FAILED
        severity = AuditSeverity.INFO if success else AuditSeverity.WARNING

        self.log(
            event_type=event_type,
            severity=severity,
            username=username,
            ip_address=ip_address,
            result="success" if success else "failed",
            details={"reason": reason} if reason else None
        )

    def log_logout(self, user_id: int, username: str, ip_address: str):
        """Log user logout"""
        self.log(
            event_type=AuditEventType.AUTH_LOGOUT,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            result="success"
        )

    def log_access_denied(
        self,
        user_id: int,
        username: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: str,
        ip_address: str
    ):
        """Log access denied event"""
        self.log(
            event_type=AuditEventType.AUTHZ_ACCESS_DENIED,
            severity=AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result="denied",
            ip_address=ip_address,
            details={"reason": reason}
        )

    def log_file_upload(
        self,
        user_id: int,
        username: str,
        filename: str,
        file_size: int,
        file_type: str,
        sha256: str,
        ip_address: str
    ):
        """Log file upload"""
        self.log(
            event_type=AuditEventType.FILE_UPLOADED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type="file",
            resource_id=sha256,
            action="upload",
            result="success",
            ip_address=ip_address,
            details={
                "filename": filename,
                "file_size": file_size,
                "file_type": file_type
            }
        )

    def log_binary_analysis(
        self,
        user_id: int,
        username: str,
        binary_id: int,
        filename: str,
        analysis_type: str,
        duration_seconds: float,
        success: bool,
        ip_address: str,
        error: Optional[str] = None
    ):
        """Log binary analysis"""
        event_type = AuditEventType.BINARY_ANALYZED if success else AuditEventType.BINARY_ANALYSIS_FAILED
        severity = AuditSeverity.INFO if success else AuditSeverity.ERROR

        self.log(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            username=username,
            resource_type="binary",
            resource_id=str(binary_id),
            action="analyze",
            result="success" if success else "failed",
            ip_address=ip_address,
            details={
                "filename": filename,
                "analysis_type": analysis_type,
                "duration_seconds": duration_seconds
            },
            error=error
        )

    def log_fuzzing_started(
        self,
        user_id: int,
        username: str,
        campaign_id: str,
        binary_name: str,
        config: Dict[str, Any],
        ip_address: str
    ):
        """Log fuzzing campaign start"""
        self.log(
            event_type=AuditEventType.FUZZING_STARTED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type="fuzzing_campaign",
            resource_id=campaign_id,
            action="start",
            result="success",
            ip_address=ip_address,
            details={
                "binary_name": binary_name,
                "config": config
            }
        )

    def log_data_export(
        self,
        user_id: int,
        username: str,
        data_type: str,
        record_count: int,
        format: str,
        ip_address: str
    ):
        """Log data export"""
        self.log(
            event_type=AuditEventType.DATA_EXPORTED,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type=data_type,
            action="export",
            result="success",
            ip_address=ip_address,
            details={
                "record_count": record_count,
                "format": format
            }
        )

    def log_admin_action(
        self,
        admin_user_id: int,
        admin_username: str,
        action: str,
        target_user_id: Optional[int],
        target_username: Optional[str],
        changes: Dict[str, Any],
        ip_address: str
    ):
        """Log administrative action"""
        self.log(
            event_type=AuditEventType.ADMIN_USER_MODIFIED,
            severity=AuditSeverity.WARNING,  # Admin actions are notable
            user_id=admin_user_id,
            username=admin_username,
            resource_type="user",
            resource_id=str(target_user_id) if target_user_id else None,
            action=action,
            result="success",
            ip_address=ip_address,
            details={
                "target_username": target_username,
                "changes": changes
            }
        )

    def log_suspicious_activity(
        self,
        user_id: Optional[int],
        username: Optional[str],
        activity_type: str,
        description: str,
        ip_address: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log suspicious activity"""
        self.log(
            event_type=AuditEventType.SECURITY_SUSPICIOUS_ACTIVITY,
            severity=AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            action=activity_type,
            ip_address=ip_address,
            details={
                "description": description,
                **(details or {})
            }
        )

    def log_resource_limit_exceeded(
        self,
        user_id: int,
        username: str,
        resource: str,
        limit: str,
        current: str,
        operation: str,
        ip_address: str
    ):
        """Log resource limit violation"""
        self.log(
            event_type=AuditEventType.SECURITY_RESOURCE_LIMIT_EXCEEDED,
            severity=AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            action=operation,
            result="denied",
            ip_address=ip_address,
            details={
                "resource": resource,
                "limit": limit,
                "current": current
            }
        )

    def log_system_error(
        self,
        error_type: str,
        error_message: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log system error"""
        self.log(
            event_type=AuditEventType.SYSTEM_ERROR,
            severity=AuditSeverity.ERROR,
            action=error_type,
            result="error",
            error=error_message,
            details=details
        )


# Global audit logger instance
audit_logger = AuditLogger()


# ============================================================================
# Decorators for Automatic Audit Logging
# ============================================================================

def audit_log(event_type: AuditEventType, severity: AuditSeverity = AuditSeverity.INFO):
    """
    Decorator to automatically log function calls.

    Usage:
        @audit_log(AuditEventType.BINARY_ANALYZED)
        async def analyze_binary(binary_id: int, user: User):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from kwargs if present
            user = kwargs.get('user')
            user_id = user.id if user else None
            username = user.username if user else None

            # Get function name and module
            func_name = func.__name__
            module_name = func.__module__

            try:
                result = await func(*args, **kwargs)

                # Log success
                audit_logger.log(
                    event_type=event_type,
                    severity=severity,
                    user_id=user_id,
                    username=username,
                    action=func_name,
                    result="success",
                    details={
                        "function": f"{module_name}.{func_name}",
                        "args_count": len(args),
                        "kwargs_keys": list(kwargs.keys())
                    }
                )

                return result

            except Exception as e:
                # Log failure
                audit_logger.log(
                    event_type=event_type,
                    severity=AuditSeverity.ERROR,
                    user_id=user_id,
                    username=username,
                    action=func_name,
                    result="error",
                    error=str(e),
                    details={
                        "function": f"{module_name}.{func_name}",
                        "error_type": type(e).__name__
                    }
                )

                raise

        return wrapper
    return decorator


def audit_access(resource_type: str):
    """
    Decorator to log resource access.

    Usage:
        @audit_access("scan")
        async def get_scan(scan_id: int, user: User):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get('user')

            # Extract resource ID from args
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            resource_id = None

            if params and len(args) > 0:
                resource_id = str(args[0])
            elif f"{resource_type}_id" in kwargs:
                resource_id = str(kwargs[f"{resource_type}_id"])

            try:
                result = await func(*args, **kwargs)

                # Log access granted
                audit_logger.log(
                    event_type=AuditEventType.DATA_ACCESSED,
                    severity=AuditSeverity.INFO,
                    user_id=user.id if user else None,
                    username=user.username if user else None,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action="access",
                    result="granted"
                )

                return result

            except PermissionError as e:
                # Log access denied
                audit_logger.log_access_denied(
                    user_id=user.id if user else 0,
                    username=user.username if user else "unknown",
                    resource_type=resource_type,
                    resource_id=resource_id or "unknown",
                    action="access",
                    reason=str(e),
                    ip_address="unknown"
                )

                raise

        return wrapper
    return decorator
