"""
Custom exceptions for the VRAgent backend.
Provides structured error handling throughout the application.
"""
from typing import Any, Dict, Optional


class VRAgentError(Exception):
    """Base exception for all VRAgent errors."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.details = details or {}
        super().__init__(self.message)


class ProjectNotFoundError(VRAgentError):
    """Raised when a project cannot be found."""
    
    def __init__(self, project_id: int):
        super().__init__(
            message=f"Project with ID {project_id} not found",
            error_code="PROJECT_NOT_FOUND",
            details={"project_id": project_id}
        )


class ScanRunNotFoundError(VRAgentError):
    """Raised when a scan run cannot be found."""
    
    def __init__(self, scan_run_id: int):
        super().__init__(
            message=f"Scan run with ID {scan_run_id} not found",
            error_code="SCAN_RUN_NOT_FOUND",
            details={"scan_run_id": scan_run_id}
        )


class ReportNotFoundError(VRAgentError):
    """Raised when a report cannot be found."""
    
    def __init__(self, report_id: int):
        super().__init__(
            message=f"Report with ID {report_id} not found",
            error_code="REPORT_NOT_FOUND",
            details={"report_id": report_id}
        )


class FileUploadError(VRAgentError):
    """Raised when file upload validation fails."""
    
    def __init__(self, message: str, filename: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="FILE_UPLOAD_ERROR",
            details={"filename": filename} if filename else {}
        )


class ZipExtractionError(VRAgentError):
    """Raised when zip extraction fails."""
    
    def __init__(self, message: str, path: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="ZIP_EXTRACTION_ERROR",
            details={"path": path} if path else {}
        )


class ScanError(VRAgentError):
    """Raised when a scan operation fails."""
    
    def __init__(self, message: str, project_id: Optional[int] = None):
        super().__init__(
            message=message,
            error_code="SCAN_ERROR",
            details={"project_id": project_id} if project_id else {}
        )


class ExternalServiceError(VRAgentError):
    """Raised when an external service call fails."""
    
    def __init__(self, service: str, message: str):
        super().__init__(
            message=f"{service} service error: {message}",
            error_code="EXTERNAL_SERVICE_ERROR",
            details={"service": service}
        )


class GeminiAPIError(ExternalServiceError):
    """Raised when Gemini API calls fail."""
    
    def __init__(self, message: str):
        super().__init__(service="Gemini", message=message)


class OSVAPIError(ExternalServiceError):
    """Raised when OSV API calls fail."""
    
    def __init__(self, message: str):
        super().__init__(service="OSV", message=message)
