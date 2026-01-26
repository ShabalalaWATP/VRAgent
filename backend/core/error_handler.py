"""
VRAgent Error Handler - User-Friendly Error Messages
Provides helpful error messages with solutions and documentation links
"""

from typing import Optional
import logging

logger = logging.getLogger(__name__)


class VRAgentError(Exception):
    """Base exception with user-friendly messages"""

    def __init__(
        self,
        message: str,
        solution: Optional[str] = None,
        docs_url: Optional[str] = None,
        error_code: Optional[str] = None
    ):
        self.message = message
        self.solution = solution
        self.docs_url = docs_url
        self.error_code = error_code or "VRAGENT_ERROR"
        super().__init__(self.user_friendly_message)

    @property
    def user_friendly_message(self) -> str:
        """Generate user-friendly error message"""
        msg = f"❌ {self.message}"

        if self.solution:
            msg += f"\n💡 Solution: {self.solution}"

        if self.docs_url:
            msg += f"\n📖 Documentation: {self.docs_url}"

        return msg

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses"""
        return {
            "error": self.error_code,
            "message": self.message,
            "solution": self.solution,
            "docs_url": self.docs_url
        }


# File-related errors
class FileNotFoundError(VRAgentError):
    """Raised when file not found"""

    def __init__(self, path: str):
        super().__init__(
            message=f"File not found: {path}",
            solution="Check the file path and ensure the file exists",
            docs_url="https://docs.vragent.com/troubleshooting#file-not-found",
            error_code="FILE_NOT_FOUND"
        )


class FileTooLargeError(VRAgentError):
    """Raised when file exceeds size limit"""

    def __init__(self, size_gb: float, max_gb: float):
        super().__init__(
            message=f"File too large: {size_gb:.2f}GB (maximum: {max_gb:.2f}GB)",
            solution=f"Upload a smaller file or contact support for enterprise limits",
            docs_url="https://docs.vragent.com/limits#file-size",
            error_code="FILE_TOO_LARGE"
        )


class InvalidFileFormatError(VRAgentError):
    """Raised when file format not supported"""

    def __init__(self, format: str, supported_formats: list):
        super().__init__(
            message=f"Unsupported file format: {format}",
            solution=f"Supported formats: {', '.join(supported_formats)}",
            docs_url="https://docs.vragent.com/supported-formats",
            error_code="INVALID_FILE_FORMAT"
        )


# Binary analysis errors
class BinaryParsingError(VRAgentError):
    """Raised when binary cannot be parsed"""

    def __init__(self, reason: str):
        super().__init__(
            message=f"Failed to parse binary: {reason}",
            solution="Ensure the file is a valid PE/ELF/Mach-O binary",
            docs_url="https://docs.vragent.com/troubleshooting#parsing-error",
            error_code="BINARY_PARSING_ERROR"
        )


class DecompilationError(VRAgentError):
    """Raised when decompilation fails"""

    def __init__(self, reason: str):
        super().__init__(
            message=f"Decompilation failed: {reason}",
            solution="Try standard analysis mode or check if Ghidra is properly configured",
            docs_url="https://docs.vragent.com/troubleshooting#decompilation-failed",
            error_code="DECOMPILATION_ERROR"
        )


class YARAScanError(VRAgentError):
    """Raised when YARA scanning fails"""

    def __init__(self, reason: str):
        super().__init__(
            message=f"YARA scan failed: {reason}",
            solution="YARA rules may be corrupted. Contact support if issue persists.",
            docs_url="https://docs.vragent.com/troubleshooting#yara-error",
            error_code="YARA_SCAN_ERROR"
        )


# Dependency errors
class DependencyMissingError(VRAgentError):
    """Raised when required dependency missing"""

    def __init__(self, dependency: str, install_command: Optional[str] = None):
        solution = "Contact your system administrator"
        if install_command:
            solution = f"Install it with: {install_command}"

        super().__init__(
            message=f"Required dependency missing: {dependency}",
            solution=solution,
            docs_url="https://docs.vragent.com/dependencies",
            error_code="DEPENDENCY_MISSING"
        )


class ServiceUnavailableError(VRAgentError):
    """Raised when a service is unavailable"""

    def __init__(self, service: str):
        super().__init__(
            message=f"Service temporarily unavailable: {service}",
            solution="Please try again in a few moments. If issue persists, contact support.",
            docs_url="https://docs.vragent.com/status",
            error_code="SERVICE_UNAVAILABLE"
        )


# Resource errors
class ResourceLimitExceededError(VRAgentError):
    """Raised when resource limit exceeded"""

    def __init__(self, resource: str, limit: str):
        super().__init__(
            message=f"Resource limit exceeded: {resource} (limit: {limit})",
            solution="Upgrade your plan for higher limits or contact support",
            docs_url="https://docs.vragent.com/limits",
            error_code="RESOURCE_LIMIT_EXCEEDED"
        )


class MemoryLimitExceededError(VRAgentError):
    """Raised when memory limit exceeded"""

    def __init__(self, used_gb: float, limit_gb: float):
        super().__init__(
            message=f"Memory limit exceeded: {used_gb:.2f}GB / {limit_gb:.2f}GB",
            solution="Try analyzing a smaller file or reduce analysis scope",
            docs_url="https://docs.vragent.com/troubleshooting#memory-limit",
            error_code="MEMORY_LIMIT_EXCEEDED"
        )


class TimeoutError(VRAgentError):
    """Raised when operation times out"""

    def __init__(self, operation: str, timeout_seconds: int):
        super().__init__(
            message=f"Operation timed out: {operation} (timeout: {timeout_seconds}s)",
            solution="Try again or contact support if issue persists",
            docs_url="https://docs.vragent.com/troubleshooting#timeout",
            error_code="TIMEOUT"
        )


# Authentication/Authorization errors
class AuthenticationError(VRAgentError):
    """Raised when authentication fails"""

    def __init__(self, reason: str = "Invalid credentials"):
        super().__init__(
            message=f"Authentication failed: {reason}",
            solution="Check your credentials or reset your password",
            docs_url="https://docs.vragent.com/authentication",
            error_code="AUTHENTICATION_FAILED"
        )


class AuthorizationError(VRAgentError):
    """Raised when user lacks permissions"""

    def __init__(self, resource: str):
        super().__init__(
            message=f"Access denied: {resource}",
            solution="You don't have permission to access this resource. Contact your administrator.",
            docs_url="https://docs.vragent.com/permissions",
            error_code="AUTHORIZATION_FAILED"
        )


# AI/Analysis errors
class AIServiceError(VRAgentError):
    """Raised when AI service fails"""

    def __init__(self, service: str, reason: str):
        super().__init__(
            message=f"AI service error ({service}): {reason}",
            solution="The AI service is temporarily unavailable. Results may be limited.",
            docs_url="https://docs.vragent.com/troubleshooting#ai-service",
            error_code="AI_SERVICE_ERROR"
        )


class AnalysisError(VRAgentError):
    """Raised when analysis fails"""

    def __init__(self, phase: str, reason: str):
        super().__init__(
            message=f"Analysis failed during {phase}: {reason}",
            solution="Try standard analysis mode or contact support",
            docs_url="https://docs.vragent.com/troubleshooting#analysis-failed",
            error_code="ANALYSIS_FAILED"
        )


# Helper function for error handling decorator
def handle_errors(func):
    """Decorator to convert exceptions to VRAgentErrors"""

    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except VRAgentError:
            # Already a VRAgent error, re-raise
            raise
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            raise FileNotFoundError(str(e))
        except MemoryError as e:
            logger.error(f"Out of memory: {e}")
            raise MemoryLimitExceededError(0, 8)  # Assume 8GB limit
        except Exception as e:
            # Unexpected error - log and wrap
            logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
            raise VRAgentError(
                message=f"An unexpected error occurred: {str(e)}",
                solution="Please try again. If issue persists, contact support with error details.",
                docs_url="https://docs.vragent.com/support",
                error_code="INTERNAL_ERROR"
            )

    return wrapper
