"""
Tests for error handling system
"""

import pytest
from unittest.mock import Mock, AsyncMock

from backend.core.error_handler import (
    VRAgentError,
    FileNotFoundError,
    FileTooLargeError,
    InvalidFileFormatError,
    BinaryParsingError,
    DecompilationError,
    YARAScanError,
    DependencyMissingError,
    ServiceUnavailableError,
    ResourceLimitExceededError,
    MemoryLimitExceededError,
    TimeoutError,
    AuthenticationError,
    AuthorizationError,
    AIServiceError,
    AnalysisError,
    handle_errors,
)


class TestVRAgentError:
    """Test base VRAgentError class"""

    def test_basic_error(self):
        """Test creating basic error"""
        error = VRAgentError(
            message="Something went wrong",
            error_code="TEST_ERROR"
        )

        assert error.message == "Something went wrong"
        assert error.error_code == "TEST_ERROR"
        assert error.solution is None
        assert error.docs_url is None

    def test_error_with_solution(self):
        """Test error with solution"""
        error = VRAgentError(
            message="Test error",
            solution="Try this fix",
            error_code="TEST_ERROR"
        )

        assert error.solution == "Try this fix"
        assert "Try this fix" in error.user_friendly_message

    def test_error_with_docs_url(self):
        """Test error with documentation URL"""
        error = VRAgentError(
            message="Test error",
            docs_url="https://docs.vragent.com/test",
            error_code="TEST_ERROR"
        )

        assert error.docs_url == "https://docs.vragent.com/test"
        assert "https://docs.vragent.com/test" in error.user_friendly_message

    def test_user_friendly_message(self):
        """Test user-friendly message formatting"""
        error = VRAgentError(
            message="Operation failed",
            solution="Retry the operation",
            docs_url="https://docs.vragent.com/help",
            error_code="OP_FAILED"
        )

        message = error.user_friendly_message

        assert "❌" in message
        assert "Operation failed" in message
        assert "💡 Solution: Retry the operation" in message
        assert "📖 Documentation: https://docs.vragent.com/help" in message

    def test_to_dict(self):
        """Test conversion to dictionary"""
        error = VRAgentError(
            message="Test error",
            solution="Test solution",
            docs_url="https://docs.vragent.com",
            error_code="TEST_ERROR"
        )

        error_dict = error.to_dict()

        assert error_dict["error"] == "TEST_ERROR"
        assert error_dict["message"] == "Test error"
        assert error_dict["solution"] == "Test solution"
        assert error_dict["docs_url"] == "https://docs.vragent.com"


class TestFileErrors:
    """Test file-related error classes"""

    def test_file_not_found_error(self):
        """Test FileNotFoundError"""
        error = FileNotFoundError("/path/to/missing.bin")

        assert "/path/to/missing.bin" in error.message
        assert error.error_code == "FILE_NOT_FOUND"
        assert "Check the file path" in error.solution
        assert error.docs_url is not None

    def test_file_too_large_error(self):
        """Test FileTooLargeError"""
        error = FileTooLargeError(size_gb=6.5, max_gb=5.0)

        assert "6.50GB" in error.message
        assert "5.00GB" in error.message
        assert error.error_code == "FILE_TOO_LARGE"
        assert "smaller file" in error.solution

    def test_invalid_file_format_error(self):
        """Test InvalidFileFormatError"""
        error = InvalidFileFormatError(
            format=".txt",
            supported_formats=[".exe", ".elf", ".bin"]
        )

        assert ".txt" in error.message
        assert error.error_code == "INVALID_FILE_FORMAT"
        assert ".exe" in error.solution
        assert ".elf" in error.solution


class TestBinaryAnalysisErrors:
    """Test binary analysis error classes"""

    def test_binary_parsing_error(self):
        """Test BinaryParsingError"""
        error = BinaryParsingError("Invalid PE header")

        assert "Invalid PE header" in error.message
        assert error.error_code == "BINARY_PARSING_ERROR"
        assert "PE/ELF/Mach-O" in error.solution

    def test_decompilation_error(self):
        """Test DecompilationError"""
        error = DecompilationError("Ghidra timeout")

        assert "Ghidra timeout" in error.message
        assert error.error_code == "DECOMPILATION_ERROR"
        assert "standard analysis" in error.solution.lower()

    def test_yara_scan_error(self):
        """Test YARAScanError"""
        error = YARAScanError("Rule compilation failed")

        assert "Rule compilation failed" in error.message
        assert error.error_code == "YARA_SCAN_ERROR"


class TestDependencyErrors:
    """Test dependency error classes"""

    def test_dependency_missing_error_with_command(self):
        """Test DependencyMissingError with install command"""
        error = DependencyMissingError(
            dependency="ghidra",
            install_command="apt install ghidra"
        )

        assert "ghidra" in error.message
        assert error.error_code == "DEPENDENCY_MISSING"
        assert "apt install ghidra" in error.solution

    def test_dependency_missing_error_without_command(self):
        """Test DependencyMissingError without install command"""
        error = DependencyMissingError(dependency="proprietary-tool")

        assert "proprietary-tool" in error.message
        assert "system administrator" in error.solution

    def test_service_unavailable_error(self):
        """Test ServiceUnavailableError"""
        error = ServiceUnavailableError("Redis")

        assert "Redis" in error.message
        assert error.error_code == "SERVICE_UNAVAILABLE"
        assert "try again" in error.solution.lower()


class TestResourceErrors:
    """Test resource-related error classes"""

    def test_resource_limit_exceeded_error(self):
        """Test ResourceLimitExceededError"""
        error = ResourceLimitExceededError(
            resource="CPU",
            limit="80%"
        )

        assert "CPU" in error.message
        assert "80%" in error.message
        assert error.error_code == "RESOURCE_LIMIT_EXCEEDED"

    def test_memory_limit_exceeded_error(self):
        """Test MemoryLimitExceededError"""
        error = MemoryLimitExceededError(used_gb=10.5, limit_gb=8.0)

        assert "10.50GB" in error.message
        assert "8.00GB" in error.message
        assert error.error_code == "MEMORY_LIMIT_EXCEEDED"
        assert "smaller file" in error.solution

    def test_timeout_error(self):
        """Test TimeoutError"""
        error = TimeoutError(operation="analysis", timeout_seconds=3600)

        assert "analysis" in error.message
        assert "3600" in error.message
        assert error.error_code == "TIMEOUT"


class TestAuthErrors:
    """Test authentication/authorization error classes"""

    def test_authentication_error_default(self):
        """Test AuthenticationError with default reason"""
        error = AuthenticationError()

        assert "Invalid credentials" in error.message
        assert error.error_code == "AUTHENTICATION_FAILED"

    def test_authentication_error_custom(self):
        """Test AuthenticationError with custom reason"""
        error = AuthenticationError("Token expired")

        assert "Token expired" in error.message
        assert error.error_code == "AUTHENTICATION_FAILED"

    def test_authorization_error(self):
        """Test AuthorizationError"""
        error = AuthorizationError("/admin/users")

        assert "/admin/users" in error.message
        assert error.error_code == "AUTHORIZATION_FAILED"
        assert "permission" in error.solution.lower()


class TestAIErrors:
    """Test AI/Analysis error classes"""

    def test_ai_service_error(self):
        """Test AIServiceError"""
        error = AIServiceError(
            service="gemini",
            reason="API key invalid"
        )

        assert "gemini" in error.message
        assert "API key invalid" in error.message
        assert error.error_code == "AI_SERVICE_ERROR"

    def test_analysis_error(self):
        """Test AnalysisError"""
        error = AnalysisError(
            phase="disassembly",
            reason="Unknown architecture"
        )

        assert "disassembly" in error.message
        assert "Unknown architecture" in error.message
        assert error.error_code == "ANALYSIS_FAILED"


@pytest.mark.asyncio
class TestHandleErrorsDecorator:
    """Test error handling decorator"""

    async def test_handle_errors_normal_execution(self):
        """Test decorator with normal execution"""
        @handle_errors
        async def successful_function():
            return "success"

        result = await successful_function()
        assert result == "success"

    async def test_handle_errors_vragent_error(self):
        """Test decorator with VRAgentError"""
        @handle_errors
        async def function_with_vragent_error():
            raise FileNotFoundError("/test/file.bin")

        with pytest.raises(FileNotFoundError):
            await function_with_vragent_error()

    async def test_handle_errors_file_not_found(self):
        """Test decorator converting FileNotFoundError"""
        @handle_errors
        async def function_with_file_error():
            raise FileNotFoundError("/missing.bin")

        with pytest.raises(FileNotFoundError):
            await function_with_file_error()

    async def test_handle_errors_memory_error(self):
        """Test decorator converting MemoryError"""
        @handle_errors
        async def function_with_memory_error():
            raise MemoryError("Out of memory")

        with pytest.raises(MemoryLimitExceededError):
            await function_with_memory_error()

    async def test_handle_errors_generic_exception(self):
        """Test decorator converting generic exceptions"""
        @handle_errors
        async def function_with_generic_error():
            raise ValueError("Something went wrong")

        with pytest.raises(VRAgentError) as exc_info:
            await function_with_generic_error()

        error = exc_info.value
        assert error.error_code == "INTERNAL_ERROR"
        assert "Something went wrong" in error.message


class TestErrorMessageFormatting:
    """Test error message formatting"""

    def test_emoji_in_messages(self):
        """Test that errors include emojis for better UX"""
        error = FileNotFoundError("/test.bin")
        message = error.user_friendly_message

        assert "❌" in message

    def test_solution_emoji(self):
        """Test that solutions include emoji"""
        error = FileTooLargeError(6.0, 5.0)
        message = error.user_friendly_message

        assert "💡" in message

    def test_docs_emoji(self):
        """Test that docs URL includes emoji"""
        error = FileTooLargeError(6.0, 5.0)
        message = error.user_friendly_message

        assert "📖" in message

    def test_multiline_message(self):
        """Test multiline error messages"""
        error = VRAgentError(
            message="First line",
            solution="Second line",
            docs_url="https://docs.vragent.com",
            error_code="TEST"
        )

        message = error.user_friendly_message
        lines = message.split("\n")

        assert len(lines) == 3


class TestErrorInheritance:
    """Test error class inheritance"""

    def test_all_errors_inherit_from_vragent_error(self):
        """Test that all custom errors inherit from VRAgentError"""
        error_classes = [
            FileNotFoundError,
            FileTooLargeError,
            InvalidFileFormatError,
            BinaryParsingError,
            DecompilationError,
            YARAScanError,
            DependencyMissingError,
            ServiceUnavailableError,
            ResourceLimitExceededError,
            MemoryLimitExceededError,
            TimeoutError,
            AuthenticationError,
            AuthorizationError,
            AIServiceError,
            AnalysisError,
        ]

        for error_class in error_classes:
            # Create instance with minimal args
            if error_class == FileNotFoundError:
                error = error_class("/test")
            elif error_class == FileTooLargeError:
                error = error_class(1.0, 0.5)
            elif error_class == InvalidFileFormatError:
                error = error_class(".txt", [".bin"])
            elif error_class in [BinaryParsingError, DecompilationError, YARAScanError]:
                error = error_class("test")
            elif error_class == DependencyMissingError:
                error = error_class("test")
            elif error_class == ServiceUnavailableError:
                error = error_class("test")
            elif error_class == ResourceLimitExceededError:
                error = error_class("test", "100")
            elif error_class == MemoryLimitExceededError:
                error = error_class(1.0, 0.5)
            elif error_class == TimeoutError:
                error = error_class("test", 60)
            elif error_class == AuthenticationError:
                error = error_class()
            elif error_class == AuthorizationError:
                error = error_class("/test")
            elif error_class == AIServiceError:
                error = error_class("test", "test")
            elif error_class == AnalysisError:
                error = error_class("test", "test")

            assert isinstance(error, VRAgentError)
            assert isinstance(error, Exception)

    def test_all_errors_have_error_code(self):
        """Test that all errors have error_code attribute"""
        error_instances = [
            FileNotFoundError("/test"),
            FileTooLargeError(1.0, 0.5),
            InvalidFileFormatError(".txt", [".bin"]),
            BinaryParsingError("test"),
            DecompilationError("test"),
            YARAScanError("test"),
            DependencyMissingError("test"),
            ServiceUnavailableError("test"),
            ResourceLimitExceededError("test", "100"),
            MemoryLimitExceededError(1.0, 0.5),
            TimeoutError("test", 60),
            AuthenticationError(),
            AuthorizationError("/test"),
            AIServiceError("test", "test"),
            AnalysisError("test", "test"),
        ]

        for error in error_instances:
            assert hasattr(error, "error_code")
            assert error.error_code is not None
            assert len(error.error_code) > 0

    def test_all_errors_have_to_dict(self):
        """Test that all errors can be converted to dict"""
        error_instances = [
            FileNotFoundError("/test"),
            FileTooLargeError(1.0, 0.5),
            InvalidFileFormatError(".txt", [".bin"]),
        ]

        for error in error_instances:
            error_dict = error.to_dict()
            assert isinstance(error_dict, dict)
            assert "error" in error_dict
            assert "message" in error_dict


class TestErrorDocumentation:
    """Test that errors have proper documentation"""

    def test_errors_have_docs_urls(self):
        """Test that important errors have documentation URLs"""
        errors_with_docs = [
            FileNotFoundError("/test"),
            FileTooLargeError(1.0, 0.5),
            InvalidFileFormatError(".txt", [".bin"]),
            BinaryParsingError("test"),
            DecompilationError("test"),
        ]

        for error in errors_with_docs:
            assert error.docs_url is not None
            assert error.docs_url.startswith("https://docs.vragent.com")


class TestErrorUsageInAPI:
    """Test error usage in API context"""

    def test_error_to_dict_for_api_response(self):
        """Test converting error to dict for API response"""
        error = FileTooLargeError(6.5, 5.0)
        error_dict = error.to_dict()

        # Should have all fields needed for API response
        assert "error" in error_dict
        assert "message" in error_dict
        assert "solution" in error_dict
        assert "docs_url" in error_dict

        # Check values
        assert error_dict["error"] == "FILE_TOO_LARGE"
        assert "6.50GB" in error_dict["message"]

    def test_multiple_errors_consistent_format(self):
        """Test that different errors have consistent dict format"""
        errors = [
            FileNotFoundError("/test"),
            FileTooLargeError(1.0, 0.5),
            BinaryParsingError("test"),
        ]

        for error in errors:
            error_dict = error.to_dict()

            # All should have same keys
            assert set(error_dict.keys()) == {"error", "message", "solution", "docs_url"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
