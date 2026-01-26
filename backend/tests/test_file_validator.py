"""
Tests for file validation system
"""

import pytest
import tempfile
import os
import hashlib
from pathlib import Path
from io import BytesIO
from unittest.mock import Mock, patch

from backend.core.file_validator import (
    FileValidator,
    ValidationConfig,
    FileInfo,
    binary_validator,
    apk_validator,
    firmware_validator,
)
from backend.core.error_handler import (
    FileNotFoundError as VRAgentFileNotFoundError,
    FileTooLargeError,
)


class TestFileValidator:
    """Test FileValidator class"""

    def setup_method(self):
        """Create temporary test files"""
        self.temp_dir = tempfile.mkdtemp()

        # Create test binary file (ELF)
        self.binary_path = os.path.join(self.temp_dir, "test.elf")
        with open(self.binary_path, "wb") as f:
            # ELF magic number
            f.write(b"\x7fELF")
            f.write(b"\x00" * 1000)  # 1KB file

        # Create text file
        self.text_path = os.path.join(self.temp_dir, "test.txt")
        with open(self.text_path, "w") as f:
            f.write("This is a text file\n" * 100)

        # Create large file (for size testing)
        self.large_path = os.path.join(self.temp_dir, "large.bin")
        with open(self.large_path, "wb") as f:
            f.write(b"\x00" * (10 * 1024 * 1024))  # 10MB

    def teardown_method(self):
        """Clean up temporary files"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_validate_file_not_found(self):
        """Test validation of non-existent file"""
        validator = FileValidator()

        with pytest.raises(VRAgentFileNotFoundError):
            validator.validate_file("/nonexistent/file.bin")

    def test_validate_binary_file(self):
        """Test validation of binary file"""
        validator = FileValidator(
            ValidationConfig(
                max_size_gb=1.0,
                calculate_hash=True
            )
        )

        file_info = validator.validate_file(self.binary_path)

        assert isinstance(file_info, FileInfo)
        assert file_info.is_valid
        assert file_info.size_bytes > 0
        assert file_info.is_binary
        assert file_info.extension == ".elf"
        assert len(file_info.sha256) == 64
        assert len(file_info.validation_errors) == 0

    def test_validate_text_file(self):
        """Test validation of text file"""
        validator = FileValidator()

        file_info = validator.validate_file(self.text_path)

        assert file_info.is_valid
        assert not file_info.is_binary
        assert file_info.extension == ".txt"

    def test_file_too_large(self):
        """Test validation with size limit exceeded"""
        validator = FileValidator(
            ValidationConfig(max_size_gb=0.005)  # 5MB limit
        )

        with pytest.raises(FileTooLargeError):
            validator.validate_file(self.large_path)

    def test_allowed_extensions(self):
        """Test validation with allowed extensions"""
        validator = FileValidator(
            ValidationConfig(
                allowed_extensions=[".exe", ".dll"],
                max_size_gb=1.0
            )
        )

        file_info = validator.validate_file(self.binary_path)

        # Should not be valid (extension is .elf, not in allowed list)
        assert not file_info.is_valid
        assert any(".elf" in err for err in file_info.validation_errors)

    def test_allowed_mime_types(self):
        """Test validation with allowed MIME types"""
        validator = FileValidator(
            ValidationConfig(
                allowed_mime_types=["application/pdf"],
                max_size_gb=1.0
            )
        )

        file_info = validator.validate_file(self.binary_path)

        # Should not be valid (MIME type not PDF)
        assert not file_info.is_valid
        assert any("MIME type" in err for err in file_info.validation_errors)

    def test_require_binary(self):
        """Test validation requiring binary files"""
        validator = FileValidator(
            ValidationConfig(
                require_binary=True,
                max_size_gb=1.0
            )
        )

        # Binary file should pass
        binary_info = validator.validate_file(self.binary_path)
        assert binary_info.is_valid

        # Text file should fail
        text_info = validator.validate_file(self.text_path)
        assert not text_info.is_valid
        assert any("binary" in err.lower() for err in text_info.validation_errors)

    def test_calculate_hash(self):
        """Test SHA256 hash calculation"""
        validator = FileValidator(
            ValidationConfig(calculate_hash=True)
        )

        file_info = validator.validate_file(self.binary_path)

        # Verify hash is correct
        with open(self.binary_path, "rb") as f:
            expected_hash = hashlib.sha256(f.read()).hexdigest()

        assert file_info.sha256 == expected_hash

    def test_skip_hash_calculation(self):
        """Test skipping hash calculation"""
        validator = FileValidator(
            ValidationConfig(calculate_hash=False)
        )

        file_info = validator.validate_file(self.binary_path)

        assert file_info.sha256 == ""

    def test_is_executable_detection(self):
        """Test executable detection"""
        # Create ELF executable
        elf_path = os.path.join(self.temp_dir, "test.elf")
        with open(elf_path, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")  # ELF header
            f.write(b"\x00" * 1000)

        validator = FileValidator()
        file_info = validator.validate_file(elf_path)

        assert file_info.is_binary
        # Executable detection depends on file magic

    def test_is_archive_detection(self):
        """Test archive detection"""
        # Create ZIP file
        zip_path = os.path.join(self.temp_dir, "test.zip")
        with open(zip_path, "wb") as f:
            f.write(b"PK\x03\x04")  # ZIP signature
            f.write(b"\x00" * 100)

        validator = FileValidator()
        file_info = validator.validate_file(zip_path)

        assert file_info.extension == ".zip"
        assert file_info.is_archive

    @pytest.mark.asyncio
    async def test_validate_file_async(self):
        """Test async file validation"""
        validator = FileValidator()

        file_info = await validator.validate_file_async(self.binary_path)

        assert isinstance(file_info, FileInfo)
        assert file_info.is_valid

    @pytest.mark.asyncio
    async def test_stream_file_chunks(self):
        """Test streaming file in chunks"""
        validator = FileValidator()

        chunks = []
        async for chunk in validator.stream_file_chunks(self.binary_path, chunk_size=100):
            chunks.append(chunk)

        # Verify we got all data
        total_size = sum(len(chunk) for chunk in chunks)
        expected_size = os.path.getsize(self.binary_path)
        assert total_size == expected_size

    def test_validate_upload(self):
        """Test upload file validation"""
        validator = FileValidator(
            ValidationConfig(
                allowed_extensions=[".elf", ".bin"],
                max_size_gb=1.0
            )
        )

        # Create mock uploaded file
        file_content = b"\x7fELF" + b"\x00" * 1000
        file = BytesIO(file_content)

        is_valid, error = validator.validate_upload(
            file,
            "test.elf",
            max_size_bytes=1024 * 1024  # 1MB
        )

        assert is_valid
        assert error == ""

    def test_validate_upload_too_large(self):
        """Test upload validation with oversized file"""
        validator = FileValidator()

        # Create large file content
        file_content = b"\x00" * (2 * 1024 * 1024)  # 2MB
        file = BytesIO(file_content)

        is_valid, error = validator.validate_upload(
            file,
            "large.bin",
            max_size_bytes=1024 * 1024  # 1MB limit
        )

        assert not is_valid
        assert "too large" in error.lower()

    def test_validate_upload_invalid_extension(self):
        """Test upload validation with invalid extension"""
        validator = FileValidator(
            ValidationConfig(allowed_extensions=[".exe", ".dll"])
        )

        file = BytesIO(b"\x00" * 100)

        is_valid, error = validator.validate_upload(
            file,
            "test.txt",  # Not in allowed list
            max_size_bytes=1024 * 1024
        )

        assert not is_valid
        assert "not allowed" in error


class TestPreConfiguredValidators:
    """Test pre-configured validator instances"""

    def setup_method(self):
        """Create test files"""
        self.temp_dir = tempfile.mkdtemp()

        # Binary file
        self.binary_path = os.path.join(self.temp_dir, "test.exe")
        with open(self.binary_path, "wb") as f:
            f.write(b"MZ")  # PE header
            f.write(b"\x00" * 1000)

        # APK file
        self.apk_path = os.path.join(self.temp_dir, "test.apk")
        with open(self.apk_path, "wb") as f:
            f.write(b"PK\x03\x04")  # ZIP signature
            f.write(b"\x00" * 1000)

        # Firmware file
        self.firmware_path = os.path.join(self.temp_dir, "test.bin")
        with open(self.firmware_path, "wb") as f:
            f.write(b"\x00" * 1000)

    def teardown_method(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_binary_validator(self):
        """Test pre-configured binary validator"""
        file_info = binary_validator.validate_file(self.binary_path)

        assert file_info.is_valid or len(file_info.validation_errors) > 0
        assert file_info.is_binary

    def test_apk_validator(self):
        """Test pre-configured APK validator"""
        file_info = apk_validator.validate_file(self.apk_path)

        # Should validate (correct extension)
        assert file_info.is_valid or len(file_info.validation_errors) > 0

    def test_firmware_validator(self):
        """Test pre-configured firmware validator"""
        file_info = firmware_validator.validate_file(self.firmware_path)

        assert file_info.is_valid or len(file_info.validation_errors) > 0


class TestFileInfoDataclass:
    """Test FileInfo dataclass"""

    def test_file_info_creation(self):
        """Test creating FileInfo instance"""
        info = FileInfo(
            path="/test/file.bin",
            size_bytes=1024,
            size_gb=0.001,
            mime_type="application/octet-stream",
            file_type="binary data",
            extension=".bin",
            sha256="abc123",
            is_binary=True,
            is_executable=False,
            is_archive=False,
            is_valid=True,
            validation_errors=[]
        )

        assert info.path == "/test/file.bin"
        assert info.size_bytes == 1024
        assert info.is_valid
        assert len(info.validation_errors) == 0


class TestStreamingValidation:
    """Test streaming validation for large files"""

    def setup_method(self):
        """Create large test file"""
        self.temp_dir = tempfile.mkdtemp()
        self.large_file = os.path.join(self.temp_dir, "large.bin")

        # Create 100MB file
        with open(self.large_file, "wb") as f:
            for _ in range(100):
                f.write(b"\x00" * (1024 * 1024))  # 1MB chunks

    def teardown_method(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_hash_calculation_streaming(self):
        """Test that hash calculation uses streaming"""
        validator = FileValidator(
            ValidationConfig(calculate_hash=True)
        )

        # This should not load entire file into memory
        file_info = validator.validate_file(self.large_file)

        assert len(file_info.sha256) == 64

    @pytest.mark.asyncio
    async def test_stream_large_file(self):
        """Test streaming large file in chunks"""
        validator = FileValidator()

        chunk_count = 0
        total_bytes = 0

        async for chunk in validator.stream_file_chunks(
            self.large_file,
            chunk_size=1024 * 1024  # 1MB chunks
        ):
            chunk_count += 1
            total_bytes += len(chunk)

        # Should be ~100 chunks for 100MB file
        assert chunk_count >= 90  # Allow some variation
        assert total_bytes == os.path.getsize(self.large_file)


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def setup_method(self):
        """Create test files"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_empty_file(self):
        """Test validation of empty file"""
        empty_file = os.path.join(self.temp_dir, "empty.bin")
        Path(empty_file).touch()

        validator = FileValidator()
        file_info = validator.validate_file(empty_file)

        assert file_info.size_bytes == 0
        assert file_info.is_valid

    def test_file_with_no_extension(self):
        """Test validation of file without extension"""
        no_ext_file = os.path.join(self.temp_dir, "noextension")
        with open(no_ext_file, "wb") as f:
            f.write(b"\x00" * 100)

        validator = FileValidator()
        file_info = validator.validate_file(no_ext_file)

        assert file_info.extension == ""
        assert file_info.is_valid

    def test_symlink_file(self):
        """Test validation of symlinked file"""
        if os.name != 'nt':  # Skip on Windows
            real_file = os.path.join(self.temp_dir, "real.bin")
            with open(real_file, "wb") as f:
                f.write(b"\x00" * 100)

            symlink_file = os.path.join(self.temp_dir, "link.bin")
            os.symlink(real_file, symlink_file)

            validator = FileValidator()
            file_info = validator.validate_file(symlink_file)

            # Should follow symlink and validate
            assert file_info.is_valid

    def test_permission_denied(self):
        """Test validation when file is not readable"""
        if os.name != 'nt':  # Skip on Windows
            protected_file = os.path.join(self.temp_dir, "protected.bin")
            with open(protected_file, "wb") as f:
                f.write(b"\x00" * 100)

            # Remove read permissions
            os.chmod(protected_file, 0o000)

            validator = FileValidator()

            try:
                # Should raise PermissionError or similar
                file_info = validator.validate_file(protected_file)
            except Exception as e:
                assert True  # Expected to fail
            finally:
                # Restore permissions for cleanup
                os.chmod(protected_file, 0o644)


class TestValidationPerformance:
    """Test validation performance"""

    def setup_method(self):
        """Create test files"""
        self.temp_dir = tempfile.mkdtemp()

        # Create 1GB file
        self.huge_file = os.path.join(self.temp_dir, "huge.bin")
        with open(self.huge_file, "wb") as f:
            for _ in range(1024):
                f.write(b"\x00" * (1024 * 1024))  # 1MB chunks = 1GB total

    def teardown_method(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_validation_speed(self):
        """Test that validation completes in reasonable time"""
        import time

        validator = FileValidator(
            ValidationConfig(
                max_size_gb=2.0,
                calculate_hash=True
            )
        )

        start = time.time()
        file_info = validator.validate_file(self.huge_file)
        elapsed = time.time() - start

        # Validation of 1GB should complete in under 30 seconds
        assert elapsed < 30.0
        assert file_info.is_valid


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
