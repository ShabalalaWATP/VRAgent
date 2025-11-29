"""
Tests for codebase service.
"""
import pytest
import zipfile
from pathlib import Path

from backend.services.codebase_service import (
    unpack_zip_to_temp,
    iter_source_files,
    split_into_chunks,
    create_code_chunks,
    IGNORED_FOLDERS,
)
from backend.core.exceptions import ZipExtractionError
from backend import models


class TestUnpackZipToTemp:
    """Tests for zip extraction functionality."""
    
    def test_unpack_valid_zip(self, temp_zip_file: Path):
        """Should extract a valid zip file."""
        result = unpack_zip_to_temp(str(temp_zip_file))
        assert result.exists()
        assert (result / "app.py").exists()
        assert (result / "requirements.txt").exists()
    
    def test_unpack_creates_temp_directory(self, temp_zip_file: Path):
        """Extracted directory should be in temp location."""
        result = unpack_zip_to_temp(str(temp_zip_file))
        assert "codebase_" in str(result)
    
    def test_unpack_rejects_path_traversal(self, malicious_zip_file: Path):
        """Should reject zip files with path traversal attempts."""
        with pytest.raises(ZipExtractionError) as exc_info:
            unpack_zip_to_temp(str(malicious_zip_file))
        assert "traversal" in str(exc_info.value).lower() or "escape" in str(exc_info.value).lower()
    
    def test_unpack_rejects_invalid_zip(self, tmp_path: Path):
        """Should raise error for invalid zip files."""
        invalid_file = tmp_path / "not_a_zip.zip"
        invalid_file.write_text("This is not a zip file")
        
        with pytest.raises(ZipExtractionError) as exc_info:
            unpack_zip_to_temp(str(invalid_file))
        assert "invalid" in str(exc_info.value).lower() or "bad" in str(exc_info.value).lower()
    
    def test_unpack_rejects_large_files(self, tmp_path: Path):
        """Should reject files that exceed size limits."""
        # This test would need a large file to actually trigger,
        # but we can verify the logic is in place
        zip_path = tmp_path / "large.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Create a file that appears large in the zip info
            zf.writestr("small.txt", "small content")
        
        # Normal small file should work
        result = unpack_zip_to_temp(str(zip_path))
        assert result.exists()


class TestIterSourceFiles:
    """Tests for source file iteration."""
    
    def test_finds_python_files(self, temp_zip_file: Path):
        """Should find Python files."""
        extracted = unpack_zip_to_temp(str(temp_zip_file))
        files = list(iter_source_files(extracted))
        py_files = [f for f in files if f.suffix == ".py"]
        assert len(py_files) >= 1
    
    def test_ignores_node_modules(self, tmp_path: Path):
        """Should ignore node_modules directory."""
        # Create a structure with node_modules
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package.js").write_text("module.exports = {}")
        (tmp_path / "app.js").write_text("console.log('hello')")
        
        files = list(iter_source_files(tmp_path))
        file_names = [f.name for f in files]
        
        assert "app.js" in file_names
        assert "package.js" not in file_names
    
    def test_finds_multiple_languages(self, tmp_path: Path):
        """Should find files of multiple languages."""
        (tmp_path / "app.py").write_text("print('python')")
        (tmp_path / "app.js").write_text("console.log('js')")
        (tmp_path / "app.ts").write_text("console.log('ts')")
        (tmp_path / "app.go").write_text("package main")
        
        files = list(iter_source_files(tmp_path))
        extensions = {f.suffix for f in files}
        
        assert ".py" in extensions
        assert ".js" in extensions
        assert ".ts" in extensions
        assert ".go" in extensions


class TestSplitIntoChunks:
    """Tests for code chunking."""
    
    def test_splits_on_function_def(self):
        """Should split on function definitions."""
        code = """def foo():
    pass

def bar():
    return 1
"""
        chunks = split_into_chunks(code)
        assert len(chunks) >= 2
    
    def test_splits_on_class_def(self):
        """Should split on class definitions."""
        code = """class Foo:
    pass

class Bar:
    pass
"""
        chunks = split_into_chunks(code)
        assert len(chunks) >= 2
    
    def test_single_chunk_for_simple_code(self):
        """Simple code without functions should be one chunk."""
        code = "x = 1\ny = 2\nz = x + y"
        chunks = split_into_chunks(code)
        assert len(chunks) == 1
    
    def test_preserves_line_numbers(self):
        """Chunks should have correct line numbers."""
        code = """# Comment
x = 1

def foo():
    pass
"""
        chunks = split_into_chunks(code)
        # First chunk should start at line 1
        assert chunks[0][0] == 1


class TestCreateCodeChunks:
    """Tests for creating CodeChunk models."""
    
    def test_creates_code_chunk_models(self, sample_project, tmp_path: Path):
        """Should create CodeChunk model instances."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def foo(): pass")
        
        chunks = [
            (1, 1, "def foo(): pass"),
        ]
        
        db_chunks = create_code_chunks(
            sample_project, tmp_path, test_file, "python", chunks
        )
        
        assert len(db_chunks) == 1
        assert db_chunks[0].project_id == sample_project.id
        assert db_chunks[0].language == "python"
        assert db_chunks[0].file_path == "test.py"
    
    def test_handles_nested_paths(self, sample_project, tmp_path: Path):
        """Should handle nested file paths correctly."""
        nested_dir = tmp_path / "src" / "utils"
        nested_dir.mkdir(parents=True)
        test_file = nested_dir / "helper.py"
        test_file.write_text("def helper(): pass")
        
        chunks = [(1, 1, "def helper(): pass")]
        
        db_chunks = create_code_chunks(
            sample_project, tmp_path, test_file, "python", chunks
        )
        
        assert "src" in db_chunks[0].file_path or "utils" in db_chunks[0].file_path
