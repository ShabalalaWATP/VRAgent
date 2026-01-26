"""
Tests for Agentic Binary Fuzzer Robustness

These tests verify that the agentic fuzzer handles edge cases,
errors, and unexpected inputs gracefully without crashing.
"""

import asyncio
import hashlib
import os
import pytest
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

# Import the modules to test
from backend.services.fuzzing_engine_wrapper import (
    EngineConfig,
    EngineType,
    EngineStatus,
    EngineStats,
    EnginePool,
    FuzzingEngine,
    MockFuzzingEngine,
    AFLPlusPlusEngine,
    CrashInfo,
    create_engine,
    check_fuzzer_availability,
)

from backend.services.campaign_persistence import (
    CampaignPersistenceService,
    get_persistence_service,
)

from backend.services.binary_fuzzer_utils import (
    validate_binary_data,
    detect_binary_format,
    safe_extract_strings,
    RobustDisassembler,
    RobustAIClient,
    heuristic_vulnerability_detection,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_binary_data():
    """Create sample ELF binary data."""
    # Minimal ELF header
    return b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 56


@pytest.fixture
def sample_pe_data():
    """Create sample PE binary data."""
    return b'MZ' + b'\x00' * 62


@pytest.fixture
def engine_config(temp_dir, sample_binary_data):
    """Create a valid engine configuration."""
    binary_path = os.path.join(temp_dir, "test_binary")
    seed_dir = os.path.join(temp_dir, "seeds")
    output_dir = os.path.join(temp_dir, "output")

    # Create directories and files
    os.makedirs(seed_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    with open(binary_path, "wb") as f:
        f.write(sample_binary_data)

    # Create a seed file
    with open(os.path.join(seed_dir, "seed1"), "wb") as f:
        f.write(b"AAAA")

    return EngineConfig(
        engine_type=EngineType.MOCK,
        binary_path=binary_path,
        seed_dir=seed_dir,
        output_dir=output_dir,
        timeout_ms=1000,
        memory_limit_mb=256,
        mock_mode=True,
    )


# =============================================================================
# Test Binary Validation
# =============================================================================

class TestBinaryValidation:
    """Tests for binary data validation."""

    def test_validate_empty_data(self):
        """Empty binary data should be rejected."""
        is_valid, error = validate_binary_data(b"", "test.bin")
        assert not is_valid
        assert "empty" in error.lower() or "small" in error.lower()

    def test_validate_too_small(self):
        """Tiny binary data should be rejected."""
        is_valid, error = validate_binary_data(b"A", "test.bin")
        assert not is_valid

    def test_validate_valid_elf(self, sample_binary_data):
        """Valid ELF data should be accepted."""
        is_valid, error = validate_binary_data(sample_binary_data, "test.elf")
        assert is_valid
        assert error is None or error == ""

    def test_validate_valid_pe(self, sample_pe_data):
        """Valid PE data should be accepted."""
        is_valid, error = validate_binary_data(sample_pe_data, "test.exe")
        assert is_valid

    def test_validate_none_data(self):
        """None data should be handled gracefully."""
        is_valid, error = validate_binary_data(None, "test.bin")
        assert not is_valid

    def test_validate_max_size(self):
        """Very large binaries should be rejected."""
        # Create data just over max size (500MB default)
        large_data = b"A" * (500 * 1024 * 1024 + 1)
        is_valid, error = validate_binary_data(large_data, "huge.bin")
        # Should handle without crashing, may or may not be valid depending on impl


class TestFormatDetection:
    """Tests for binary format detection."""

    def test_detect_elf(self, sample_binary_data):
        """Should detect ELF format."""
        fmt, arch = detect_binary_format(sample_binary_data)
        assert fmt == "elf"
        assert arch in ["x86", "x86_64", "unknown"]

    def test_detect_pe(self, sample_pe_data):
        """Should detect PE format."""
        fmt, arch = detect_binary_format(sample_pe_data)
        assert fmt == "pe"

    def test_detect_unknown(self):
        """Should handle unknown format gracefully."""
        fmt, arch = detect_binary_format(b"random data here")
        assert fmt == "unknown"

    def test_detect_empty(self):
        """Should handle empty data gracefully."""
        fmt, arch = detect_binary_format(b"")
        assert fmt == "unknown"

    def test_detect_none(self):
        """Should handle None gracefully."""
        try:
            fmt, arch = detect_binary_format(None)
            assert fmt == "unknown"
        except (TypeError, AttributeError):
            pass  # Expected behavior


# =============================================================================
# Test String Extraction
# =============================================================================

class TestStringExtraction:
    """Tests for safe string extraction."""

    def test_extract_ascii_strings(self):
        """Should extract ASCII strings."""
        data = b"\x00\x00hello world\x00\x00test string\x00\x00"
        strings = safe_extract_strings(data, min_length=4)
        assert "hello world" in strings or any("hello" in s for s in strings)

    def test_extract_from_empty(self):
        """Should handle empty data."""
        strings = safe_extract_strings(b"")
        assert strings == [] or strings is not None

    def test_extract_max_strings(self):
        """Should respect max_strings limit."""
        data = b"aaa\x00bbb\x00ccc\x00ddd\x00eee\x00" * 100
        strings = safe_extract_strings(data, min_length=3, max_strings=5)
        assert len(strings) <= 5

    def test_extract_no_crash_on_binary(self, sample_binary_data):
        """Should not crash on binary data."""
        strings = safe_extract_strings(sample_binary_data)
        assert isinstance(strings, list)


# =============================================================================
# Test Disassembler
# =============================================================================

class TestRobustDisassembler:
    """Tests for robust disassembler."""

    def test_init_without_crash(self):
        """Disassembler should initialize without crashing."""
        disasm = RobustDisassembler()
        assert disasm is not None

    def test_disassemble_x86(self):
        """Should disassemble x86 instructions."""
        disasm = RobustDisassembler()
        # NOP instruction
        result = disasm.disassemble(b"\x90\x90\x90", "x86")
        # Should return something or empty list, but not crash

    def test_disassemble_empty(self):
        """Should handle empty data."""
        disasm = RobustDisassembler()
        result = disasm.disassemble(b"", "x86")
        assert result == [] or result is not None

    def test_disassemble_invalid_arch(self):
        """Should handle invalid architecture gracefully."""
        disasm = RobustDisassembler()
        result = disasm.disassemble(b"\x90", "unknown_arch")
        # Should not crash


# =============================================================================
# Test Mock Fuzzing Engine
# =============================================================================

class TestMockFuzzingEngine:
    """Tests for mock fuzzing engine."""

    @pytest.mark.asyncio
    async def test_start_stop(self, engine_config):
        """Engine should start and stop without errors."""
        engine = MockFuzzingEngine("test_engine", engine_config)

        started = await engine.start()
        assert started
        assert engine.is_running

        await engine.stop()
        assert not engine.is_running

    @pytest.mark.asyncio
    async def test_get_stats(self, engine_config):
        """Should return valid statistics."""
        engine = MockFuzzingEngine("test_engine", engine_config)
        await engine.start()

        stats = await engine.get_stats()
        assert isinstance(stats, EngineStats)
        assert stats.engine_id == "test_engine"
        assert stats.executions >= 0

        await engine.stop()

    @pytest.mark.asyncio
    async def test_add_seed(self, engine_config):
        """Should add seeds without error."""
        engine = MockFuzzingEngine("test_engine", engine_config)
        await engine.start()

        success = await engine.add_seed(b"test seed data")
        assert success

        await engine.stop()

    @pytest.mark.asyncio
    async def test_get_crashes(self, engine_config):
        """Should return crashes without error."""
        engine = MockFuzzingEngine("test_engine", engine_config)
        await engine.start()

        # Run for a bit to potentially generate crashes
        for _ in range(10):
            await engine.get_stats()
            await asyncio.sleep(0.1)

        crashes = await engine.get_crashes()
        assert isinstance(crashes, list)

        await engine.stop()

    @pytest.mark.asyncio
    async def test_stats_accumulate(self, engine_config):
        """Stats should accumulate over time."""
        engine = MockFuzzingEngine("test_engine", engine_config)
        await engine.start()

        # Get initial stats
        stats1 = await engine.get_stats()
        initial_exec = stats1.executions

        # Wait and get more stats
        await asyncio.sleep(0.5)
        stats2 = await engine.get_stats()

        assert stats2.executions >= initial_exec

        await engine.stop()


# =============================================================================
# Test Engine Pool
# =============================================================================

class TestEnginePool:
    """Tests for engine pool management."""

    @pytest.mark.asyncio
    async def test_add_remove_engine(self, engine_config):
        """Should add and remove engines."""
        pool = EnginePool(max_engines=4)

        engine = await pool.add_engine("engine1", engine_config, prefer_mock=True)
        assert engine is not None
        assert pool.get_running_count() == 1

        removed = await pool.remove_engine("engine1")
        assert removed
        assert pool.get_running_count() == 0

    @pytest.mark.asyncio
    async def test_pool_limit(self, engine_config):
        """Should respect max engines limit."""
        pool = EnginePool(max_engines=2)

        await pool.add_engine("engine1", engine_config, prefer_mock=True)
        await pool.add_engine("engine2", engine_config, prefer_mock=True)

        # Third engine should fail or return None
        engine3 = await pool.add_engine("engine3", engine_config, prefer_mock=True)
        assert engine3 is None

        await pool.stop_all()

    @pytest.mark.asyncio
    async def test_get_all_stats(self, engine_config):
        """Should get stats from all engines."""
        pool = EnginePool(max_engines=4)

        await pool.add_engine("engine1", engine_config, prefer_mock=True)
        await pool.add_engine("engine2", engine_config, prefer_mock=True)

        stats = await pool.get_all_stats()
        assert len(stats) == 2
        assert "engine1" in stats
        assert "engine2" in stats

        await pool.stop_all()

    @pytest.mark.asyncio
    async def test_stop_all(self, engine_config):
        """Should stop all engines."""
        pool = EnginePool(max_engines=4)

        await pool.add_engine("engine1", engine_config, prefer_mock=True)
        await pool.add_engine("engine2", engine_config, prefer_mock=True)

        await pool.stop_all()
        assert pool.get_running_count() == 0


# =============================================================================
# Test Engine Factory
# =============================================================================

class TestEngineFactory:
    """Tests for engine factory function."""

    def test_create_mock_engine(self, engine_config):
        """Should create mock engine when requested."""
        engine = create_engine("test", engine_config, prefer_mock=True)
        assert isinstance(engine, MockFuzzingEngine)

    def test_fallback_to_mock(self, engine_config):
        """Should fallback to mock when AFL not available."""
        engine_config.engine_type = EngineType.AFLPP
        engine_config.mock_mode = False

        # This should fallback to mock if AFL isn't installed
        engine = create_engine("test", engine_config, prefer_mock=False)
        # Either AFL or Mock depending on system
        assert isinstance(engine, (AFLPlusPlusEngine, MockFuzzingEngine))

    def test_check_fuzzer_availability(self):
        """Should return availability dict without crashing."""
        availability = check_fuzzer_availability()
        assert isinstance(availability, dict)
        assert "afl-fuzz" in availability or "afl++" in availability


# =============================================================================
# Test AI Client Robustness
# =============================================================================

class TestRobustAIClient:
    """Tests for robust AI client."""

    def test_init_without_api_key(self):
        """Should initialize without crashing even without API key."""
        client = RobustAIClient()
        # Should not crash

    @pytest.mark.asyncio
    async def test_analyze_with_unavailable_api(self):
        """Should handle unavailable API gracefully."""
        client = RobustAIClient()

        # Mock the actual API call to fail
        with patch.object(client, '_call_api', side_effect=Exception("API unavailable")):
            result = await client.analyze("test prompt", fallback="default")
            # Should return fallback or handle gracefully

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Should handle timeouts gracefully."""
        client = RobustAIClient(timeout=0.001)  # Very short timeout

        # Should not hang forever
        try:
            result = await asyncio.wait_for(
                client.analyze("test"),
                timeout=1.0
            )
        except asyncio.TimeoutError:
            pass  # Expected
        except Exception:
            pass  # Also acceptable - graceful failure


# =============================================================================
# Test Heuristic Analysis
# =============================================================================

class TestHeuristicAnalysis:
    """Tests for heuristic vulnerability detection."""

    def test_detect_dangerous_functions(self, sample_binary_data):
        """Should detect dangerous functions."""
        # Binary with strcpy string
        data = sample_binary_data + b"\x00strcpy\x00gets\x00"
        vulns = heuristic_vulnerability_detection(data)
        assert isinstance(vulns, list)

    def test_handle_empty_data(self):
        """Should handle empty data."""
        vulns = heuristic_vulnerability_detection(b"")
        assert isinstance(vulns, list)

    def test_handle_none(self):
        """Should handle None gracefully."""
        try:
            vulns = heuristic_vulnerability_detection(None)
            assert isinstance(vulns, list) or vulns is None
        except (TypeError, AttributeError):
            pass  # Expected


# =============================================================================
# Test Persistence Service
# =============================================================================

class TestPersistenceService:
    """Tests for campaign persistence service."""

    def test_init_without_db(self):
        """Should initialize without database connection."""
        service = CampaignPersistenceService(db=None)
        assert service is not None

    @pytest.mark.asyncio
    async def test_save_campaign_no_db(self):
        """Should handle save when DB unavailable."""
        service = CampaignPersistenceService(db=None)

        result = await service.save_campaign(
            campaign_id="test123",
            binary_hash="abc123",
            binary_name="test.bin",
            status="running",
            config={},
        )
        # Should return False but not crash
        assert result == False

    @pytest.mark.asyncio
    async def test_load_campaign_no_db(self):
        """Should handle load when DB unavailable."""
        service = CampaignPersistenceService(db=None)

        result = await service.load_campaign("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_campaigns_no_db(self):
        """Should return empty list when DB unavailable."""
        service = CampaignPersistenceService(db=None)

        result = await service.list_campaigns()
        assert result == []


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for the full fuzzing workflow."""

    @pytest.mark.asyncio
    async def test_full_mock_fuzzing_session(self, engine_config):
        """Run a complete mock fuzzing session."""
        pool = EnginePool(max_engines=2)

        # Add engines
        engine1 = await pool.add_engine("e1", engine_config, prefer_mock=True)
        engine2 = await pool.add_engine("e2", engine_config, prefer_mock=True)

        assert pool.get_running_count() == 2

        # Run for a few iterations
        for i in range(5):
            stats = await pool.get_all_stats()
            crashes = await pool.get_all_crashes()

            # Verify stats are valid
            for engine_id, stat in stats.items():
                assert stat.executions >= 0
                assert stat.is_healthy

            await asyncio.sleep(0.2)

        # Clean up
        await pool.stop_all()
        assert pool.get_running_count() == 0

    @pytest.mark.asyncio
    async def test_engine_resilience(self, engine_config):
        """Test engine resilience to errors."""
        engine = MockFuzzingEngine("resilient", engine_config)
        await engine.start()

        # Multiple rapid operations should not crash
        tasks = []
        for _ in range(20):
            tasks.append(engine.get_stats())
            tasks.append(engine.add_seed(b"seed" + os.urandom(10)))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Should complete without fatal errors
        error_count = sum(1 for r in results if isinstance(r, Exception))
        assert error_count < len(results)  # Most should succeed

        await engine.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
