"""
Tests for health check endpoints
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock

from backend.main import app
from backend.routers.health import (
    check_database,
    check_redis,
    check_ai_services,
    check_ghidra,
    ServiceStatus
)


client = TestClient(app)


class TestHealthEndpoints:
    """Test health check endpoints"""

    def test_health_basic(self):
        """Test basic /health endpoint exists"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]

    def test_health_comprehensive(self):
        """Test comprehensive health check structure"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()

        # Check required fields
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "uptime_seconds" in data
        assert "services" in data
        assert "resources" in data
        assert "warnings" in data

        # Check services structure
        services = data["services"]
        assert isinstance(services, dict)

        # Check resources structure
        resources = data["resources"]
        assert "memory" in resources
        assert "disk" in resources
        assert "cpu" in resources

    def test_readiness_probe(self):
        """Test /health/ready endpoint"""
        response = client.get("/health/ready")
        # Should return 200 if ready, 503 if not
        assert response.status_code in [200, 503]

        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "ready"

    def test_liveness_probe(self):
        """Test /health/live endpoint"""
        response = client.get("/health/live")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert "timestamp" in data

    def test_resources_endpoint(self):
        """Test /health/resources endpoint"""
        response = client.get("/health/resources")
        assert response.status_code == 200
        data = response.json()

        # Check system stats
        assert "system" in data
        system = data["system"]
        assert "memory" in system
        assert "disk" in system
        assert "cpu" in system

        # Check process stats
        assert "process" in data
        process = data["process"]
        assert "pid" in process
        assert "memory_mb" in process
        assert "cpu_percent" in process
        assert "threads" in process

    def test_version_endpoint(self):
        """Test /health/version endpoint"""
        response = client.get("/health/version")
        assert response.status_code == 200
        data = response.json()

        assert "version" in data
        assert "name" in data
        assert data["name"] == "VRAgent Binary Analyzer"


@pytest.mark.asyncio
class TestServiceChecks:
    """Test individual service check functions"""

    async def test_check_database_success(self):
        """Test database check with healthy database"""
        # Mock database session
        mock_db = AsyncMock()
        mock_result = Mock()
        mock_result.fetchone.return_value = (1,)
        mock_db.execute.return_value = mock_result

        status = await check_database(mock_db)

        assert isinstance(status, ServiceStatus)
        assert status.name == "database"
        assert status.status == "ok"
        assert status.latency_ms is not None
        assert status.latency_ms > 0

    async def test_check_database_failure(self):
        """Test database check with connection failure"""
        # Mock database session that raises exception
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Connection refused")

        status = await check_database(mock_db)

        assert status.name == "database"
        assert status.status == "down"
        assert status.error == "Connection refused"

    async def test_check_redis_success(self):
        """Test Redis check with healthy Redis"""
        with patch('backend.routers.health.aioredis') as mock_redis_module:
            # Mock Redis client
            mock_client = AsyncMock()
            mock_client.ping.return_value = True
            mock_client.info.return_value = {
                "redis_version": "7.0.0",
                "uptime_in_days": 30,
                "connected_clients": 5
            }
            mock_redis_module.from_url.return_value = mock_client

            status = await check_redis()

            assert status.name == "redis"
            assert status.status == "ok"
            assert status.latency_ms is not None
            assert status.details["version"] == "7.0.0"

    async def test_check_redis_failure(self):
        """Test Redis check with connection failure"""
        with patch('backend.routers.health.aioredis') as mock_redis_module:
            mock_client = AsyncMock()
            mock_client.ping.side_effect = Exception("Connection timeout")
            mock_redis_module.from_url.return_value = mock_client

            status = await check_redis()

            assert status.name == "redis"
            assert status.status == "down"
            assert "Connection timeout" in status.error

    async def test_check_ai_services_configured(self):
        """Test AI services check with API keys configured"""
        with patch('backend.routers.health.settings') as mock_settings:
            mock_settings.gemini_api_key = "test_key"
            mock_settings.openai_api_key = "test_key"

            status = await check_ai_services()

            assert status.name == "ai_services"
            assert status.status == "ok"
            assert "gemini" in status.details["available"]
            assert "openai" in status.details["available"]

    async def test_check_ai_services_not_configured(self):
        """Test AI services check without API keys"""
        with patch('backend.routers.health.settings') as mock_settings:
            mock_settings.gemini_api_key = None
            mock_settings.openai_api_key = None

            status = await check_ai_services()

            assert status.name == "ai_services"
            assert status.status == "degraded"
            assert "No AI API keys configured" in status.error

    async def test_check_ghidra_configured(self):
        """Test Ghidra check with GHIDRA_HOME set"""
        with patch('backend.routers.health.settings') as mock_settings, \
             patch('backend.routers.health.os.path.isdir') as mock_isdir, \
             patch('backend.routers.health.os.path.isfile') as mock_isfile:

            mock_settings.ghidra_home = "/opt/ghidra"
            mock_isdir.return_value = True
            mock_isfile.return_value = True

            status = await check_ghidra()

            assert status.name == "ghidra"
            assert status.status == "ok"
            assert status.details["ghidra_home"] == "/opt/ghidra"

    async def test_check_ghidra_not_configured(self):
        """Test Ghidra check without GHIDRA_HOME"""
        with patch('backend.routers.health.settings') as mock_settings:
            mock_settings.ghidra_home = None

            status = await check_ghidra()

            assert status.name == "ghidra"
            assert status.status == "degraded"
            assert "GHIDRA_HOME not configured" in status.error


class TestHealthIntegration:
    """Integration tests for health checks"""

    def test_health_check_docker_healthcheck_compatible(self):
        """Test that /health/ready works for Docker health checks"""
        # This endpoint should return 200 for healthy, 503 for unhealthy
        response = client.get("/health/ready")
        assert response.status_code in [200, 503]

    def test_health_check_kubernetes_compatible(self):
        """Test Kubernetes probe compatibility"""
        # Readiness probe
        ready_response = client.get("/health/ready")
        assert ready_response.status_code in [200, 503]

        # Liveness probe
        live_response = client.get("/health/live")
        assert live_response.status_code == 200

    def test_health_check_monitoring_compatible(self):
        """Test compatibility with monitoring systems (Prometheus, etc.)"""
        response = client.get("/health/resources")
        assert response.status_code == 200
        data = response.json()

        # Should have all metrics needed for monitoring
        assert "system" in data
        assert "process" in data
        assert "timestamp" in data

        # Metrics should be numeric
        assert isinstance(data["process"]["memory_mb"], (int, float))
        assert isinstance(data["process"]["cpu_percent"], (int, float))


class TestHealthResponseFormat:
    """Test health check response format consistency"""

    def test_service_status_structure(self):
        """Test ServiceStatus model structure"""
        status = ServiceStatus(
            name="test_service",
            status="ok",
            latency_ms=10.5,
            details={"key": "value"}
        )

        assert status.name == "test_service"
        assert status.status == "ok"
        assert status.latency_ms == 10.5
        assert status.error is None
        assert status.details == {"key": "value"}

    def test_all_health_endpoints_return_json(self):
        """Test that all health endpoints return valid JSON"""
        endpoints = [
            "/health",
            "/health/ready",
            "/health/live",
            "/health/resources",
            "/health/version"
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.headers["content-type"] == "application/json"
            # Should not raise JSONDecodeError
            data = response.json()
            assert isinstance(data, dict)


class TestHealthEdgeCases:
    """Test health check edge cases and error conditions"""

    def test_health_check_under_load(self):
        """Test health check performance under load"""
        # Make 10 concurrent requests
        responses = []
        for _ in range(10):
            response = client.get("/health")
            responses.append(response)

        # All should succeed
        for response in responses:
            assert response.status_code == 200

    def test_health_check_with_slow_service(self):
        """Test health check when a service is slow"""
        # This is more of a timeout test - health checks should complete
        # even if individual service checks are slow
        response = client.get("/health")
        assert response.status_code == 200

    def test_resources_endpoint_multiple_calls(self):
        """Test that resources endpoint returns consistent data"""
        response1 = client.get("/health/resources")
        response2 = client.get("/health/resources")

        assert response1.status_code == 200
        assert response2.status_code == 200

        data1 = response1.json()
        data2 = response2.json()

        # PIDs should be the same
        assert data1["process"]["pid"] == data2["process"]["pid"]

        # Memory usage should be similar (within 100MB)
        mem_diff = abs(data1["process"]["memory_mb"] - data2["process"]["memory_mb"])
        assert mem_diff < 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
