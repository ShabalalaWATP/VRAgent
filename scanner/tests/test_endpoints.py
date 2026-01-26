from fastapi.testclient import TestClient

from scanner.server import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "healthy"
    assert "timestamp" in payload


def test_info_endpoint_reports_scanner():
    response = client.get("/info")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("scanner") == "VRAgent Scanner Sidecar"
    assert "capabilities" in payload
    assert isinstance(payload["capabilities"], dict)


def test_agent_planner_returns_reasoned_plan():
    payload = {
        "web_targets": [
            {"ip": "192.168.0.5", "port": 80, "service": "http", "url": "http://192.168.0.5"}
        ],
        "network_targets": [
            {"ip": "10.0.0.5", "port": 22, "service": "ssh", "nuclei_tags": ["ssh"]}
        ],
        "execute_scans": False,
    }

    response = client.post("/agent/plan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["plan"]["summary"]["total_actions"] == 4
    assert data["plan"]["summary"]["total_phases"] == 2
    assert data["launched_scans"] == []
