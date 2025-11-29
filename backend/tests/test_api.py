"""
Tests for API endpoints.
"""
import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Tests for the health check endpoint."""
    
    def test_health_returns_ok(self, client: TestClient):
        """Health endpoint should return OK status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "environment" in data


class TestProjectsAPI:
    """Tests for project endpoints."""
    
    def test_create_project(self, client: TestClient):
        """Should create a new project."""
        response = client.post(
            "/projects",
            json={"name": "New Test Project", "description": "Test description"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "New Test Project"
        assert data["description"] == "Test description"
        assert "id" in data
    
    def test_create_project_minimal(self, client: TestClient):
        """Should create project with just name."""
        response = client.post("/projects", json={"name": "Minimal Project"})
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Minimal Project"
    
    def test_get_projects_empty(self, client: TestClient):
        """Should return empty list when no projects exist."""
        response = client.get("/projects")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_get_project(self, client: TestClient, sample_project):
        """Should return a specific project."""
        response = client.get(f"/projects/{sample_project.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_project.id
        assert data["name"] == sample_project.name
    
    def test_get_project_not_found(self, client: TestClient):
        """Should return 404 for non-existent project."""
        response = client.get("/projects/99999")
        assert response.status_code == 404


class TestReportsAPI:
    """Tests for report endpoints."""
    
    def test_get_report(self, client: TestClient, sample_report):
        """Should return a specific report."""
        response = client.get(f"/reports/{sample_report.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == sample_report.id
        assert data["title"] == sample_report.title
    
    def test_get_report_not_found(self, client: TestClient):
        """Should return 404 for non-existent report."""
        response = client.get("/reports/99999")
        assert response.status_code == 404
    
    def test_get_report_findings(self, client: TestClient, sample_report, sample_findings):
        """Should return findings for a report."""
        response = client.get(f"/reports/{sample_report.id}/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2


class TestExportsAPI:
    """Tests for report export endpoints."""
    
    def test_export_markdown(self, client: TestClient, sample_report, sample_findings):
        """Should export report as markdown."""
        response = client.get(f"/reports/{sample_report.id}/export/markdown")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/markdown; charset=utf-8"
        content = response.text
        assert sample_report.title in content
        assert "## Findings" in content
    
    def test_export_pdf(self, client: TestClient, sample_report, sample_findings):
        """Should export report as PDF."""
        response = client.get(f"/reports/{sample_report.id}/export/pdf")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert len(response.content) > 0
    
    def test_export_docx(self, client: TestClient, sample_report, sample_findings):
        """Should export report as DOCX."""
        response = client.get(f"/reports/{sample_report.id}/export/docx")
        assert response.status_code == 200
        assert "wordprocessingml" in response.headers["content-type"]
        assert len(response.content) > 0
    
    def test_export_not_found(self, client: TestClient):
        """Should return 404 for non-existent report export."""
        response = client.get("/reports/99999/export/markdown")
        assert response.status_code == 404
