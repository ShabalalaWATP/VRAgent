"""
Pytest configuration and fixtures for VRAgent tests.
"""
import os
import tempfile
from typing import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Set test environment before importing app
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

from backend.core.database import Base, get_db
from backend.main import app
from backend import models


# Test database setup
TEST_DATABASE_URL = "sqlite:///./test.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db() -> Generator[Session, None, None]:
    """Override database dependency for testing."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create test database tables once per session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    # Clean up test database file
    try:
        os.remove("./test.db")
    except OSError:
        pass


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    """Provide a test database session that rolls back after each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def client(db: Session) -> Generator[TestClient, None, None]:
    """Provide a test client with database override."""
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_project(db: Session) -> models.Project:
    """Create a sample project for testing."""
    project = models.Project(
        name="Test Project",
        description="A test project for unit tests",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def sample_project_with_upload(db: Session, tmp_path: Path) -> models.Project:
    """Create a sample project with a mock uploaded zip."""
    import zipfile
    
    # Create a test zip file
    zip_path = tmp_path / "test_code.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("main.py", "def hello():\n    print('Hello')\n")
        zf.writestr("requirements.txt", "fastapi==0.110.0\n")
    
    project = models.Project(
        name="Test Project with Upload",
        description="A test project with uploaded code",
        upload_path=str(zip_path),
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def sample_scan_run(db: Session, sample_project: models.Project) -> models.ScanRun:
    """Create a sample scan run."""
    scan_run = models.ScanRun(
        project_id=sample_project.id,
        status="queued",
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    return scan_run


@pytest.fixture
def sample_report(db: Session, sample_project: models.Project, sample_scan_run: models.ScanRun) -> models.Report:
    """Create a sample report."""
    report = models.Report(
        project_id=sample_project.id,
        scan_run_id=sample_scan_run.id,
        title="Test Report",
        summary="Test summary",
        overall_risk_score=5.5,
        data={
            "severity_counts": {"high": 2, "medium": 3, "low": 1},
            "affected_packages": ["requests", "urllib3"],
        },
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@pytest.fixture
def sample_findings(db: Session, sample_project: models.Project, sample_scan_run: models.ScanRun) -> list[models.Finding]:
    """Create sample findings."""
    findings = [
        models.Finding(
            project_id=sample_project.id,
            scan_run_id=sample_scan_run.id,
            type="code_pattern",
            severity="high",
            file_path="main.py",
            start_line=10,
            summary="Use of eval detected",
            details={"pattern": "eval("},
        ),
        models.Finding(
            project_id=sample_project.id,
            scan_run_id=sample_scan_run.id,
            type="dependency_vuln",
            severity="medium",
            summary="Known vulnerability in requests",
            details={"external_id": "CVE-2023-1234", "dependency": "requests"},
        ),
    ]
    db.add_all(findings)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings


@pytest.fixture
def temp_zip_file(tmp_path: Path) -> Path:
    """Create a temporary zip file with test code."""
    import zipfile
    
    zip_path = tmp_path / "test_code.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("app.py", """
import os
def dangerous_eval(user_input):
    return eval(user_input)  # Vulnerable!
    
def safe_function():
    return "Hello, World!"
""")
        zf.writestr("utils/helper.py", """
import subprocess
def run_command(cmd):
    return subprocess.run(cmd, shell=True)  # shell=True is dangerous
""")
        zf.writestr("requirements.txt", "fastapi==0.110.0\nrequests==2.28.0\n")
        zf.writestr("package.json", '{"dependencies": {"express": "^4.18.0"}}')
    
    return zip_path


@pytest.fixture
def malicious_zip_file(tmp_path: Path) -> Path:
    """Create a zip file with path traversal attempt."""
    import zipfile
    
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        # This should be blocked by the security check
        zf.writestr("../../../etc/passwd", "malicious content")
    
    return zip_path
