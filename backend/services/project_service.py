import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from sqlalchemy.orm import Session

from backend import models
from backend.schemas import ProjectCreate


def list_projects(db: Session) -> List[models.Project]:
    return db.query(models.Project).order_by(models.Project.created_at.desc()).all()


def get_project(db: Session, project_id: int) -> Optional[models.Project]:
    return db.query(models.Project).filter(models.Project.id == project_id).first()


def create_project(db: Session, project_in: ProjectCreate) -> models.Project:
    project = models.Project(
        name=project_in.name, description=project_in.description, git_url=project_in.git_url
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def save_upload(db: Session, project: models.Project, upload_file_path: str) -> models.Project:
    # Use the shared uploads volume mounted at /app/uploads (shared between backend and worker)
    target_dir = Path("/app/uploads")
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / f"project_{project.id}.zip"
    shutil.copy(upload_file_path, dest)
    project.upload_path = str(dest)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project
