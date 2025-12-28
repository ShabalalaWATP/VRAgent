import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend import models
from backend.schemas import ProjectCreate


def list_projects(db: Session, owner_id: Optional[int] = None) -> List[models.Project]:
    """List projects owned by user or shared with them."""
    query = db.query(models.Project)
    if owner_id is not None:
        # Include projects owned by user OR where user is a collaborator
        query = query.outerjoin(
            models.ProjectCollaborator,
            models.Project.id == models.ProjectCollaborator.project_id
        ).filter(
            or_(
                models.Project.owner_id == owner_id,
                models.ProjectCollaborator.user_id == owner_id
            )
        ).distinct()
    return query.order_by(models.Project.created_at.desc()).all()


def get_project(db: Session, project_id: int) -> Optional[models.Project]:
    return db.query(models.Project).filter(models.Project.id == project_id).first()


def can_access_project(db: Session, project_id: int, user_id: int) -> Tuple[bool, str]:
    """Check if user can access project. Returns (can_access, role)."""
    project = get_project(db, project_id)
    if not project:
        return False, ""
    
    # Owner has full access
    if project.owner_id == user_id:
        return True, "owner"
    
    # Check if user is a collaborator
    collaborator = db.query(models.ProjectCollaborator).filter(
        models.ProjectCollaborator.project_id == project_id,
        models.ProjectCollaborator.user_id == user_id
    ).first()
    
    if collaborator:
        return True, collaborator.role
    
    return False, ""


def can_edit_project(db: Session, project_id: int, user_id: int) -> bool:
    """Check if user can edit project (owner, admin, or editor)."""
    can_access, role = can_access_project(db, project_id, user_id)
    return can_access and role in ("owner", "admin", "editor")


def create_project(db: Session, project_in: ProjectCreate, owner_id: Optional[int] = None) -> models.Project:
    """Create a new project with optional owner."""
    project = models.Project(
        name=project_in.name,
        description=project_in.description,
        git_url=project_in.git_url,
        is_shared="true" if project_in.is_shared else "false",
        owner_id=owner_id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def add_collaborator(
    db: Session, 
    project_id: int, 
    user_id: int, 
    role: str = "editor",
    added_by: Optional[int] = None
) -> Optional[models.ProjectCollaborator]:
    """Add a collaborator to a project."""
    # Check if already a collaborator
    existing = db.query(models.ProjectCollaborator).filter(
        models.ProjectCollaborator.project_id == project_id,
        models.ProjectCollaborator.user_id == user_id
    ).first()
    
    if existing:
        # Update role
        existing.role = role
        db.commit()
        db.refresh(existing)
        return existing
    
    collaborator = models.ProjectCollaborator(
        project_id=project_id,
        user_id=user_id,
        role=role,
        added_by=added_by
    )
    db.add(collaborator)
    db.commit()
    db.refresh(collaborator)
    return collaborator


def remove_collaborator(db: Session, project_id: int, user_id: int) -> bool:
    """Remove a collaborator from a project."""
    result = db.query(models.ProjectCollaborator).filter(
        models.ProjectCollaborator.project_id == project_id,
        models.ProjectCollaborator.user_id == user_id
    ).delete()
    db.commit()
    return result > 0


def list_collaborators(db: Session, project_id: int) -> List[dict]:
    """List all collaborators for a project."""
    collaborators = db.query(models.ProjectCollaborator).filter(
        models.ProjectCollaborator.project_id == project_id
    ).all()
    
    result = []
    for collab in collaborators:
        user = db.query(models.User).filter(models.User.id == collab.user_id).first()
        result.append({
            "id": collab.id,
            "project_id": collab.project_id,
            "user_id": collab.user_id,
            "role": collab.role,
            "added_at": collab.added_at,
            "username": user.username if user else None,
            "email": user.email if user else None,
        })
    return result


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
