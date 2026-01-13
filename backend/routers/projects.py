from pathlib import Path
import shutil
import tempfile
import zipfile
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.auth import get_current_active_user
from backend.models.models import User
from backend.schemas import Project, ProjectCreate, ProjectCollaborator, ProjectCollaboratorCreate, UploadResponse
from backend.services import project_service
from backend.services import git_service

router = APIRouter()
logger = get_logger(__name__)


class CloneRequest(BaseModel):
    """Request body for cloning a repository."""
    repo_url: str
    branch: str | None = None


class CloneResponse(BaseModel):
    """Response for clone operation."""
    message: str
    repo_name: str
    branch: str
    path: str


class AddCollaboratorRequest(BaseModel):
    """Request to add a collaborator."""
    username: str
    role: str = "editor"  # 'viewer', 'editor', 'admin'


class UpdateCollaboratorRequest(BaseModel):
    """Request to update a collaborator's role."""
    role: str


def project_to_response(project, user_id: int, db: Session) -> dict:
    """Convert project model to response with additional fields."""
    # Get user's role
    can_access, role = project_service.can_access_project(db, project.id, user_id)
    
    # Get owner username
    owner = db.query(User).filter(User.id == project.owner_id).first() if project.owner_id else None
    
    # Count collaborators
    from backend.models.models import ProjectCollaborator as CollabModel
    collab_count = db.query(CollabModel).filter(CollabModel.project_id == project.id).count()
    
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "git_url": project.git_url,
        "is_shared": project.is_shared == "true",
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "owner_id": project.owner_id,
        "owner_username": owner.username if owner else None,
        "collaborator_count": collab_count,
        "user_role": role if can_access else None,
    }


@router.get("", response_model=list[Project])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all projects belonging to the current user or shared with them."""
    projects = project_service.list_projects(db, owner_id=current_user.id)
    return [project_to_response(p, current_user.id, db) for p in projects]


@router.post("", response_model=Project)
def create_project(
    project_in: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Create a new project for the current user."""
    project = project_service.create_project(db, project_in, owner_id=current_user.id)
    return project_to_response(project, current_user.id, db)


@router.get("/{project_id}", response_model=Project)
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific project (must be owner or collaborator)."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check access
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")
    
    return project_to_response(project, current_user.id, db)


@router.delete("/{project_id}")
def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete a project and all associated data (only owner can delete)."""
    from backend import models
    from backend.models.models import CombinedAnalysisReport
    
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Only owner can delete
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the project owner can delete the project")
    
    # CRITICAL: Delete combined analysis reports FIRST before any other operations
    # This prevents SQLAlchemy from trying to set project_id=NULL
    db.query(CombinedAnalysisReport).filter(CombinedAnalysisReport.project_id == project_id).delete(synchronize_session='fetch')
    db.flush()  # Ensure deletion is committed before other operations
    
    # Get all scan runs for this project
    scan_runs = db.query(models.ScanRun).filter(models.ScanRun.project_id == project_id).all()
    scan_run_ids = [sr.id for sr in scan_runs]
    
    # Delete exploit scenarios for reports in this project
    reports = db.query(models.Report).filter(models.Report.project_id == project_id).all()
    for report in reports:
        db.query(models.ExploitScenario).filter(
            models.ExploitScenario.report_id == report.id
        ).delete()
    
    # Delete findings for all scan runs (do this before vulnerabilities as findings have FK to vulnerability)
    if scan_run_ids:
        db.query(models.Finding).filter(
            models.Finding.scan_run_id.in_(scan_run_ids)
        ).delete(synchronize_session=False)
    
    # Also delete any findings directly linked to project (redundant but safe)
    db.query(models.Finding).filter(models.Finding.project_id == project_id).delete(synchronize_session=False)
    
    # Delete vulnerabilities (after findings, as findings have FK to vulnerability)
    db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project_id).delete()
    
    # Delete dependencies (after vulnerabilities, as vulnerabilities have FK to dependency)
    db.query(models.Dependency).filter(models.Dependency.project_id == project_id).delete()
    
    # Delete reports
    db.query(models.Report).filter(models.Report.project_id == project_id).delete()
    
    # Delete scan runs
    db.query(models.ScanRun).filter(models.ScanRun.project_id == project_id).delete()
    
    # Delete code chunks
    db.query(models.CodeChunk).filter(models.CodeChunk.project_id == project_id).delete()
    
    # Delete collaborators
    db.query(models.ProjectCollaborator).filter(models.ProjectCollaborator.project_id == project_id).delete()
    
    # Delete team chat conversation and all related data (messages, participants, etc.)
    # The foreign key in DB doesn't have CASCADE, so we need to delete manually
    from backend.models.models import (
        Conversation, ConversationParticipant, Message, PinnedMessage, Poll, MessageReadReceipt,
        ProjectFile, ProjectDocument, DocumentChatMessage, DocumentAnalysisReport, ReportChatMessage,
        ReverseEngineeringReport, NetworkAnalysisReport, FuzzingSession
    )
    
    # Delete network analysis reports (Nmap, PCAP, DNS, SSL scans)
    db.query(NetworkAnalysisReport).filter(NetworkAnalysisReport.project_id == project_id).delete()
    
    # Delete fuzzing sessions
    db.query(FuzzingSession).filter(FuzzingSession.project_id == project_id).delete()
    
    # Delete project files (these have CASCADE but let's be explicit)
    db.query(ProjectFile).filter(ProjectFile.project_id == project_id).delete()
    
    # Delete project documents and their chat messages FIRST (before DocumentAnalysisReport)
    # ProjectDocument has a foreign key to DocumentAnalysisReport (report_id)
    documents_to_delete = db.query(ProjectDocument).filter(ProjectDocument.project_id == project_id).all()
    for doc in documents_to_delete:
        db.query(DocumentChatMessage).filter(DocumentChatMessage.document_id == doc.id).delete()
    db.query(ProjectDocument).filter(ProjectDocument.project_id == project_id).delete()
    
    # Delete document analysis reports and their chat messages (after ProjectDocument)
    reports_to_delete = db.query(DocumentAnalysisReport).filter(DocumentAnalysisReport.project_id == project_id).all()
    for report in reports_to_delete:
        db.query(ReportChatMessage).filter(ReportChatMessage.report_id == report.id).delete()
    db.query(DocumentAnalysisReport).filter(DocumentAnalysisReport.project_id == project_id).delete()
    
    # Delete reverse engineering reports
    db.query(ReverseEngineeringReport).filter(ReverseEngineeringReport.project_id == project_id).delete()
    
    conversations = db.query(Conversation).filter(Conversation.project_id == project_id).all()
    for conv in conversations:
        # Delete pinned messages
        db.query(PinnedMessage).filter(PinnedMessage.conversation_id == conv.id).delete()
        # Delete polls
        db.query(Poll).filter(Poll.conversation_id == conv.id).delete()
        # Delete read receipts
        db.query(MessageReadReceipt).filter(MessageReadReceipt.conversation_id == conv.id).delete()
        # Delete messages
        db.query(Message).filter(Message.conversation_id == conv.id).delete()
        # Delete participants
        db.query(ConversationParticipant).filter(ConversationParticipant.conversation_id == conv.id).delete()
        # Delete conversation
        db.delete(conv)
    
    # Delete kanban boards and their columns/cards (cascade handles columns->cards)
    from backend.models.models import KanbanBoard, KanbanColumn, KanbanCard
    
    kanban_boards = db.query(KanbanBoard).filter(KanbanBoard.project_id == project_id).all()
    for board in kanban_boards:
        # Delete cards first
        for col in board.columns:
            db.query(KanbanCard).filter(KanbanCard.column_id == col.id).delete()
        # Delete columns
        db.query(KanbanColumn).filter(KanbanColumn.board_id == board.id).delete()
        # Delete board
        db.delete(board)
    
    # Delete the project itself
    db.delete(project)
    db.commit()
    
    logger.info(f"Deleted project {project_id} and all associated data")
    return {"status": "deleted", "project_id": project_id}


# ============================================================================
# Collaborator Endpoints
# ============================================================================

@router.get("/{project_id}/collaborators", response_model=List[ProjectCollaborator])
def list_collaborators(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all collaborators for a project."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check access
    can_access, _ = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Not authorized to view collaborators")
    
    return project_service.list_collaborators(db, project_id)


@router.post("/{project_id}/collaborators", response_model=ProjectCollaborator)
def add_collaborator(
    project_id: int,
    request: AddCollaboratorRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Add a collaborator to a shared project (owner or admin only)."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if project is shared
    if project.is_shared != "true":
        raise HTTPException(status_code=400, detail="Cannot add collaborators to a non-shared project")
    
    # Check access - only owner or admin can add collaborators
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access or role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only project owner or admin can add collaborators")
    
    # Find user by username
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{request.username}' not found")
    
    # Can't add yourself
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot add yourself as a collaborator")
    
    # Can't add the owner
    if user.id == project.owner_id:
        raise HTTPException(status_code=400, detail="Cannot add the owner as a collaborator")
    
    # Validate role
    if request.role not in ("viewer", "editor", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'viewer', 'editor', or 'admin'")
    
    collaborator = project_service.add_collaborator(
        db, project_id, user.id, request.role, added_by=current_user.id
    )
    
    return {
        "id": collaborator.id,
        "project_id": collaborator.project_id,
        "user_id": collaborator.user_id,
        "role": collaborator.role,
        "added_at": collaborator.added_at,
        "username": user.username,
        "email": user.email,
    }


@router.put("/{project_id}/collaborators/{user_id}", response_model=ProjectCollaborator)
def update_collaborator(
    project_id: int,
    user_id: int,
    request: UpdateCollaboratorRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Update a collaborator's role (owner or admin only)."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check access - only owner or admin can update collaborators
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access or role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only project owner or admin can update collaborators")
    
    # Validate role
    if request.role not in ("viewer", "editor", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'viewer', 'editor', or 'admin'")
    
    # Update collaborator
    from backend.models.models import ProjectCollaborator as CollabModel
    collaborator = db.query(CollabModel).filter(
        CollabModel.project_id == project_id,
        CollabModel.user_id == user_id
    ).first()
    
    if not collaborator:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    
    collaborator.role = request.role
    db.commit()
    db.refresh(collaborator)
    
    user = db.query(User).filter(User.id == user_id).first()
    return {
        "id": collaborator.id,
        "project_id": collaborator.project_id,
        "user_id": collaborator.user_id,
        "role": collaborator.role,
        "added_at": collaborator.added_at,
        "username": user.username if user else None,
        "email": user.email if user else None,
    }


@router.delete("/{project_id}/collaborators/{user_id}")
def remove_collaborator(
    project_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Remove a collaborator from a project (owner, admin, or self)."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check access - owner/admin can remove anyone, users can remove themselves
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    is_self = user_id == current_user.id
    
    if not can_access:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if not is_self and role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only project owner or admin can remove collaborators")
    
    success = project_service.remove_collaborator(db, project_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    
    return {"status": "removed", "user_id": user_id}


# ============================================================================
# Upload and Clone Endpoints
# ============================================================================

@router.post("/{project_id}/upload", response_model=UploadResponse)
async def upload_project_code(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check edit access
    if not project_service.can_edit_project(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Not authorized to upload to this project")

    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only zip uploads are supported")
    tmp_dir = Path(tempfile.mkdtemp(prefix="upload_"))
    dest = tmp_dir / file.filename
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    project_service.save_upload(db, project, str(dest))
    return UploadResponse(message="Upload received", path=str(dest))


@router.post("/{project_id}/clone", response_model=CloneResponse)
async def clone_repository(
    project_id: int, 
    clone_request: CloneRequest, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Clone a GitHub/GitLab repository and prepare it for scanning.
    """
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check edit access
    if not project_service.can_edit_project(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Not authorized to clone to this project")
    
    try:
        # Clone the repository
        logger.info(f"Cloning repository {clone_request.repo_url} for project {project_id}")
        result = git_service.clone_repository(
            repo_url=clone_request.repo_url,
            branch=clone_request.branch,
            depth=1,
        )
        
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Clone failed")
        
        # Create a zip file from the cloned repository
        tmp_dir = Path(tempfile.mkdtemp(prefix="clone_"))
        zip_path = tmp_dir / f"{result.repo_name}.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            clone_path = Path(result.path)
            for file_path in clone_path.rglob("*"):
                if ".git" in file_path.parts:
                    continue
                if file_path.is_file():
                    arcname = file_path.relative_to(clone_path)
                    zipf.write(file_path, arcname)
        
        git_service.cleanup_clone(result.path)
        project_service.save_upload(db, project, str(zip_path))
        
        project.git_url = clone_request.repo_url
        db.add(project)
        db.commit()
        
        logger.info(f"Repository cloned successfully: {result.repo_name}")
        
        return CloneResponse(
            message="Repository cloned successfully",
            repo_name=result.repo_name,
            branch=result.branch,
            path=str(zip_path),
        )
        
    except git_service.InvalidRepoURLError as e:
        logger.warning(f"Invalid repository URL: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except git_service.GitCloneError as e:
        logger.error(f"Git clone error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Unexpected error during clone: {e}")
        raise HTTPException(status_code=500, detail=f"Clone failed: {str(e)}")


# ----- Project Team Chat Endpoints -----

@router.get("/{project_id}/team-chat")
def get_project_team_chat(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get or create the team chat conversation for a shared project."""
    from backend.models.models import Conversation, ConversationParticipant, ProjectCollaborator as CollabModel
    
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check access
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")
    
    # Check if project is shared
    if project.is_shared != "true":
        raise HTTPException(status_code=400, detail="Team chat is only available for shared projects")
    
    # Find or create the team chat conversation
    conversation = db.query(Conversation).filter(
        Conversation.project_id == project_id
    ).first()
    
    if not conversation:
        # Create the team chat conversation
        conversation = Conversation(
            name=f"{project.name} Team Chat",
            is_group="true",
            description=f"Team chat for project: {project.name}",
            created_by=project.owner_id,
            project_id=project_id,
        )
        db.add(conversation)
        db.flush()
        
        # Add owner as participant
        if project.owner_id:
            owner_participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=project.owner_id,
                role="owner",
            )
            db.add(owner_participant)
        
        # Add all collaborators as participants
        collaborators = db.query(CollabModel).filter(CollabModel.project_id == project_id).all()
        for collab in collaborators:
            participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=collab.user_id,
                role="member",
            )
            db.add(participant)
        
        db.commit()
    else:
        # Ensure current user is a participant (in case they were added after chat creation)
        existing = db.query(ConversationParticipant).filter(
            ConversationParticipant.conversation_id == conversation.id,
            ConversationParticipant.user_id == current_user.id,
        ).first()
        
        if not existing:
            new_participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=current_user.id,
                role="member",
            )
            db.add(new_participant)
            db.commit()
    
    return {
        "conversation_id": conversation.id,
        "name": conversation.name,
        "description": conversation.description,
        "project_id": project_id,
        "created_at": conversation.created_at,
    }


@router.post("/{project_id}/team-chat/sync-participants")
def sync_team_chat_participants(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Sync team chat participants with project collaborators (owner/admin only)."""
    from backend.models.models import Conversation, ConversationParticipant, ProjectCollaborator as CollabModel
    
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Check if user is owner or admin
    can_access, role = project_service.can_access_project(db, project_id, current_user.id)
    if not can_access or role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only owners and admins can sync participants")
    
    # Get or create the team chat
    conversation = db.query(Conversation).filter(
        Conversation.project_id == project_id
    ).first()
    
    if not conversation:
        raise HTTPException(status_code=404, detail="Team chat not found. Access the team chat first to create it.")
    
    # Get all project collaborators + owner
    collab_user_ids = set()
    if project.owner_id:
        collab_user_ids.add(project.owner_id)
    
    collaborators = db.query(CollabModel).filter(CollabModel.project_id == project_id).all()
    for collab in collaborators:
        collab_user_ids.add(collab.user_id)
    
    # Get existing participants
    existing_participants = db.query(ConversationParticipant).filter(
        ConversationParticipant.conversation_id == conversation.id
    ).all()
    existing_user_ids = {p.user_id for p in existing_participants}
    
    # Add missing participants
    added = 0
    for user_id in collab_user_ids:
        if user_id not in existing_user_ids:
            new_participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=user_id,
                role="member",
            )
            db.add(new_participant)
            added += 1
    
    # Remove participants who are no longer collaborators
    removed = 0
    for participant in existing_participants:
        if participant.user_id not in collab_user_ids:
            db.delete(participant)
            removed += 1
    
    db.commit()
    
    return {
        "status": "ok",
        "added": added,
        "removed": removed,
        "total_participants": len(collab_user_ids),
    }

