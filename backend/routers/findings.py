"""Router for finding notes and project notes - user annotations."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from backend.core.database import get_db
from backend.core.auth import get_current_user
from backend.models.models import Finding, FindingNote, ProjectNote, Project, User, ProjectCollaborator

router = APIRouter(prefix="/findings", tags=["findings"])


def _verify_finding_access(db: Session, finding_id: int, user_id: int) -> Finding:
    """Verify user has access to the finding's project."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    project = db.query(Project).filter(Project.id == finding.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if project.owner_id == user_id:
        return finding
    
    collaborator = db.query(ProjectCollaborator).filter(
        ProjectCollaborator.project_id == project.id,
        ProjectCollaborator.user_id == user_id
    ).first()
    
    if not collaborator:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return finding


def _verify_project_access(db: Session, project_id: int, user_id: int) -> Project:
    """Verify user has access to the project."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    if project.owner_id == user_id:
        return project
    
    collaborator = db.query(ProjectCollaborator).filter(
        ProjectCollaborator.project_id == project_id,
        ProjectCollaborator.user_id == user_id
    ).first()
    
    if not collaborator:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return project


# ============================================================================
# Pydantic Schemas
# ============================================================================

class NoteCreate(BaseModel):
    content: str
    note_type: str = "comment"  # comment, remediation, false_positive, accepted_risk, in_progress
    extra_data: Optional[dict] = None


class NoteUpdate(BaseModel):
    content: Optional[str] = None
    note_type: Optional[str] = None
    extra_data: Optional[dict] = None


class NoteResponse(BaseModel):
    id: int
    finding_id: int
    user_id: Optional[int]
    content: str
    note_type: str
    created_at: datetime
    updated_at: datetime
    extra_data: Optional[dict]

    class Config:
        from_attributes = True


class FindingWithNotesResponse(BaseModel):
    id: int
    project_id: int
    type: str
    severity: str
    file_path: Optional[str]
    start_line: Optional[int]
    end_line: Optional[int]
    summary: str
    details: Optional[dict]
    notes_count: int
    notes: List[NoteResponse]

    class Config:
        from_attributes = True


class NoteSummary(BaseModel):
    total_notes: int
    by_type: dict
    recent_notes: List[NoteResponse]


# ============================================================================
# API Endpoints
# ============================================================================

@router.get("/{finding_id}/notes", response_model=List[NoteResponse])
def get_finding_notes(
    finding_id: int,
    note_type: Optional[str] = Query(None, description="Filter by note type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all notes for a specific finding."""
    # Verify finding exists and user has access
    finding = _verify_finding_access(db, finding_id, current_user.id)
    
    query = db.query(FindingNote).filter(FindingNote.finding_id == finding_id)
    
    if note_type:
        query = query.filter(FindingNote.note_type == note_type)
    
    notes = query.order_by(FindingNote.created_at.desc()).all()
    
    return notes


@router.post("/{finding_id}/notes", response_model=NoteResponse, status_code=201)
def create_finding_note(
    finding_id: int,
    note_data: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new note for a finding."""
    # Verify finding exists and user has access
    finding = _verify_finding_access(db, finding_id, current_user.id)
    
    # Validate note_type
    valid_types = ["comment", "remediation", "false_positive", "accepted_risk", "in_progress"]
    if note_data.note_type not in valid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid note_type. Must be one of: {', '.join(valid_types)}"
        )
    
    note = FindingNote(
        finding_id=finding_id,
        content=note_data.content,
        note_type=note_data.note_type,
        extra_data=note_data.extra_data
    )
    
    db.add(note)
    db.commit()
    db.refresh(note)
    
    return note


@router.put("/notes/{note_id}", response_model=NoteResponse)
def update_finding_note(
    note_id: int,
    note_data: NoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing note."""
    note = db.get(FindingNote, note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    
    # Verify user has access to the finding's project
    _verify_finding_access(db, note.finding_id, current_user.id)
    
    if note_data.content is not None:
        note.content = note_data.content
    
    if note_data.note_type is not None:
        valid_types = ["comment", "remediation", "false_positive", "accepted_risk", "in_progress"]
        if note_data.note_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid note_type. Must be one of: {', '.join(valid_types)}"
            )
        note.note_type = note_data.note_type
    
    if note_data.extra_data is not None:
        note.extra_data = note_data.extra_data
    
    db.commit()
    db.refresh(note)
    
    return note


@router.delete("/notes/{note_id}", status_code=204)
def delete_finding_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a note."""
    note = db.get(FindingNote, note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    
    # Verify user has access to the finding's project
    _verify_finding_access(db, note.finding_id, current_user.id)
    
    db.delete(note)
    db.commit()


@router.get("/project/{project_id}/notes-summary", response_model=NoteSummary)
def get_project_notes_summary(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get summary of all notes across a project's findings."""
    # Verify user has access to the project
    _verify_project_access(db, project_id, current_user.id)
    
    # Get all notes for findings in this project
    all_notes = (
        db.query(FindingNote)
        .join(Finding, FindingNote.finding_id == Finding.id)
        .filter(Finding.project_id == project_id)
        .order_by(FindingNote.created_at.desc())
        .all()
    )
    
    # Count by type
    by_type = {}
    for note in all_notes:
        by_type[note.note_type] = by_type.get(note.note_type, 0) + 1
    
    # Get recent 10 notes
    recent_notes = all_notes[:10] if all_notes else []
    
    return NoteSummary(
        total_notes=len(all_notes),
        by_type=by_type,
        recent_notes=recent_notes
    )


@router.get("/project/{project_id}/findings-with-notes")
def get_findings_with_notes(
    project_id: int,
    has_notes: Optional[bool] = Query(None, description="Filter to findings with/without notes"),
    note_type: Optional[str] = Query(None, description="Filter by note type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all findings for a project with their notes."""
    _verify_project_access(db, project_id, current_user.id)
    
    findings = (
        db.query(Finding)
        .filter(Finding.project_id == project_id)
        .options(joinedload(Finding.notes))
        .all()
    )
    
    response = []
    for finding in findings:
        notes = list(finding.notes)
        
        # Filter by note_type if specified
        if note_type:
            notes = [n for n in notes if n.note_type == note_type]
        
        # Filter by has_notes if specified
        if has_notes is True and len(notes) == 0:
            continue
        if has_notes is False and len(notes) > 0:
            continue
        
        response.append({
            "id": finding.id,
            "project_id": finding.project_id,
            "type": finding.type,
            "severity": finding.severity,
            "file_path": finding.file_path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "summary": finding.summary,
            "details": finding.details,
            "notes_count": len(notes),
            "notes": [
                {
                    "id": n.id,
                    "finding_id": n.finding_id,
                    "user_id": n.user_id,
                    "content": n.content,
                    "note_type": n.note_type,
                    "created_at": n.created_at,
                    "updated_at": n.updated_at,
                    "extra_data": n.extra_data
                }
                for n in sorted(notes, key=lambda x: x.created_at, reverse=True)
            ]
        })
    
    return response


# ============================================================================
# Project Notes Schemas
# ============================================================================

class ProjectNoteCreate(BaseModel):
    title: Optional[str] = None
    content: str
    note_type: str = "general"  # general, todo, important, reference
    extra_data: Optional[dict] = None


class ProjectNoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    note_type: Optional[str] = None
    extra_data: Optional[dict] = None


class ProjectNoteResponse(BaseModel):
    id: int
    project_id: int
    user_id: Optional[int]
    title: Optional[str]
    content: str
    note_type: str
    created_at: datetime
    updated_at: datetime
    extra_data: Optional[dict]

    class Config:
        from_attributes = True


# ============================================================================
# Project Notes API Endpoints
# ============================================================================

@router.get("/project/{project_id}/general-notes", response_model=List[ProjectNoteResponse])
def get_project_notes(
    project_id: int,
    note_type: Optional[str] = Query(None, description="Filter by note type"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all general notes for a project (not tied to findings)."""
    _verify_project_access(db, project_id, current_user.id)
    
    query = db.query(ProjectNote).filter(ProjectNote.project_id == project_id)
    
    if note_type:
        query = query.filter(ProjectNote.note_type == note_type)
    
    notes = query.order_by(ProjectNote.created_at.desc()).all()
    
    return notes


@router.post("/project/{project_id}/general-notes", response_model=ProjectNoteResponse, status_code=201)
def create_project_note(
    project_id: int,
    note_data: ProjectNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new general note for a project."""
    _verify_project_access(db, project_id, current_user.id)
    
    # Validate note_type
    valid_types = ["general", "todo", "important", "reference"]
    if note_data.note_type not in valid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid note_type. Must be one of: {', '.join(valid_types)}"
        )
    
    note = ProjectNote(
        project_id=project_id,
        title=note_data.title,
        content=note_data.content,
        note_type=note_data.note_type,
        extra_data=note_data.extra_data
    )
    
    db.add(note)
    db.commit()
    db.refresh(note)
    
    return note


@router.put("/project-notes/{note_id}", response_model=ProjectNoteResponse)
def update_project_note(
    note_id: int,
    note_data: ProjectNoteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an existing project note."""
    note = db.get(ProjectNote, note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    
    _verify_project_access(db, note.project_id, current_user.id)
    
    if note_data.title is not None:
        note.title = note_data.title
    
    if note_data.content is not None:
        note.content = note_data.content
    
    if note_data.note_type is not None:
        valid_types = ["general", "todo", "important", "reference"]
        if note_data.note_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid note_type. Must be one of: {', '.join(valid_types)}"
            )
        note.note_type = note_data.note_type
    
    if note_data.extra_data is not None:
        note.extra_data = note_data.extra_data
    
    db.commit()
    db.refresh(note)
    
    return note


@router.delete("/project-notes/{note_id}", status_code=204)
def delete_project_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a project note."""
    note = db.get(ProjectNote, note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    
    _verify_project_access(db, note.project_id, current_user.id)
    
    db.delete(note)
    db.commit()
