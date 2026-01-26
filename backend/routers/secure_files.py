"""
Secure file download endpoints with authentication and authorization.

Replaces insecure StaticFiles mounts with proper access control:
- Project files: Only accessible to project owner/collaborators
- Project documents: Only accessible to project owner/collaborators
- Chat files: Only accessible to conversation participants
"""
import os
import mimetypes
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from backend.core.database import get_db
from backend.core.auth import get_current_active_user
from backend.core.config import settings
from backend.core.logging import get_logger
from backend.models.models import (
    User, Project, ProjectFile, ProjectDocument, ProjectCollaborator,
    Conversation, ConversationParticipant, Message, DocumentTranslation
)

logger = get_logger(__name__)

router = APIRouter(prefix="/files", tags=["secure-files"])


def check_project_access(db: Session, project_id: int, user_id: int) -> bool:
    """Check if user has access to the project (owner or collaborator)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False

    # Owner has access
    if project.owner_id == user_id:
        return True

    # Check collaborator access
    collaborator = db.query(ProjectCollaborator).filter(
        and_(
            ProjectCollaborator.project_id == project_id,
            ProjectCollaborator.user_id == user_id,
            ProjectCollaborator.status == "accepted"
        )
    ).first()

    return collaborator is not None


def check_chat_file_access(db: Session, filename: str, user_id: int) -> bool:
    """
    Check if user has access to a chat file.

    A user can access a chat file if they are a participant in a conversation
    where a message contains this file's URL.
    """
    # Build the file URL pattern to search for
    file_url = f"/api/files/chat/{filename}"

    # Find messages containing this file URL
    messages_with_file = db.query(Message).filter(
        Message.file_url == file_url
    ).all()

    if not messages_with_file:
        # Also check file_urls JSON array for multi-file messages
        # This is a fallback - most messages use file_url
        return False

    # Check if user is a participant in any conversation containing this message
    for message in messages_with_file:
        participant = db.query(ConversationParticipant).filter(
            and_(
                ConversationParticipant.conversation_id == message.conversation_id,
                ConversationParticipant.user_id == user_id
            )
        ).first()

        if participant:
            return True

    return False


def get_safe_file_path(base_dir: str, *path_parts: str) -> Optional[Path]:
    """
    Safely construct a file path, preventing path traversal attacks.
    Returns None if the resulting path is outside the base directory.
    """
    base = Path(base_dir).resolve()

    # Clean each path part to remove any traversal attempts
    clean_parts = []
    for part in path_parts:
        # Remove any path separators and parent directory references
        clean = Path(part).name  # Gets just the filename, no path
        if clean and clean not in ('.', '..'):
            clean_parts.append(clean)

    if not clean_parts:
        return None

    # Construct the full path
    full_path = base.joinpath(*clean_parts).resolve()

    # Verify the path is still under the base directory
    try:
        full_path.relative_to(base)
    except ValueError:
        # Path traversal attempt detected
        logger.warning(f"Path traversal attempt detected: {path_parts}")
        return None

    return full_path


def stream_file(file_path: Path, chunk_size: int = 8192):
    """Generator to stream file content in chunks."""
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


# =============================================================================
# Project Files - Secure Download
# =============================================================================

@router.get("/project/{project_id}/{filename}")
async def download_project_file(
    project_id: int,
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Securely download a project file.

    Requires authentication and project access (owner or collaborator).
    """
    # Check project access
    if not check_project_access(db, project_id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this project"
        )

    # Verify file exists in database and belongs to this project
    project_file = db.query(ProjectFile).filter(
        and_(
            ProjectFile.project_id == project_id,
            ProjectFile.filename == filename
        )
    ).first()

    if not project_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    # Construct safe file path
    base_dir = os.path.join(settings.upload_dir, "project_files", str(project_id))
    file_path = get_safe_file_path(base_dir, filename)

    if not file_path or not file_path.exists():
        logger.error(f"File not found on disk: {project_file.file_path}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )

    # Determine content type
    content_type = project_file.mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    # Stream the file
    return StreamingResponse(
        stream_file(file_path),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{project_file.original_filename}"',
            "Content-Length": str(project_file.file_size),
            "Cache-Control": "private, max-age=3600",  # Cache for 1 hour, but private
        }
    )


# =============================================================================
# Project Documents - Secure Download
# =============================================================================

@router.get("/document/{project_id}/{filename}")
async def download_project_document(
    project_id: int,
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Securely download a project document.

    Requires authentication and project access (owner or collaborator).
    """
    # Check project access
    if not check_project_access(db, project_id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this project"
        )

    # Verify document exists in database and belongs to this project
    document = db.query(ProjectDocument).filter(
        and_(
            ProjectDocument.project_id == project_id,
            ProjectDocument.filename == filename
        )
    ).first()

    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    # Construct safe file path
    base_dir = os.path.join(settings.upload_dir, "project_documents", str(project_id))
    file_path = get_safe_file_path(base_dir, filename)

    if not file_path or not file_path.exists():
        logger.error(f"Document not found on disk: {document.file_path}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found on disk"
        )

    # Determine content type
    content_type = document.mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    # Stream the file
    return StreamingResponse(
        stream_file(file_path),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{document.original_filename}"',
            "Content-Length": str(document.file_size),
            "Cache-Control": "private, max-age=3600",
        }
    )


# =============================================================================
# Project Translations - Secure Download
# =============================================================================

@router.get("/translation/{project_id}/{filename}")
async def download_project_translation(
    project_id: int,
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Securely download a project translation file.

    Requires authentication and project access (owner or collaborator).
    """
    if not check_project_access(db, project_id, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this project"
        )

    translation = db.query(DocumentTranslation).filter(
        and_(
            DocumentTranslation.project_id == project_id,
            or_(
                DocumentTranslation.filename == filename,
                DocumentTranslation.output_filename == filename
            )
        )
    ).first()

    if not translation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Translation file not found"
        )

    base_dir = os.path.join(settings.upload_dir, "project_translations", str(project_id))
    file_path = get_safe_file_path(base_dir, filename)

    if not file_path or not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found on disk"
        )

    download_name = (
        translation.output_filename
        if filename == translation.output_filename
        else translation.original_filename
    )
    if filename == translation.output_filename:
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    else:
        content_type = translation.mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    return StreamingResponse(
        stream_file(file_path),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Content-Length": str(file_path.stat().st_size),
            "Cache-Control": "private, max-age=3600",
        }
    )


# =============================================================================
# Chat Files - Secure Download
# =============================================================================

@router.get("/chat/{filename}")
async def download_chat_file(
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Securely download a chat file attachment.

    Requires authentication and being a participant in a conversation
    where this file was shared.
    """
    # Check if user has access to this chat file
    if not check_chat_file_access(db, filename, current_user.id):
        # Also allow the file uploader to access their own files
        # Check if this file was uploaded by looking at messages
        file_url = f"/api/files/chat/{filename}"
        user_message = db.query(Message).filter(
            and_(
                Message.file_url == file_url,
                Message.sender_id == current_user.id
            )
        ).first()

        if not user_message:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this file"
            )

    # Construct safe file path
    base_dir = os.path.join(settings.upload_dir, "chat")
    file_path = get_safe_file_path(base_dir, filename)

    if not file_path or not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )

    # Determine content type
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    # For images, allow inline display; for others, force download
    disposition = "inline" if content_type.startswith("image/") else "attachment"

    # Stream the file
    return StreamingResponse(
        stream_file(file_path),
        media_type=content_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "Cache-Control": "private, max-age=3600",
        }
    )


# =============================================================================
# Admin: List orphaned files (for cleanup)
# =============================================================================

@router.get("/admin/orphaned")
async def list_orphaned_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    List files on disk that don't have corresponding database records.
    Admin only - useful for cleanup.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    orphaned = {
        "project_files": [],
        "project_documents": [],
        "chat_files": [],
    }

    # Check project files
    project_files_dir = Path(settings.upload_dir) / "project_files"
    if project_files_dir.exists():
        for project_dir in project_files_dir.iterdir():
            if project_dir.is_dir():
                try:
                    project_id = int(project_dir.name)
                    for file_path in project_dir.iterdir():
                        if file_path.is_file():
                            exists = db.query(ProjectFile).filter(
                                and_(
                                    ProjectFile.project_id == project_id,
                                    ProjectFile.filename == file_path.name
                                )
                            ).first()
                            if not exists:
                                orphaned["project_files"].append(str(file_path))
                except ValueError:
                    pass

    # Check project documents
    docs_dir = Path(settings.upload_dir) / "project_documents"
    if docs_dir.exists():
        for project_dir in docs_dir.iterdir():
            if project_dir.is_dir():
                try:
                    project_id = int(project_dir.name)
                    for file_path in project_dir.iterdir():
                        if file_path.is_file():
                            exists = db.query(ProjectDocument).filter(
                                and_(
                                    ProjectDocument.project_id == project_id,
                                    ProjectDocument.filename == file_path.name
                                )
                            ).first()
                            if not exists:
                                orphaned["project_documents"].append(str(file_path))
                except ValueError:
                    pass

    # Check chat files
    chat_dir = Path(settings.upload_dir) / "chat"
    if chat_dir.exists():
        for file_path in chat_dir.iterdir():
            if file_path.is_file():
                file_url = f"/api/files/chat/{file_path.name}"
                exists = db.query(Message).filter(
                    Message.file_url == file_url
                ).first()
                if not exists:
                    orphaned["chat_files"].append(str(file_path))

    return {
        "orphaned_files": orphaned,
        "total_count": sum(len(v) for v in orphaned.values())
    }
