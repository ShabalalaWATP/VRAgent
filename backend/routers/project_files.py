"""
Project Files & Documents Router

Endpoints for:
- File storage (upload, list, download, delete)
- Document AI analysis (upload, summarize, Q&A)
"""

import os
import uuid
import shutil
import mimetypes
import logging
import asyncio
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, BackgroundTasks, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any

from backend.core.database import get_db

# Translation progress tracking (in-memory store for WebSocket streaming)
# Key: task_id (str), Value: {"current": int, "total": int, "message": str, "percent": int, "complete": bool}
translation_progress: Dict[str, Dict[str, Any]] = {}
from backend.core.auth import get_current_active_user
from backend.core.config import settings
from backend.models.models import (
    User,
    Project,
    ProjectFile,
    ProjectDocument,
    DocumentChatMessage,
    DocumentAnalysisReport,
    ReportChatMessage,
    DocumentTranslation,
)
from backend.services import project_service
from backend.services.document_ai_service import document_ai_service
from backend.services.document_translation_service import document_translation_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["project-files"])


# ============================================================================
# Pydantic Schemas
# ============================================================================

class ProjectFileResponse(BaseModel):
    id: int
    project_id: int
    filename: str
    original_filename: str
    file_url: str
    file_size: int
    mime_type: Optional[str]
    description: Optional[str]
    folder: Optional[str]
    created_at: datetime
    uploaded_by_username: Optional[str] = None
    
    class Config:
        from_attributes = True


class ProjectDocumentResponse(BaseModel):
    id: int
    project_id: int
    filename: str
    original_filename: str
    file_url: str
    file_size: int
    mime_type: Optional[str]
    summary: Optional[str]
    key_points: Optional[List[str]]
    status: str
    error_message: Optional[str]
    created_at: datetime
    processed_at: Optional[datetime]
    uploaded_by_username: Optional[str] = None
    
    class Config:
        from_attributes = True


class DocumentChatMessageResponse(BaseModel):
    id: int
    document_id: int
    role: str
    content: str
    created_at: datetime
    username: Optional[str] = None
    
    class Config:
        from_attributes = True


class AskQuestionRequest(BaseModel):
    question: str


class AskQuestionResponse(BaseModel):
    question: str
    answer: str
    message_id: int


class DocumentAnalysisReportResponse(BaseModel):
    id: int
    project_id: int
    custom_prompt: Optional[str]
    analysis_depth: Optional[str] = None
    combined_summary: Optional[str]
    combined_key_points: Optional[List[str]]
    status: str
    error_message: Optional[str]
    created_at: datetime
    processed_at: Optional[datetime]
    created_by_username: Optional[str] = None
    documents: List[ProjectDocumentResponse] = []
    
    class Config:
        from_attributes = True


class ReportChatMessageResponse(BaseModel):
    id: int
    report_id: int
    role: str
    content: str
    created_at: datetime
    username: Optional[str] = None
    
    class Config:
        from_attributes = True


class DocumentTranslationResponse(BaseModel):
    id: int
    project_id: int
    filename: str
    original_filename: str
    file_url: str
    file_size: int
    mime_type: Optional[str]
    output_filename: Optional[str]
    output_url: Optional[str]
    target_language: str
    source_language: Optional[str]
    ocr_languages: Optional[str]
    ocr_used: Optional[bool]
    page_count: Optional[int]
    chars_extracted: Optional[int]
    chars_translated: Optional[int]
    translate_images: bool = False
    image_text_regions_translated: Optional[int] = None
    # Quick Win metrics
    headers_footers_skipped: Optional[int] = None
    code_blocks_skipped: Optional[int] = None
    links_preserved: Optional[int] = None
    # Medium effort metrics
    multi_column_pages: Optional[int] = None
    quality_score: Optional[float] = None
    # Large effort metrics
    exact_fonts_used: Optional[int] = None
    tables_stitched: Optional[int] = None
    status: str
    error_message: Optional[str]
    created_at: datetime
    processed_at: Optional[datetime]
    uploaded_by_username: Optional[str] = None

    class Config:
        from_attributes = True


# ============================================================================
# Helper Functions
# ============================================================================

def get_upload_dir() -> Path:
    """Get the upload directory path."""
    upload_dir = Path(os.environ.get("UPLOAD_DIR", "/app/uploads"))
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


def check_project_access(db: Session, project_id: int, user_id: int) -> Project:
    """Check if user has access to the project."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    can_access, role = project_service.can_access_project(db, project_id, user_id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return project


def check_project_edit_access(db: Session, project_id: int, user_id: int) -> Project:
    """Check if user has edit access to the project."""
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    can_access, role = project_service.can_access_project(db, project_id, user_id)
    if not can_access:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if role == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot upload files")
    
    return project


# ============================================================================
# File Storage Endpoints
# ============================================================================

@router.post("/{project_id}/files", response_model=ProjectFileResponse)
async def upload_project_file(
    project_id: int,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    folder: Optional[str] = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a file to the project's file storage."""
    project = check_project_edit_access(db, project_id, current_user.id)
    
    # Validate file size (1GB max)
    MAX_SIZE = 1024 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 1GB")
    
    # Generate unique filename
    ext = Path(file.filename).suffix if file.filename else ""
    unique_filename = f"{uuid.uuid4()}{ext}"
    
    # Create project files directory
    upload_dir = get_upload_dir()
    project_dir = upload_dir / "project_files" / str(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Save file
    file_path = project_dir / unique_filename
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Determine MIME type
    mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    
    # Create database record
    project_file = ProjectFile(
        project_id=project_id,
        uploaded_by=current_user.id,
        filename=unique_filename,
        original_filename=file.filename or "unnamed",
        file_path=str(file_path),
        file_url=f"/api/files/project/{project_id}/{unique_filename}",
        file_size=len(content),
        mime_type=mime_type,
        description=description,
        folder=folder or "",
    )
    
    db.add(project_file)
    db.commit()
    db.refresh(project_file)
    
    logger.info(f"User {current_user.id} uploaded file {file.filename} to project {project_id}")
    
    return ProjectFileResponse(
        id=project_file.id,
        project_id=project_file.project_id,
        filename=project_file.filename,
        original_filename=project_file.original_filename,
        file_url=project_file.file_url,
        file_size=project_file.file_size,
        mime_type=project_file.mime_type,
        description=project_file.description,
        folder=project_file.folder,
        created_at=project_file.created_at,
        uploaded_by_username=current_user.username,
    )


@router.get("/{project_id}/files", response_model=List[ProjectFileResponse])
def list_project_files(
    project_id: int,
    folder: Optional[str] = Query(
        None,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_\-/]+$",
        description="Folder name (alphanumeric, underscore, hyphen, slash only)"
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all files in a project's file storage."""
    check_project_access(db, project_id, current_user.id)

    # Additional path traversal check
    if folder and (".." in folder or folder.startswith("/")):
        raise HTTPException(status_code=400, detail="Invalid folder name")

    query = db.query(ProjectFile).filter(ProjectFile.project_id == project_id)
    if folder is not None:
        query = query.filter(ProjectFile.folder == folder)
    
    files = query.order_by(ProjectFile.created_at.desc()).all()
    
    result = []
    for f in files:
        uploader = db.query(User).filter(User.id == f.uploaded_by).first()
        result.append(ProjectFileResponse(
            id=f.id,
            project_id=f.project_id,
            filename=f.filename,
            original_filename=f.original_filename,
            file_url=f.file_url,
            file_size=f.file_size,
            mime_type=f.mime_type,
            description=f.description,
            folder=f.folder,
            created_at=f.created_at,
            uploaded_by_username=uploader.username if uploader else None,
        ))
    
    return result


@router.delete("/{project_id}/files/{file_id}")
def delete_project_file(
    project_id: int,
    file_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete a file from the project's file storage."""
    check_project_edit_access(db, project_id, current_user.id)
    
    file = db.query(ProjectFile).filter(
        ProjectFile.id == file_id,
        ProjectFile.project_id == project_id
    ).first()
    
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Delete physical file
    try:
        if os.path.exists(file.file_path):
            os.remove(file.file_path)
    except Exception as e:
        logger.warning(f"Could not delete physical file: {e}")
    
    # Delete database record
    db.delete(file)
    db.commit()
    
    return {"status": "deleted", "file_id": file_id}


# ============================================================================
# Document AI Endpoints
# ============================================================================

def process_document_sync(document_id: int):
    """Background task to process document and generate summary."""
    import asyncio
    from backend.core.database import SessionLocal

    db = SessionLocal()
    
    try:
        document = db.query(ProjectDocument).filter(ProjectDocument.id == document_id).first()
        if not document:
            return
        
        document.status = "processing"
        db.commit()
        
        # Extract text
        try:
            text = document_ai_service.extract_text(document.file_path, document.mime_type)
            document.extracted_text = text
            
            # Chunk text for storage
            chunks = document_ai_service.chunk_text(text)
            document.text_chunks = chunks
            
            # Generate AI summary - run async in sync context
            async def generate():
                return await document_ai_service.generate_summary(text, document.original_filename)
            
            result = asyncio.run(generate())
            document.summary = result.get("summary", "")
            document.key_points = result.get("key_points", [])
            
            document.status = "completed"
            document.processed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error processing document {document_id}: {e}")
            document.status = "failed"
            document.error_message = str(e)
        
        db.commit()
        
    finally:
        db.close()


@router.post("/{project_id}/documents", response_model=ProjectDocumentResponse)
async def upload_document_for_analysis(
    project_id: int,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a document for AI analysis and summarization."""
    project = check_project_edit_access(db, project_id, current_user.id)
    
    # Check file type
    mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    if not document_ai_service.is_supported(mime_type):
        supported = ", ".join(document_ai_service.SUPPORTED_MIME_TYPES.values())
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file type: {mime_type}. Supported types: {supported}"
        )
    
    # Validate file size (100MB max for documents)
    MAX_SIZE = 100 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="Document too large. Maximum size is 100MB")
    
    # Generate unique filename
    ext = Path(file.filename).suffix if file.filename else ""
    unique_filename = f"{uuid.uuid4()}{ext}"
    
    # Create project documents directory
    upload_dir = get_upload_dir()
    docs_dir = upload_dir / "project_documents" / str(project_id)
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    # Save file
    file_path = docs_dir / unique_filename
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Create database record
    document = ProjectDocument(
        project_id=project_id,
        uploaded_by=current_user.id,
        filename=unique_filename,
        original_filename=file.filename or "unnamed",
        file_path=str(file_path),
        file_url=f"/api/files/document/{project_id}/{unique_filename}",
        file_size=len(content),
        mime_type=mime_type,
        status="pending",
    )
    
    db.add(document)
    db.commit()
    db.refresh(document)
    
    # Start background processing
    background_tasks.add_task(process_document_sync, document.id)
    
    logger.info(f"User {current_user.id} uploaded document {file.filename} for analysis in project {project_id}")
    
    return ProjectDocumentResponse(
        id=document.id,
        project_id=document.project_id,
        filename=document.filename,
        original_filename=document.original_filename,
        file_url=document.file_url,
        file_size=document.file_size,
        mime_type=document.mime_type,
        summary=document.summary,
        key_points=document.key_points,
        status=document.status,
        error_message=document.error_message,
        created_at=document.created_at,
        processed_at=document.processed_at,
        uploaded_by_username=current_user.username,
    )


@router.get("/{project_id}/documents", response_model=List[ProjectDocumentResponse])
def list_project_documents(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all documents in a project with their analysis status."""
    check_project_access(db, project_id, current_user.id)
    
    documents = db.query(ProjectDocument).filter(
        ProjectDocument.project_id == project_id
    ).order_by(ProjectDocument.created_at.desc()).all()
    
    result = []
    for doc in documents:
        uploader = db.query(User).filter(User.id == doc.uploaded_by).first()
        result.append(ProjectDocumentResponse(
            id=doc.id,
            project_id=doc.project_id,
            filename=doc.filename,
            original_filename=doc.original_filename,
            file_url=doc.file_url,
            file_size=doc.file_size,
            mime_type=doc.mime_type,
            summary=doc.summary,
            key_points=doc.key_points or [],
            status=doc.status,
            error_message=doc.error_message,
            created_at=doc.created_at,
            processed_at=doc.processed_at,
            uploaded_by_username=uploader.username if uploader else None,
        ))
    
    return result


@router.get("/{project_id}/documents/{document_id}", response_model=ProjectDocumentResponse)
def get_document(
    project_id: int,
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific document with its analysis."""
    check_project_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    uploader = db.query(User).filter(User.id == document.uploaded_by).first()
    
    return ProjectDocumentResponse(
        id=document.id,
        project_id=document.project_id,
        filename=document.filename,
        original_filename=document.original_filename,
        file_url=document.file_url,
        file_size=document.file_size,
        mime_type=document.mime_type,
        summary=document.summary,
        key_points=document.key_points or [],
        status=document.status,
        error_message=document.error_message,
        created_at=document.created_at,
        processed_at=document.processed_at,
        uploaded_by_username=uploader.username if uploader else None,
    )


@router.delete("/{project_id}/documents/{document_id}")
def delete_document(
    project_id: int,
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete a document and its chat history."""
    check_project_edit_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Delete physical file
    try:
        if os.path.exists(document.file_path):
            os.remove(document.file_path)
    except Exception as e:
        logger.warning(f"Could not delete physical file: {e}")
    
    # Delete chat messages (cascade should handle this, but be explicit)
    db.query(DocumentChatMessage).filter(
        DocumentChatMessage.document_id == document_id
    ).delete()
    
    # Delete document record
    db.delete(document)
    db.commit()
    
    return {"status": "deleted", "document_id": document_id}


@router.post("/{project_id}/documents/{document_id}/reprocess")
async def reprocess_document(
    project_id: int,
    document_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Reprocess a document to regenerate its summary."""
    check_project_edit_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    # Reset status
    document.status = "pending"
    document.error_message = None
    db.commit()
    
    # Start background processing
    background_tasks.add_task(process_document_sync, document.id)
    
    return {"status": "reprocessing", "document_id": document_id}


# ============================================================================
# Document Chat Endpoints
# ============================================================================

@router.get("/{project_id}/documents/{document_id}/chat", response_model=List[DocumentChatMessageResponse])
def get_document_chat_history(
    project_id: int,
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get chat history for a document."""
    check_project_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    messages = db.query(DocumentChatMessage).filter(
        DocumentChatMessage.document_id == document_id
    ).order_by(DocumentChatMessage.created_at.asc()).all()
    
    result = []
    for msg in messages:
        user = db.query(User).filter(User.id == msg.user_id).first() if msg.user_id else None
        result.append(DocumentChatMessageResponse(
            id=msg.id,
            document_id=msg.document_id,
            role=msg.role,
            content=msg.content,
            created_at=msg.created_at,
            username=user.username if user else None,
        ))
    
    return result


@router.post("/{project_id}/documents/{document_id}/chat", response_model=AskQuestionResponse)
async def ask_document_question(
    project_id: int,
    document_id: int,
    request: AskQuestionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Ask a question about a document using AI."""
    check_project_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    if document.status != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Document is not ready for Q&A. Status: {document.status}"
        )
    
    # Get chat history
    history = db.query(DocumentChatMessage).filter(
        DocumentChatMessage.document_id == document_id
    ).order_by(DocumentChatMessage.created_at.asc()).all()
    
    chat_history = [{"role": msg.role, "content": msg.content} for msg in history]
    
    # Save user question
    user_message = DocumentChatMessage(
        document_id=document_id,
        user_id=current_user.id,
        role="user",
        content=request.question,
    )
    db.add(user_message)
    db.commit()
    
    # Generate AI answer
    try:
        answer = await document_ai_service.answer_question(
            question=request.question,
            document_text=document.extracted_text or "",
            document_summary=document.summary or "",
            chat_history=chat_history,
            filename=document.original_filename,
        )
    except Exception as e:
        logger.error(f"Error answering question: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate answer: {str(e)}")
    
    # Save AI answer
    ai_message = DocumentChatMessage(
        document_id=document_id,
        user_id=None,
        role="assistant",
        content=answer,
    )
    db.add(ai_message)
    db.commit()
    db.refresh(ai_message)
    
    return AskQuestionResponse(
        question=request.question,
        answer=answer,
        message_id=ai_message.id,
    )


@router.delete("/{project_id}/documents/{document_id}/chat")
def clear_document_chat_history(
    project_id: int,
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Clear chat history for a document."""
    check_project_edit_access(db, project_id, current_user.id)
    
    document = db.query(ProjectDocument).filter(
        ProjectDocument.id == document_id,
        ProjectDocument.project_id == project_id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    db.query(DocumentChatMessage).filter(
        DocumentChatMessage.document_id == document_id
    ).delete()
    db.commit()
    
    return {"status": "cleared", "document_id": document_id}


# ============================================================================
# Analysis Report Endpoints (Multi-Document Analysis)
# ============================================================================

def process_report_sync(report_id: int, db_url: str):
    """Background task to process all documents in a report and generate combined summary."""
    import asyncio
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    
    try:
        report = db.query(DocumentAnalysisReport).filter(DocumentAnalysisReport.id == report_id).first()
        if not report:
            return
        
        report.status = "processing"
        db.commit()
        
        try:
            # Get all documents in this report
            documents = db.query(ProjectDocument).filter(
                ProjectDocument.report_id == report_id
            ).all()
            
            # Extract text from each document first
            doc_data = []
            for doc in documents:
                doc.status = "processing"
                db.commit()
                
                try:
                    text = document_ai_service.extract_text(doc.file_path, doc.mime_type)
                    doc.extracted_text = text
                    doc.text_chunks = document_ai_service.chunk_text(text)
                    doc.status = "completed"
                    db.commit()
                    
                    doc_data.append({
                        "filename": doc.original_filename,
                        "text": text
                    })
                except Exception as e:
                    logger.error(f"Error extracting text from {doc.original_filename}: {e}")
                    doc.status = "failed"
                    doc.error_message = str(e)
                    db.commit()
            
            if not doc_data:
                raise ValueError("No documents could be processed")
            
            # Generate combined AI summary
            async def generate():
                return await document_ai_service.generate_multi_document_summary(
                    doc_data,
                    report.custom_prompt or "",
                    analysis_depth=report.analysis_depth or "standard",
                )
            
            result = asyncio.run(generate())
            report.combined_summary = result.get("combined_summary", "")
            report.combined_key_points = result.get("combined_key_points", [])
            
            report.status = "completed"
            report.processed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error processing report {report_id}: {e}")
            report.status = "failed"
            report.error_message = str(e)
        
        db.commit()
        
    finally:
        db.close()


# ============================================================================
# Document Translation Endpoints
# ============================================================================

def process_translation_sync(translation_id: int, db_url: str, task_id: str = "", export_format: str = "pdf"):
    """Background task to translate a document with OCR support."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    # Progress callback for real-time WebSocket updates
    def update_progress(current: int, total: int, message: str):
        if task_id:
            translation_progress[task_id] = {
                "current": current,
                "total": total,
                "message": message,
                "percent": int(current / total * 100) if total > 0 else 0,
                "complete": current >= total
            }

    try:
        translation = db.query(DocumentTranslation).filter(DocumentTranslation.id == translation_id).first()
        if not translation:
            return

        translation.status = "processing"
        db.commit()

        # Initialize progress
        if task_id:
            translation_progress[task_id] = {
                "current": 0, "total": 1, "message": "Starting translation...",
                "percent": 0, "complete": False
            }

        try:
            if (translation.mime_type or "").lower() == "application/pdf":
                output_path, metadata = asyncio.run(
                    document_translation_service.translate_pdf_preserve_layout(
                        file_path=translation.file_path,
                        target_language=translation.target_language,
                        source_language=translation.source_language,
                        ocr_languages=translation.ocr_languages,
                        translate_images=translation.translate_images or False,
                        progress_callback=update_progress,
                    )
                )
                output_filename = Path(output_path).name
                translation.output_filename = output_filename
                translation.output_path = output_path
                translation.output_url = f"/api/files/translation/{translation.project_id}/{output_filename}"
                translation.ocr_used = bool(metadata.get("ocr_used"))
                translation.page_count = metadata.get("page_count")
                translation.chars_extracted = metadata.get("chars_extracted")
                translation.chars_translated = metadata.get("chars_translated")
                translation.image_text_regions_translated = metadata.get("image_text_regions_translated", 0)
                # Quick Win metrics
                translation.headers_footers_skipped = metadata.get("headers_footers_skipped", 0)
                translation.code_blocks_skipped = metadata.get("code_blocks_skipped", 0)
                translation.links_preserved = metadata.get("links_preserved", 0)
                # Medium effort metrics
                translation.multi_column_pages = metadata.get("multi_column_pages", 0)
                translation.quality_score = metadata.get("quality_score")
                # Large effort metrics
                translation.exact_fonts_used = metadata.get("exact_fonts_used", 0)
                translation.tables_stitched = metadata.get("tables_stitched", 0)
                
                # Export to DOCX if requested
                if export_format == "docx" and output_path:
                    try:
                        docx_path = document_translation_service.export_pdf_to_docx(output_path)
                        if docx_path and os.path.exists(docx_path):
                            docx_filename = Path(docx_path).name
                            translation.output_filename = docx_filename
                            translation.output_path = docx_path
                            translation.output_url = f"/api/files/translation/{translation.project_id}/{docx_filename}"
                            logger.info(f"Exported translation to DOCX: {docx_path}")
                    except Exception as docx_err:
                        logger.warning(f"DOCX export failed, keeping PDF: {docx_err}")
                
                translation.status = "completed"
                translation.processed_at = datetime.utcnow()
            else:
                text, metadata = document_translation_service.extract_text_with_metadata(
                    file_path=translation.file_path,
                    filename=translation.original_filename,
                    mime_type=translation.mime_type or "",
                    ocr_languages=translation.ocr_languages,
                )

                translated_text, translate_meta = asyncio.run(
                    document_translation_service.translate_text(
                        text=text,
                        target_language=translation.target_language,
                        source_language=translation.source_language,
                    )
                )

                output_filename = f"{Path(translation.original_filename).stem}_{uuid.uuid4().hex[:8]}_translated.txt"
                output_dir = Path(translation.file_path).parent
                output_path = output_dir / output_filename
                output_path.write_text(translated_text, encoding="utf-8")

                translation.output_filename = output_filename
                translation.output_path = str(output_path)
                translation.output_url = f"/api/files/translation/{translation.project_id}/{output_filename}"
                translation.ocr_used = bool(metadata.get("ocr_used"))
                translation.page_count = metadata.get("page_count")
                translation.chars_extracted = metadata.get("chars_extracted")
                translation.chars_translated = len(translated_text)
                translation.status = "completed"
                translation.processed_at = datetime.utcnow()
        except Exception as e:
            logger.error(f"Translation failed for {translation_id}: {e}")
            translation.status = "failed"
            translation.error_message = str(e)

        db.commit()
    finally:
        db.close()


@router.post("/{project_id}/translations", response_model=DocumentTranslationResponse)
async def upload_document_for_translation(
    project_id: int,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    target_language: Optional[str] = Form("English"),
    source_language: Optional[str] = Form(None),
    ocr_languages: Optional[str] = Form(None),
    translate_images: Optional[bool] = Form(False),
    export_format: Optional[str] = Form("pdf"),  # "pdf" or "docx"
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Upload a document for translation with OCR support.
    
    Args:
        translate_images: If True, OCR and translate text within embedded images (screenshots, diagrams, etc.)
    """
    check_project_edit_access(db, project_id, current_user.id)

    mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
    if not mime_type or not document_translation_service.is_supported(mime_type):
        supported = ", ".join(sorted(document_translation_service.SUPPORTED_MIME_TYPES.values()))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {mime_type}. Supported types: {supported}",
        )

    # Validate file size (100MB max for translations)
    MAX_SIZE = 100 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="Document too large. Maximum size is 100MB")

    ext = Path(file.filename).suffix if file.filename else ""
    unique_filename = f"{uuid.uuid4()}{ext}"

    upload_dir = get_upload_dir()
    translations_dir = upload_dir / "project_translations" / str(project_id)
    translations_dir.mkdir(parents=True, exist_ok=True)

    file_path = translations_dir / unique_filename
    with open(file_path, "wb") as f:
        f.write(content)

    translation = DocumentTranslation(
        project_id=project_id,
        uploaded_by=current_user.id,
        filename=unique_filename,
        original_filename=file.filename or "unnamed",
        file_path=str(file_path),
        file_size=len(content),
        mime_type=mime_type,
        target_language=target_language or "English",
        source_language=source_language,
        ocr_languages=ocr_languages,
        translate_images=translate_images or False,
        status="pending",
    )

    db.add(translation)
    db.commit()
    db.refresh(translation)

    db_url = str(settings.database_url)
    background_tasks.add_task(process_translation_sync, translation.id, db_url, str(translation.id), export_format or "pdf")

    return DocumentTranslationResponse(
        id=translation.id,
        project_id=translation.project_id,
        filename=translation.filename,
        original_filename=translation.original_filename,
        file_url=f"/api/files/translation/{project_id}/{translation.filename}",
        file_size=translation.file_size,
        mime_type=translation.mime_type,
        output_filename=translation.output_filename,
        output_url=translation.output_url,
        target_language=translation.target_language,
        source_language=translation.source_language,
        ocr_languages=translation.ocr_languages,
        ocr_used=translation.ocr_used,
        page_count=translation.page_count,
        chars_extracted=translation.chars_extracted,
        chars_translated=translation.chars_translated,
        status=translation.status,
        error_message=translation.error_message,
        created_at=translation.created_at,
        processed_at=translation.processed_at,
        uploaded_by_username=current_user.username,
    )


@router.websocket("/{project_id}/translations/progress/{task_id}")
async def translation_progress_ws(websocket: WebSocket, project_id: int, task_id: str):
    """WebSocket endpoint for real-time translation progress streaming.
    
    Connect to receive updates during document translation. Messages are JSON:
    {
        "current": 5,      // Current step number
        "total": 10,       // Total steps
        "message": "Translating page 3/7...",
        "percent": 50,     // Progress percentage (0-100)
        "complete": false  // True when translation is finished
    }
    """
    await websocket.accept()
    try:
        while True:
            progress = translation_progress.get(task_id, {
                "current": 0, 
                "total": 1, 
                "message": "Initializing translation...",
                "percent": 0, 
                "complete": False
            })
            await websocket.send_json(progress)
            if progress.get("complete"):
                # Give client time to receive the final message
                await asyncio.sleep(0.2)
                break
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error for task {task_id}: {e}")
    finally:
        # Cleanup progress data
        if task_id in translation_progress:
            del translation_progress[task_id]


@router.get("/{project_id}/translations", response_model=List[DocumentTranslationResponse])
def list_document_translations(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List document translations for a project."""
    check_project_access(db, project_id, current_user.id)

    translations = db.query(DocumentTranslation).filter(
        DocumentTranslation.project_id == project_id
    ).order_by(DocumentTranslation.created_at.desc()).all()

    result = []
    for tr in translations:
        uploader = db.query(User).filter(User.id == tr.uploaded_by).first()
        result.append(DocumentTranslationResponse(
            id=tr.id,
            project_id=tr.project_id,
            filename=tr.filename,
            original_filename=tr.original_filename,
            file_url=f"/api/files/translation/{project_id}/{tr.filename}",
            file_size=tr.file_size,
            mime_type=tr.mime_type,
            output_filename=tr.output_filename,
            output_url=tr.output_url,
            target_language=tr.target_language,
            source_language=tr.source_language,
            ocr_languages=tr.ocr_languages,
            ocr_used=tr.ocr_used,
            page_count=tr.page_count,
            chars_extracted=tr.chars_extracted,
            chars_translated=tr.chars_translated,
            status=tr.status,
            error_message=tr.error_message,
            created_at=tr.created_at,
            processed_at=tr.processed_at,
            uploaded_by_username=uploader.username if uploader else None,
        ))

    return result


@router.delete("/{project_id}/translations/{translation_id}")
def delete_document_translation(
    project_id: int,
    translation_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete a translation and its files."""
    check_project_edit_access(db, project_id, current_user.id)

    translation = db.query(DocumentTranslation).filter(
        DocumentTranslation.id == translation_id,
        DocumentTranslation.project_id == project_id,
    ).first()

    if not translation:
        raise HTTPException(status_code=404, detail="Translation not found")

    for path in [translation.file_path, translation.output_path]:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                logger.warning(f"Could not delete translation file: {e}")

    db.delete(translation)
    db.commit()

    return {"status": "deleted", "translation_id": translation_id}


@router.post("/{project_id}/translations/{translation_id}/reprocess")
async def reprocess_document_translation(
    project_id: int,
    translation_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Reprocess a translation job."""
    check_project_edit_access(db, project_id, current_user.id)

    translation = db.query(DocumentTranslation).filter(
        DocumentTranslation.id == translation_id,
        DocumentTranslation.project_id == project_id,
    ).first()

    if not translation:
        raise HTTPException(status_code=404, detail="Translation not found")

    translation.status = "pending"
    translation.error_message = None
    db.commit()

    db_url = str(settings.database_url)
    background_tasks.add_task(process_translation_sync, translation.id, db_url, str(translation.id), "pdf")

    return {"status": "reprocessing", "translation_id": translation_id}


@router.post("/{project_id}/analysis-reports", response_model=DocumentAnalysisReportResponse)
async def create_analysis_report(
    project_id: int,
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    custom_prompt: Optional[str] = Form(None),
    analysis_depth: Optional[str] = Form("deep"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Upload multiple documents for combined AI analysis."""
    project = check_project_edit_access(db, project_id, current_user.id)
    
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Create the report first
    report = DocumentAnalysisReport(
        project_id=project_id,
        created_by=current_user.id,
        custom_prompt=custom_prompt,
        analysis_depth=analysis_depth or "standard",
        status="pending",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    
    # Save each file and create document records
    upload_dir = get_upload_dir()
    docs_dir = upload_dir / "project_documents" / str(project_id)
    docs_dir.mkdir(parents=True, exist_ok=True)
    
    saved_docs = []
    for file in files:
        # Check file type
        mime_type = file.content_type or mimetypes.guess_type(file.filename or "")[0]
        if not document_ai_service.is_supported(mime_type):
            continue  # Skip unsupported files silently
        
        # Validate file size (100MB max per file)
        content = await file.read()
        if len(content) > 100 * 1024 * 1024:
            continue  # Skip oversized files
        
        # Generate unique filename
        ext = Path(file.filename).suffix if file.filename else ""
        unique_filename = f"{uuid.uuid4()}{ext}"
        
        # Save file
        file_path = docs_dir / unique_filename
        with open(file_path, "wb") as f:
            f.write(content)
        
        # Create document record
        document = ProjectDocument(
            project_id=project_id,
            report_id=report.id,
            uploaded_by=current_user.id,
            filename=unique_filename,
            original_filename=file.filename or "unnamed",
            file_path=str(file_path),
            file_url=f"/api/files/document/{project_id}/{unique_filename}",
            file_size=len(content),
            mime_type=mime_type,
            status="pending",
        )
        db.add(document)
        saved_docs.append(document)
    
    if not saved_docs:
        db.delete(report)
        db.commit()
        raise HTTPException(
            status_code=400, 
            detail="No valid documents provided. Supported: PDF, Word, PowerPoint, text files."
        )
    
    db.commit()
    
    # Start background processing
    db_url = str(settings.database_url)
    background_tasks.add_task(process_report_sync, report.id, db_url)
    
    logger.info(f"User {current_user.id} created analysis report with {len(saved_docs)} documents in project {project_id}")
    
    # Build response with documents
    doc_responses = []
    for doc in saved_docs:
        doc_responses.append(ProjectDocumentResponse(
            id=doc.id,
            project_id=doc.project_id,
            filename=doc.filename,
            original_filename=doc.original_filename,
            file_url=doc.file_url,
            file_size=doc.file_size,
            mime_type=doc.mime_type,
            summary=None,
            key_points=[],
            status=doc.status,
            error_message=None,
            created_at=doc.created_at,
            processed_at=None,
            uploaded_by_username=current_user.username,
        ))
    
    return DocumentAnalysisReportResponse(
        id=report.id,
        project_id=report.project_id,
        custom_prompt=report.custom_prompt,
        analysis_depth=report.analysis_depth,
        combined_summary=None,
        combined_key_points=[],
        status=report.status,
        error_message=None,
        created_at=report.created_at,
        processed_at=None,
        created_by_username=current_user.username,
        documents=doc_responses,
    )


@router.get("/{project_id}/analysis-reports", response_model=List[DocumentAnalysisReportResponse])
def list_analysis_reports(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all analysis reports for a project."""
    check_project_access(db, project_id, current_user.id)
    
    reports = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.project_id == project_id
    ).order_by(DocumentAnalysisReport.created_at.desc()).all()
    
    result = []
    for report in reports:
        creator = db.query(User).filter(User.id == report.created_by).first()
        
        # Get documents for this report
        documents = db.query(ProjectDocument).filter(
            ProjectDocument.report_id == report.id
        ).all()
        
        doc_responses = []
        for doc in documents:
            uploader = db.query(User).filter(User.id == doc.uploaded_by).first()
            doc_responses.append(ProjectDocumentResponse(
                id=doc.id,
                project_id=doc.project_id,
                filename=doc.filename,
                original_filename=doc.original_filename,
                file_url=doc.file_url,
                file_size=doc.file_size,
                mime_type=doc.mime_type,
                summary=doc.summary,
                key_points=doc.key_points or [],
                status=doc.status,
                error_message=doc.error_message,
                created_at=doc.created_at,
                processed_at=doc.processed_at,
                uploaded_by_username=uploader.username if uploader else None,
            ))
        
        result.append(DocumentAnalysisReportResponse(
            id=report.id,
            project_id=report.project_id,
            custom_prompt=report.custom_prompt,
            analysis_depth=report.analysis_depth,
            combined_summary=report.combined_summary,
            combined_key_points=report.combined_key_points or [],
            status=report.status,
            error_message=report.error_message,
            created_at=report.created_at,
            processed_at=report.processed_at,
            created_by_username=creator.username if creator else None,
            documents=doc_responses,
        ))
    
    return result


@router.get("/{project_id}/analysis-reports/{report_id}", response_model=DocumentAnalysisReportResponse)
def get_analysis_report(
    project_id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific analysis report."""
    check_project_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    creator = db.query(User).filter(User.id == report.created_by).first()
    
    # Get documents
    documents = db.query(ProjectDocument).filter(
        ProjectDocument.report_id == report.id
    ).all()
    
    doc_responses = []
    for doc in documents:
        uploader = db.query(User).filter(User.id == doc.uploaded_by).first()
        doc_responses.append(ProjectDocumentResponse(
            id=doc.id,
            project_id=doc.project_id,
            filename=doc.filename,
            original_filename=doc.original_filename,
            file_url=doc.file_url,
            file_size=doc.file_size,
            mime_type=doc.mime_type,
            summary=doc.summary,
            key_points=doc.key_points or [],
            status=doc.status,
            error_message=doc.error_message,
            created_at=doc.created_at,
            processed_at=doc.processed_at,
            uploaded_by_username=uploader.username if uploader else None,
        ))
    
    return DocumentAnalysisReportResponse(
        id=report.id,
        project_id=report.project_id,
        custom_prompt=report.custom_prompt,
        analysis_depth=report.analysis_depth,
        combined_summary=report.combined_summary,
        combined_key_points=report.combined_key_points or [],
        status=report.status,
        error_message=report.error_message,
        created_at=report.created_at,
        processed_at=report.processed_at,
        created_by_username=creator.username if creator else None,
        documents=doc_responses,
    )


@router.delete("/{project_id}/analysis-reports/{report_id}")
def delete_analysis_report(
    project_id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Delete an analysis report and all its documents."""
    check_project_edit_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Delete physical files for all documents
    documents = db.query(ProjectDocument).filter(
        ProjectDocument.report_id == report_id
    ).all()
    
    for doc in documents:
        try:
            if os.path.exists(doc.file_path):
                os.remove(doc.file_path)
        except Exception as e:
            logger.warning(f"Could not delete physical file: {e}")
    
    # Delete report (cascade will delete documents and chat messages)
    db.delete(report)
    db.commit()
    
    return {"status": "deleted", "report_id": report_id}


@router.post("/{project_id}/analysis-reports/{report_id}/reprocess")
async def reprocess_analysis_report(
    project_id: int,
    report_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Reprocess a report to regenerate combined analysis."""
    check_project_edit_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Reset status
    report.status = "pending"
    report.error_message = None
    
    # Reset document statuses
    db.query(ProjectDocument).filter(
        ProjectDocument.report_id == report_id
    ).update({"status": "pending", "error_message": None})
    
    db.commit()
    
    # Start background processing
    db_url = str(settings.database_url)
    background_tasks.add_task(process_report_sync, report.id, db_url)
    
    return {"status": "reprocessing", "report_id": report_id}


# ============================================================================
# Report Chat Endpoints
# ============================================================================

@router.get("/{project_id}/analysis-reports/{report_id}/chat", response_model=List[ReportChatMessageResponse])
def get_report_chat_history(
    project_id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get chat history for a report."""
    check_project_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    messages = db.query(ReportChatMessage).filter(
        ReportChatMessage.report_id == report_id
    ).order_by(ReportChatMessage.created_at.asc()).all()
    
    result = []
    for msg in messages:
        user = db.query(User).filter(User.id == msg.user_id).first() if msg.user_id else None
        result.append(ReportChatMessageResponse(
            id=msg.id,
            report_id=msg.report_id,
            role=msg.role,
            content=msg.content,
            created_at=msg.created_at,
            username=user.username if user else None,
        ))
    
    return result


@router.post("/{project_id}/analysis-reports/{report_id}/chat", response_model=AskQuestionResponse)
async def ask_report_question(
    project_id: int,
    report_id: int,
    request: AskQuestionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Ask a question about the documents in a report."""
    check_project_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if report.status != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Report is not ready for Q&A. Status: {report.status}"
        )
    
    # Get documents
    documents = db.query(ProjectDocument).filter(
        ProjectDocument.report_id == report_id,
        ProjectDocument.status == "completed"
    ).all()
    
    doc_data = [
        {"filename": doc.original_filename, "text": doc.extracted_text or ""}
        for doc in documents
    ]
    
    # Get chat history
    history = db.query(ReportChatMessage).filter(
        ReportChatMessage.report_id == report_id
    ).order_by(ReportChatMessage.created_at.asc()).all()
    
    chat_history = [{"role": msg.role, "content": msg.content} for msg in history]
    
    # Save user question
    user_message = ReportChatMessage(
        report_id=report_id,
        user_id=current_user.id,
        role="user",
        content=request.question,
    )
    db.add(user_message)
    db.commit()
    
    # Generate AI answer
    try:
        answer = await document_ai_service.answer_report_question(
            question=request.question,
            documents=doc_data,
            report_summary=report.combined_summary or "",
            chat_history=chat_history,
            custom_prompt=report.custom_prompt or "",
        )
    except Exception as e:
        logger.error(f"Error answering report question: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate answer: {str(e)}")
    
    # Save AI answer
    ai_message = ReportChatMessage(
        report_id=report_id,
        user_id=None,
        role="assistant",
        content=answer,
    )
    db.add(ai_message)
    db.commit()
    db.refresh(ai_message)
    
    return AskQuestionResponse(
        question=request.question,
        answer=answer,
        message_id=ai_message.id,
    )


@router.delete("/{project_id}/analysis-reports/{report_id}/chat")
def clear_report_chat_history(
    project_id: int,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Clear chat history for a report."""
    check_project_edit_access(db, project_id, current_user.id)
    
    report = db.query(DocumentAnalysisReport).filter(
        DocumentAnalysisReport.id == report_id,
        DocumentAnalysisReport.project_id == project_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    db.query(ReportChatMessage).filter(
        ReportChatMessage.report_id == report_id
    ).delete()
    db.commit()
    
    return {"status": "cleared", "report_id": report_id}
