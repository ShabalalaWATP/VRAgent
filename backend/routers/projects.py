from pathlib import Path
import shutil
import tempfile
import zipfile

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.schemas import Project, ProjectCreate, UploadResponse
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


@router.get("", response_model=list[Project])
def list_projects(db: Session = Depends(get_db)):
    return project_service.list_projects(db)


@router.post("", response_model=Project)
def create_project(project_in: ProjectCreate, db: Session = Depends(get_db)):
    return project_service.create_project(db, project_in)


@router.get("/{project_id}", response_model=Project)
def get_project(project_id: int, db: Session = Depends(get_db)):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    """Delete a project and all associated data (reports, findings, code chunks, etc.)."""
    from backend import models
    
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Get all scan runs for this project
    scan_runs = db.query(models.ScanRun).filter(models.ScanRun.project_id == project_id).all()
    scan_run_ids = [sr.id for sr in scan_runs]
    
    # Delete exploit scenarios for reports in this project
    reports = db.query(models.Report).filter(models.Report.project_id == project_id).all()
    for report in reports:
        db.query(models.ExploitScenario).filter(
            models.ExploitScenario.report_id == report.id
        ).delete()
    
    # Delete findings for all scan runs
    if scan_run_ids:
        db.query(models.Finding).filter(
            models.Finding.scan_run_id.in_(scan_run_ids)
        ).delete(synchronize_session=False)
    
    # Delete reports
    db.query(models.Report).filter(models.Report.project_id == project_id).delete()
    
    # Delete scan runs
    db.query(models.ScanRun).filter(models.ScanRun.project_id == project_id).delete()
    
    # Delete code chunks
    db.query(models.CodeChunk).filter(models.CodeChunk.project_id == project_id).delete()
    
    # Delete the project itself
    db.delete(project)
    db.commit()
    
    logger.info(f"Deleted project {project_id} and all associated data")
    return {"status": "deleted", "project_id": project_id}


@router.post("/{project_id}/upload", response_model=UploadResponse)
async def upload_project_code(
    project_id: int, file: UploadFile = File(...), db: Session = Depends(get_db)
):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

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
    db: Session = Depends(get_db)
):
    """
    Clone a GitHub/GitLab repository and prepare it for scanning.
    
    The repository will be cloned and packaged as a zip file for processing.
    Supports public repositories from GitHub, GitLab, Bitbucket, and Azure DevOps.
    """
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    try:
        # Clone the repository
        logger.info(f"Cloning repository {clone_request.repo_url} for project {project_id}")
        result = git_service.clone_repository(
            repo_url=clone_request.repo_url,
            branch=clone_request.branch,
            depth=1,  # Shallow clone for faster processing
        )
        
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Clone failed")
        
        # Create a zip file from the cloned repository
        tmp_dir = Path(tempfile.mkdtemp(prefix="clone_"))
        zip_path = tmp_dir / f"{result.repo_name}.zip"
        
        # Create zip file
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            clone_path = Path(result.path)
            for file_path in clone_path.rglob("*"):
                # Skip .git directory
                if ".git" in file_path.parts:
                    continue
                if file_path.is_file():
                    arcname = file_path.relative_to(clone_path)
                    zipf.write(file_path, arcname)
        
        # Clean up cloned directory
        git_service.cleanup_clone(result.path)
        
        # Save the upload path
        project_service.save_upload(db, project, str(zip_path))
        
        # Update project's git_url
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
