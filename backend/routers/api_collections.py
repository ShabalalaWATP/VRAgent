"""
API Collections Router

Endpoints for managing API collections, folders, and saved requests.
Postman-style organization for the API Tester.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.auth import get_current_active_user
from backend.core.database import get_db
from backend.models.models import User
from backend.services import api_collections_service as collections

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api-collections", tags=["API Collections"])


# =============================================================================
# Request/Response Models
# =============================================================================

class VariableModel(BaseModel):
    """A variable with key/value."""
    key: str
    value: str = ""
    type: str = "default"  # default or secret
    enabled: bool = True


class HeaderModel(BaseModel):
    """A header with key/value."""
    key: str
    value: str = ""
    enabled: bool = True


class ParamModel(BaseModel):
    """A query parameter."""
    key: str
    value: str = ""
    description: str = ""
    enabled: bool = True


class AuthConfigModel(BaseModel):
    """Authentication configuration."""
    type: str = "none"  # none, basic, bearer, api_key, oauth2, digest
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    oauth2_config: Optional[Dict[str, Any]] = None


# Collection Models
class CreateCollectionRequest(BaseModel):
    """Request to create a collection."""
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    variables: List[VariableModel] = []
    headers: List[HeaderModel] = []
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: str = ""
    test_script: str = ""


class UpdateCollectionRequest(BaseModel):
    """Request to update a collection."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    variables: Optional[List[VariableModel]] = None
    headers: Optional[List[HeaderModel]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: Optional[str] = None
    test_script: Optional[str] = None
    is_shared: Optional[bool] = None


# Folder Models
class CreateFolderRequest(BaseModel):
    """Request to create a folder."""
    collection_id: int
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    parent_folder_id: Optional[int] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: str = ""
    test_script: str = ""


class UpdateFolderRequest(BaseModel):
    """Request to update a folder."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    parent_folder_id: Optional[int] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: Optional[str] = None
    test_script: Optional[str] = None
    sort_order: Optional[int] = None


class MoveFolderRequest(BaseModel):
    """Request to move a folder."""
    new_parent_folder_id: Optional[int] = None
    new_collection_id: Optional[int] = None


# Request Models
class CreateRequestModel(BaseModel):
    """Request to create a saved request."""
    collection_id: int
    folder_id: Optional[int] = None
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    method: str = "GET"
    url: str = ""
    params: List[ParamModel] = []
    headers: List[HeaderModel] = []
    body_type: Optional[str] = None  # none, json, form-data, x-www-form-urlencoded, raw, binary, graphql
    body_content: str = ""
    body_form_data: List[Dict[str, Any]] = []
    graphql_query: str = ""
    graphql_variables: Optional[Dict[str, Any]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: str = ""
    test_script: str = ""
    timeout_ms: int = 30000
    follow_redirects: bool = True


class UpdateRequestModel(BaseModel):
    """Request to update a saved request."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    params: Optional[List[ParamModel]] = None
    headers: Optional[List[HeaderModel]] = None
    body_type: Optional[str] = None
    body_content: Optional[str] = None
    body_form_data: Optional[List[Dict[str, Any]]] = None
    graphql_query: Optional[str] = None
    graphql_variables: Optional[Dict[str, Any]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: Optional[str] = None
    test_script: Optional[str] = None
    timeout_ms: Optional[int] = None
    follow_redirects: Optional[bool] = None
    folder_id: Optional[int] = None
    sort_order: Optional[int] = None


class MoveRequestModel(BaseModel):
    """Request to move a request."""
    target_folder_id: Optional[int] = None
    target_collection_id: Optional[int] = None


class DuplicateRequestModel(BaseModel):
    """Request to duplicate a request."""
    new_name: Optional[str] = None
    target_folder_id: Optional[int] = None
    target_collection_id: Optional[int] = None


class SaveResponseExampleRequest(BaseModel):
    """Request to save a response example."""
    name: str
    status: int
    headers: Dict[str, str]
    body: str


class ReorderItemsRequest(BaseModel):
    """Request to reorder items."""
    items: List[Dict[str, Any]]  # [{"type": "folder"|"request", "id": 1, "sort_order": 0}]


class ImportCollectionRequest(BaseModel):
    """Request to import a collection."""
    data: Dict[str, Any]
    format: str = "auto"  # auto, postman, native


# =============================================================================
# Collection Endpoints
# =============================================================================

@router.post("/collections", response_model=Dict[str, Any])
async def create_collection(
    request: CreateCollectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new API collection."""
    try:
        result = collections.create_collection(
            db=db,
            user_id=current_user.id,
            name=request.name,
            description=request.description,
            variables=[v.model_dump() for v in request.variables],
            headers=[h.model_dump() for h in request.headers],
            auth_type=request.auth_type,
            auth_config=request.auth_config,
            pre_request_script=request.pre_request_script,
            test_script=request.test_script,
        )
        return {"success": True, "collection": result.to_dict()}
    except Exception as e:
        logger.error(f"Failed to create collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collections", response_model=Dict[str, Any])
async def list_collections(
    include_shared: bool = True,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """List all collections for the current user."""
    try:
        result = collections.get_collections(
            db=db,
            user_id=current_user.id,
            include_shared=include_shared,
        )
        return {
            "success": True,
            "collections": [c.to_dict() for c in result],
            "total": len(result),
        }
    except Exception as e:
        logger.error(f"Failed to list collections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collections/{collection_id}", response_model=Dict[str, Any])
async def get_collection(
    collection_id: int,
    include_contents: bool = True,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a single collection with its contents."""
    try:
        result = collections.get_collection(
            db=db,
            collection_id=collection_id,
            user_id=current_user.id,
            include_contents=include_contents,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {"success": True, "collection": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/collections/{collection_id}", response_model=Dict[str, Any])
async def update_collection(
    collection_id: int,
    request: UpdateCollectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Update a collection."""
    try:
        update_data = request.model_dump(exclude_unset=True)
        if "variables" in update_data:
            update_data["variables"] = [v.model_dump() if hasattr(v, 'model_dump') else v for v in update_data["variables"]]
        if "headers" in update_data:
            update_data["headers"] = [h.model_dump() if hasattr(h, 'model_dump') else h for h in update_data["headers"]]
        
        result = collections.update_collection(
            db=db,
            collection_id=collection_id,
            user_id=current_user.id,
            **update_data,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {"success": True, "collection": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/collections/{collection_id}", response_model=Dict[str, Any])
async def delete_collection(
    collection_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete a collection and all its contents."""
    try:
        success = collections.delete_collection(
            db=db,
            collection_id=collection_id,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {"success": True, "message": "Collection deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collections/{collection_id}/duplicate", response_model=Dict[str, Any])
async def duplicate_collection(
    collection_id: int,
    new_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Duplicate a collection with all its contents."""
    try:
        result = collections.duplicate_collection(
            db=db,
            collection_id=collection_id,
            user_id=current_user.id,
            new_name=new_name,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {"success": True, "collection": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to duplicate collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/collections/{collection_id}/export", response_model=Dict[str, Any])
async def export_collection(
    collection_id: int,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Export a collection to JSON or Postman format."""
    try:
        result = collections.export_collection(
            db=db,
            collection_id=collection_id,
            user_id=current_user.id,
            format=format,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found")
        return {"success": True, "data": result, "format": format}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/collections/import", response_model=Dict[str, Any])
async def import_collection(
    request: ImportCollectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Import a collection from JSON (supports Postman format)."""
    try:
        result = collections.import_collection(
            db=db,
            user_id=current_user.id,
            data=request.data,
            format=request.format,
        )
        if not result:
            raise HTTPException(status_code=400, detail="Failed to import collection")
        return {"success": True, "collection": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to import collection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Folder Endpoints
# =============================================================================

@router.post("/folders", response_model=Dict[str, Any])
async def create_folder(
    request: CreateFolderRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new folder in a collection."""
    try:
        result = collections.create_folder(
            db=db,
            collection_id=request.collection_id,
            user_id=current_user.id,
            name=request.name,
            description=request.description,
            parent_folder_id=request.parent_folder_id,
            auth_type=request.auth_type,
            auth_config=request.auth_config,
            pre_request_script=request.pre_request_script,
            test_script=request.test_script,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found or access denied")
        return {"success": True, "folder": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create folder: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/folders/{folder_id}", response_model=Dict[str, Any])
async def get_folder(
    folder_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a folder with its contents."""
    try:
        result = collections.get_folder(
            db=db,
            folder_id=folder_id,
            user_id=current_user.id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Folder not found")
        return {"success": True, "folder": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get folder: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/folders/{folder_id}", response_model=Dict[str, Any])
async def update_folder(
    folder_id: int,
    request: UpdateFolderRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Update a folder."""
    try:
        result = collections.update_folder(
            db=db,
            folder_id=folder_id,
            user_id=current_user.id,
            **request.model_dump(exclude_unset=True),
        )
        if not result:
            raise HTTPException(status_code=404, detail="Folder not found")
        return {"success": True, "folder": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update folder: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/folders/{folder_id}", response_model=Dict[str, Any])
async def delete_folder(
    folder_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete a folder and all its contents."""
    try:
        success = collections.delete_folder(
            db=db,
            folder_id=folder_id,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Folder not found")
        return {"success": True, "message": "Folder deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete folder: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/folders/{folder_id}/move", response_model=Dict[str, Any])
async def move_folder(
    folder_id: int,
    request: MoveFolderRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Move a folder to a new parent or collection."""
    try:
        result = collections.move_folder(
            db=db,
            folder_id=folder_id,
            user_id=current_user.id,
            new_parent_folder_id=request.new_parent_folder_id,
            new_collection_id=request.new_collection_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Folder not found or invalid move")
        return {"success": True, "folder": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to move folder: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Request Endpoints
# =============================================================================

@router.post("/requests", response_model=Dict[str, Any])
async def create_request(
    request: CreateRequestModel,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new saved request."""
    try:
        result = collections.create_request(
            db=db,
            collection_id=request.collection_id,
            user_id=current_user.id,
            folder_id=request.folder_id,
            name=request.name,
            description=request.description,
            method=request.method,
            url=request.url,
            params=[p.model_dump() for p in request.params],
            headers=[h.model_dump() for h in request.headers],
            body_type=request.body_type,
            body_content=request.body_content,
            body_form_data=request.body_form_data,
            graphql_query=request.graphql_query,
            graphql_variables=request.graphql_variables,
            auth_type=request.auth_type,
            auth_config=request.auth_config,
            pre_request_script=request.pre_request_script,
            test_script=request.test_script,
            timeout_ms=request.timeout_ms,
            follow_redirects=request.follow_redirects,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Collection not found or access denied")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requests/{request_id}", response_model=Dict[str, Any])
async def get_request(
    request_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a saved request."""
    try:
        result = collections.get_request(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/requests/{request_id}", response_model=Dict[str, Any])
async def update_request(
    request_id: int,
    request: UpdateRequestModel,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Update a saved request."""
    try:
        update_data = request.model_dump(exclude_unset=True)
        if "params" in update_data:
            update_data["params"] = [p.model_dump() if hasattr(p, 'model_dump') else p for p in update_data["params"]]
        if "headers" in update_data:
            update_data["headers"] = [h.model_dump() if hasattr(h, 'model_dump') else h for h in update_data["headers"]]
        
        result = collections.update_request(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
            **update_data,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/requests/{request_id}", response_model=Dict[str, Any])
async def delete_request(
    request_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete a saved request."""
    try:
        success = collections.delete_request(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "message": "Request deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/duplicate", response_model=Dict[str, Any])
async def duplicate_request(
    request_id: int,
    request: DuplicateRequestModel,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Duplicate a saved request."""
    try:
        result = collections.duplicate_request(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
            new_name=request.new_name,
            target_folder_id=request.target_folder_id,
            target_collection_id=request.target_collection_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to duplicate request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/move", response_model=Dict[str, Any])
async def move_request(
    request_id: int,
    request: MoveRequestModel,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Move a request to a different folder or collection."""
    try:
        result = collections.move_request(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
            target_folder_id=request.target_folder_id,
            target_collection_id=request.target_collection_id,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to move request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/requests/{request_id}/save-response", response_model=Dict[str, Any])
async def save_response_example(
    request_id: int,
    request: SaveResponseExampleRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Save a response example to a request."""
    try:
        result = collections.save_response_example(
            db=db,
            request_id=request_id,
            user_id=current_user.id,
            name=request.name,
            status=request.status,
            headers=request.headers,
            body=request.body,
        )
        if not result:
            raise HTTPException(status_code=404, detail="Request not found")
        return {"success": True, "request": result.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save response: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Bulk Operations
# =============================================================================

@router.post("/reorder", response_model=Dict[str, Any])
async def reorder_items(
    request: ReorderItemsRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Reorder folders and requests."""
    try:
        success = collections.reorder_items(
            db=db,
            user_id=current_user.id,
            items=request.items,
        )
        return {"success": success}
    except Exception as e:
        logger.error(f"Failed to reorder items: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Environment Models
# =============================================================================

class CreateEnvironmentRequest(BaseModel):
    """Request to create an environment."""
    name: str = Field(..., min_length=1, max_length=100)
    description: str = ""
    variables: Optional[List[VariableModel]] = None
    color: str = "#4caf50"


class UpdateEnvironmentRequest(BaseModel):
    """Request to update an environment."""
    name: Optional[str] = None
    description: Optional[str] = None
    variables: Optional[List[VariableModel]] = None
    color: Optional[str] = None


class GlobalVariableRequest(BaseModel):
    """Request to create/update a global variable."""
    key: str = Field(..., min_length=1, max_length=100)
    value: str = ""
    description: str = ""
    is_secret: bool = False


# =============================================================================
# Environment Operations
# =============================================================================

@router.post("/environments", response_model=Dict[str, Any])
async def create_environment(
    request: CreateEnvironmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new environment."""
    try:
        variables = [v.model_dump() for v in request.variables] if request.variables else None
        success, message, env = collections.create_environment(
            db=db,
            user_id=current_user.id,
            name=request.name,
            description=request.description,
            variables=variables,
            color=request.color,
        )
        if not success:
            raise HTTPException(status_code=400, detail=message)
        return {"success": True, "environment": env.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/environments", response_model=Dict[str, Any])
async def list_environments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """List all environments."""
    try:
        success, message, environments = collections.get_environments(
            db=db,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=500, detail=message)
        return {
            "success": True,
            "environments": [e.to_dict() for e in environments],
            "count": len(environments),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list environments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/environments/active", response_model=Dict[str, Any])
async def get_active_environment(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get the currently active environment."""
    try:
        success, message, env = collections.get_active_environment(
            db=db,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=500, detail=message)
        return {
            "success": True,
            "environment": env.to_dict() if env else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get active environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/environments/{environment_id}", response_model=Dict[str, Any])
async def get_environment(
    environment_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a specific environment."""
    try:
        success, message, env = collections.get_environment(
            db=db,
            user_id=current_user.id,
            environment_id=environment_id,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "environment": env.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/environments/{environment_id}", response_model=Dict[str, Any])
async def update_environment(
    environment_id: int,
    request: UpdateEnvironmentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Update an environment."""
    try:
        variables = [v.model_dump() for v in request.variables] if request.variables else None
        success, message, env = collections.update_environment(
            db=db,
            user_id=current_user.id,
            environment_id=environment_id,
            name=request.name,
            description=request.description,
            variables=variables,
            color=request.color,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "environment": env.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/environments/{environment_id}/activate", response_model=Dict[str, Any])
async def activate_environment(
    environment_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Set an environment as active."""
    try:
        success, message = collections.set_active_environment(
            db=db,
            user_id=current_user.id,
            environment_id=environment_id,
        )
        if not success:
            raise HTTPException(status_code=400, detail=message)
        return {"success": True, "message": message}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/environments/deactivate", response_model=Dict[str, Any])
async def deactivate_all_environments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Deactivate all environments."""
    try:
        success, message = collections.set_active_environment(
            db=db,
            user_id=current_user.id,
            environment_id=None,
        )
        if not success:
            raise HTTPException(status_code=400, detail=message)
        return {"success": True, "message": message}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate environments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/environments/{environment_id}", response_model=Dict[str, Any])
async def delete_environment(
    environment_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete an environment."""
    try:
        success, message = collections.delete_environment(
            db=db,
            user_id=current_user.id,
            environment_id=environment_id,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "message": message}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/environments/{environment_id}/duplicate", response_model=Dict[str, Any])
async def duplicate_environment(
    environment_id: int,
    new_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Duplicate an environment."""
    try:
        success, message, env = collections.duplicate_environment(
            db=db,
            user_id=current_user.id,
            environment_id=environment_id,
            new_name=new_name,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "environment": env.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to duplicate environment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Global Variable Operations
# =============================================================================

@router.post("/globals", response_model=Dict[str, Any])
async def create_global_variable(
    request: GlobalVariableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new global variable."""
    try:
        success, message, var = collections.create_global_variable(
            db=db,
            user_id=current_user.id,
            key=request.key,
            value=request.value,
            description=request.description,
            is_secret=request.is_secret,
        )
        if not success:
            raise HTTPException(status_code=400, detail=message)
        return {"success": True, "variable": var.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create global variable: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/globals", response_model=Dict[str, Any])
async def list_global_variables(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """List all global variables."""
    try:
        success, message, variables = collections.get_global_variables(
            db=db,
            user_id=current_user.id,
        )
        if not success:
            raise HTTPException(status_code=500, detail=message)
        return {
            "success": True,
            "variables": [v.to_dict() for v in variables],
            "count": len(variables),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list global variables: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/globals/{variable_id}", response_model=Dict[str, Any])
async def get_global_variable(
    variable_id: int,
    include_secret: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a specific global variable."""
    try:
        success, message, var = collections.get_global_variable(
            db=db,
            user_id=current_user.id,
            variable_id=variable_id,
            include_secret=include_secret,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "variable": var.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get global variable: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/globals/{variable_id}", response_model=Dict[str, Any])
async def update_global_variable(
    variable_id: int,
    request: GlobalVariableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Update a global variable."""
    try:
        success, message, var = collections.update_global_variable(
            db=db,
            user_id=current_user.id,
            variable_id=variable_id,
            key=request.key,
            value=request.value,
            description=request.description,
            is_secret=request.is_secret,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "variable": var.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update global variable: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/globals/{variable_id}", response_model=Dict[str, Any])
async def delete_global_variable(
    variable_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete a global variable."""
    try:
        success, message = collections.delete_global_variable(
            db=db,
            user_id=current_user.id,
            variable_id=variable_id,
        )
        if not success:
            raise HTTPException(status_code=404, detail=message)
        return {"success": True, "message": message}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete global variable: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Variable Substitution
# =============================================================================

@router.get("/variables/all", response_model=Dict[str, Any])
async def get_all_variables(
    collection_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get all variables for substitution (environment, global, collection)."""
    try:
        variables = collections.get_all_variables_for_substitution(
            db=db,
            user_id=current_user.id,
            collection_id=collection_id,
        )
        return {
            "success": True,
            **variables,
        }
    except Exception as e:
        logger.error(f"Failed to get all variables: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Request History
# =============================================================================

class HistoryEntryRequest(BaseModel):
    """Request body for creating a history entry."""
    method: str
    url: str
    original_url: Optional[str] = None
    headers: Optional[List[Dict[str, Any]]] = None
    body: Optional[str] = None
    collection_id: Optional[int] = None
    request_id: Optional[int] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_body: Optional[str] = None
    response_size_bytes: Optional[int] = None
    response_time_ms: Optional[float] = None
    request_cookies: Optional[List[Dict[str, Any]]] = None
    response_cookies: Optional[List[Dict[str, Any]]] = None
    test_results: Optional[List[Dict[str, Any]]] = None
    security_findings: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    environment_id: Optional[int] = None
    environment_name: Optional[str] = None


@router.post("/history", response_model=Dict[str, Any])
async def create_history_entry(
    request: HistoryEntryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Create a new history entry."""
    try:
        entry = collections.create_history_entry(
            db=db,
            user_id=current_user.id,
            method=request.method,
            url=request.url,
            original_url=request.original_url,
            headers=request.headers,
            body=request.body,
            collection_id=request.collection_id,
            request_id=request.request_id,
            status_code=request.status_code,
            status_text=request.status_text,
            response_headers=request.response_headers,
            response_body=request.response_body,
            response_size_bytes=request.response_size_bytes,
            response_time_ms=request.response_time_ms,
            request_cookies=request.request_cookies,
            response_cookies=request.response_cookies,
            test_results=request.test_results,
            security_findings=request.security_findings,
            error=request.error,
            environment_id=request.environment_id,
            environment_name=request.environment_name,
        )
        return {"success": True, "entry": entry.to_dict()}
    except Exception as e:
        logger.error(f"Failed to create history entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history", response_model=Dict[str, Any])
async def list_history(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    method: Optional[str] = None,
    url: Optional[str] = None,
    status: Optional[str] = Query(default=None, description="success, error, or redirect"),
    collection_id: Optional[int] = None,
    from_date: Optional[str] = Query(default=None, description="ISO format datetime"),
    to_date: Optional[str] = Query(default=None, description="ISO format datetime"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get request history with filtering and pagination."""
    try:
        from datetime import datetime as dt
        
        from_dt = None
        to_dt = None
        if from_date:
            from_dt = dt.fromisoformat(from_date.replace('Z', '+00:00'))
        if to_date:
            to_dt = dt.fromisoformat(to_date.replace('Z', '+00:00'))
        
        entries, total = collections.get_history(
            db=db,
            user_id=current_user.id,
            limit=limit,
            offset=offset,
            method_filter=method,
            url_filter=url,
            status_filter=status,
            collection_id=collection_id,
            from_date=from_dt,
            to_date=to_dt,
        )
        return {
            "success": True,
            "entries": [e.to_dict() for e in entries],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        logger.error(f"Failed to get history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/stats", response_model=Dict[str, Any])
async def get_history_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get statistics about request history."""
    try:
        stats = collections.get_history_stats(
            db=db,
            user_id=current_user.id,
        )
        return {"success": True, **stats}
    except Exception as e:
        logger.error(f"Failed to get history stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/{history_id}", response_model=Dict[str, Any])
async def get_history_entry(
    history_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Get a specific history entry."""
    try:
        entry = collections.get_history_entry(
            db=db,
            user_id=current_user.id,
            history_id=history_id,
        )
        if not entry:
            raise HTTPException(status_code=404, detail="History entry not found")
        return {"success": True, "entry": entry.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get history entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/history/{history_id}", response_model=Dict[str, Any])
async def delete_history_entry(
    history_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Delete a specific history entry."""
    try:
        success = collections.delete_history_entry(
            db=db,
            user_id=current_user.id,
            history_id=history_id,
        )
        if not success:
            raise HTTPException(status_code=404, detail="History entry not found")
        return {"success": True, "message": "History entry deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete history entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class ClearHistoryRequest(BaseModel):
    """Request body for clearing history."""
    older_than_days: Optional[int] = None
    collection_id: Optional[int] = None


@router.post("/history/clear", response_model=Dict[str, Any])
async def clear_history(
    request: Optional[ClearHistoryRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """Clear history entries."""
    try:
        from datetime import datetime as dt, timedelta
        
        older_than = None
        collection_id = None
        
        if request:
            if request.older_than_days:
                older_than = dt.utcnow() - timedelta(days=request.older_than_days)
            collection_id = request.collection_id
        
        count = collections.clear_history(
            db=db,
            user_id=current_user.id,
            older_than=older_than,
            collection_id=collection_id,
        )
        return {"success": True, "deleted_count": count}
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# AI-Powered Features
# =============================================================================

class NLToRequestRequest(BaseModel):
    """Request to convert natural language to API request."""
    query: str = Field(..., description="Natural language description of the request")
    base_url: Optional[str] = None
    available_endpoints: Optional[List[str]] = None
    auth_type: Optional[str] = None
    variables: Optional[Dict[str, str]] = None


class GenerateTestsRequest(BaseModel):
    """Request to generate tests from request/response."""
    request: Dict[str, Any] = Field(..., description="Request data (method, url, headers, body)")
    response: Dict[str, Any] = Field(..., description="Response data (status, headers, body, time)")
    test_types: Optional[List[str]] = None


class SuggestVariablesRequest(BaseModel):
    """Request to suggest variables from response."""
    response_body: str = Field(..., description="JSON response body")
    request_context: Optional[Dict[str, Any]] = None


class AnalyzeResponseRequest(BaseModel):
    """Request to analyze response for anomalies."""
    request: Dict[str, Any] = Field(..., description="Request data")
    response: Dict[str, Any] = Field(..., description="Response data")
    history: Optional[List[Dict[str, Any]]] = None


class GenerateDocsRequest(BaseModel):
    """Request to generate documentation from request/response."""
    request: Dict[str, Any] = Field(..., description="Request data")
    response: Dict[str, Any] = Field(..., description="Response data")


@router.post("/ai/generate-request", response_model=Dict[str, Any])
async def ai_generate_request(
    request: NLToRequestRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Convert natural language to API request using AI.
    
    Examples:
    - "Get all users with admin role"
    - "Create a new product with name 'Widget' and price 19.99"
    - "Delete the user with ID 123"
    - "Update the order status to 'shipped'"
    """
    try:
        from backend.services.api_tester_ai_service import natural_language_to_request
        
        context = {
            "base_url": request.base_url,
            "available_endpoints": request.available_endpoints,
            "auth_type": request.auth_type,
            "variables": request.variables,
        }
        
        result = await natural_language_to_request(
            query=request.query,
            context=context,
        )
        
        return {
            "success": True,
            "request": {
                "method": result.method,
                "url": result.url,
                "headers": result.headers,
                "body": result.body,
                "body_type": result.body_type,
            },
            "description": result.description,
            "confidence": result.confidence,
            "suggestions": result.suggestions,
        }
    except Exception as e:
        logger.error(f"AI request generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/generate-tests", response_model=Dict[str, Any])
async def ai_generate_tests(
    request: GenerateTestsRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Generate test assertions from request/response using AI.
    
    Analyzes the response and generates meaningful test assertions including:
    - Status code verification
    - Response time checks
    - JSON structure validation
    - Business logic assertions
    - Security checks
    """
    try:
        from backend.services.api_tester_ai_service import generate_tests_from_response
        
        tests = await generate_tests_from_response(
            request=request.request,
            response=request.response,
            test_types=request.test_types,
        )
        
        return {
            "success": True,
            "tests": [
                {
                    "name": t.name,
                    "type": t.type,
                    "target": t.target,
                    "operator": t.operator,
                    "expected": t.expected,
                    "code": t.code,
                    "description": t.description,
                }
                for t in tests
            ],
        }
    except Exception as e:
        logger.error(f"AI test generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/suggest-variables", response_model=Dict[str, Any])
async def ai_suggest_variables(
    request: SuggestVariablesRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Suggest variables to extract from response using AI.
    
    Analyzes the response and identifies values useful for subsequent requests:
    - IDs (user_id, order_id, etc.)
    - Tokens (auth tokens, CSRF tokens)
    - URLs (pagination, related resources)
    - Timestamps and counts
    """
    try:
        from backend.services.api_tester_ai_service import suggest_variables_from_response
        
        variables = await suggest_variables_from_response(
            response_body=request.response_body,
            request_context=request.request_context,
        )
        
        return {
            "success": True,
            "variables": [
                {
                    "name": v.name,
                    "json_path": v.json_path,
                    "sample_value": v.sample_value,
                    "description": v.description,
                    "scope": v.scope,
                }
                for v in variables
            ],
        }
    except Exception as e:
        logger.error(f"AI variable suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/analyze-response", response_model=Dict[str, Any])
async def ai_analyze_response(
    request: AnalyzeResponseRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Analyze response for anomalies using AI.
    
    Detects:
    - Security issues (sensitive data exposure, missing headers)
    - Performance concerns (slow response, large payload)
    - Data anomalies (null values, inconsistent structure)
    - Schema issues (wrong types, missing fields)
    """
    try:
        from backend.services.api_tester_ai_service import detect_response_anomalies
        
        anomalies = await detect_response_anomalies(
            request=request.request,
            response=request.response,
            history=request.history,
        )
        
        return {
            "success": True,
            "anomalies": [
                {
                    "type": a.type,
                    "severity": a.severity,
                    "title": a.title,
                    "description": a.description,
                    "location": a.location,
                    "suggestion": a.suggestion,
                }
                for a in anomalies
            ],
            "total_count": len(anomalies),
            "by_severity": {
                "error": len([a for a in anomalies if a.severity == "error"]),
                "warning": len([a for a in anomalies if a.severity == "warning"]),
                "info": len([a for a in anomalies if a.severity == "info"]),
            },
            "by_type": {
                "security": len([a for a in anomalies if a.type == "security"]),
                "performance": len([a for a in anomalies if a.type == "performance"]),
                "data": len([a for a in anomalies if a.type == "data"]),
                "schema": len([a for a in anomalies if a.type == "schema"]),
            },
        }
    except Exception as e:
        logger.error(f"AI response analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/generate-docs", response_model=Dict[str, Any])
async def ai_generate_docs(
    request: GenerateDocsRequest,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Generate API documentation from request/response using AI.
    
    Creates structured documentation including:
    - Summary and description
    - Parameters (path, query, header)
    - Request body schema
    - Response schema with examples
    - Tags and security requirements
    """
    try:
        from backend.services.api_tester_ai_service import generate_endpoint_documentation
        
        docs = await generate_endpoint_documentation(
            request=request.request,
            response=request.response,
        )
        
        return {
            "success": True,
            "documentation": docs,
        }
    except Exception as e:
        logger.error(f"AI documentation generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
