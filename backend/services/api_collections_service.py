"""
API Collections Service

Postman-style collections management for organizing API requests.
Supports collections, folders, and saved requests with full CRUD operations.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import Session
from sqlalchemy.orm import selectinload

from backend.models.models import (
    APICollection,
    APIFolder,
    APIRequest,
    APIEnvironment,
    APIGlobalVariable,
    APIRequestHistory,
    User,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Transfer Objects
# =============================================================================

@dataclass
class CollectionDTO:
    """Collection data transfer object."""
    id: Optional[int] = None
    name: str = ""
    description: str = ""
    variables: List[Dict[str, Any]] = field(default_factory=list)
    pre_request_script: str = ""
    test_script: str = ""
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    headers: List[Dict[str, Any]] = field(default_factory=list)
    is_shared: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    folders: List["FolderDTO"] = field(default_factory=list)
    requests: List["RequestDTO"] = field(default_factory=list)
    request_count: int = 0
    folder_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "variables": self.variables,
            "pre_request_script": self.pre_request_script,
            "test_script": self.test_script,
            "auth_type": self.auth_type,
            "auth_config": self.auth_config,
            "headers": self.headers,
            "is_shared": self.is_shared,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "folders": [f.to_dict() for f in self.folders],
            "requests": [r.to_dict() for r in self.requests],
            "request_count": self.request_count,
            "folder_count": self.folder_count,
        }


@dataclass
class FolderDTO:
    """Folder data transfer object."""
    id: Optional[int] = None
    collection_id: Optional[int] = None
    parent_folder_id: Optional[int] = None
    name: str = ""
    description: str = ""
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: str = ""
    test_script: str = ""
    sort_order: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    subfolders: List["FolderDTO"] = field(default_factory=list)
    requests: List["RequestDTO"] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "collection_id": self.collection_id,
            "parent_folder_id": self.parent_folder_id,
            "name": self.name,
            "description": self.description,
            "auth_type": self.auth_type,
            "auth_config": self.auth_config,
            "pre_request_script": self.pre_request_script,
            "test_script": self.test_script,
            "sort_order": self.sort_order,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "subfolders": [f.to_dict() for f in self.subfolders],
            "requests": [r.to_dict() for r in self.requests],
        }


@dataclass
class RequestDTO:
    """Request data transfer object."""
    id: Optional[int] = None
    collection_id: Optional[int] = None
    folder_id: Optional[int] = None
    name: str = ""
    description: str = ""
    method: str = "GET"
    url: str = ""
    params: List[Dict[str, Any]] = field(default_factory=list)
    headers: List[Dict[str, Any]] = field(default_factory=list)
    body_type: Optional[str] = None
    body_content: str = ""
    body_form_data: List[Dict[str, Any]] = field(default_factory=list)
    graphql_query: str = ""
    graphql_variables: Optional[Dict[str, Any]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None
    pre_request_script: str = ""
    test_script: str = ""
    timeout_ms: int = 30000
    follow_redirects: bool = True
    saved_responses: List[Dict[str, Any]] = field(default_factory=list)
    sort_order: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "collection_id": self.collection_id,
            "folder_id": self.folder_id,
            "name": self.name,
            "description": self.description,
            "method": self.method,
            "url": self.url,
            "params": self.params,
            "headers": self.headers,
            "body_type": self.body_type,
            "body_content": self.body_content,
            "body_form_data": self.body_form_data,
            "graphql_query": self.graphql_query,
            "graphql_variables": self.graphql_variables,
            "auth_type": self.auth_type,
            "auth_config": self.auth_config,
            "pre_request_script": self.pre_request_script,
            "test_script": self.test_script,
            "timeout_ms": self.timeout_ms,
            "follow_redirects": self.follow_redirects,
            "saved_responses": self.saved_responses,
            "sort_order": self.sort_order,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class EnvironmentDTO:
    """Environment data transfer object."""
    id: Optional[int] = None
    name: str = ""
    description: str = ""
    variables: List[Dict[str, Any]] = field(default_factory=list)
    is_active: bool = False
    color: str = "#4caf50"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "variables": self.variables,
            "is_active": self.is_active,
            "color": self.color,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class GlobalVariableDTO:
    """Global variable data transfer object."""
    id: Optional[int] = None
    key: str = ""
    value: str = ""
    description: str = ""
    is_secret: bool = False
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "is_secret": self.is_secret,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# =============================================================================
# Collection Operations
# =============================================================================

def create_collection(
    db: Session,
    user_id: int,
    name: str,
    description: str = "",
    variables: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[List[Dict[str, Any]]] = None,
    auth_type: Optional[str] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    pre_request_script: str = "",
    test_script: str = "",
) -> CollectionDTO:
    """Create a new API collection."""
    collection = APICollection(
        user_id=user_id,
        name=name,
        description=description,
        variables=variables or [],
        headers=headers or [],
        auth_type=auth_type,
        auth_config=auth_config,
        pre_request_script=pre_request_script,
        test_script=test_script,
    )
    db.add(collection)
    db.commit()
    db.refresh(collection)
    
    return _collection_to_dto(collection)


def get_collections(
    db: Session,
    user_id: int,
    include_shared: bool = True,
) -> List[CollectionDTO]:
    """Get all collections for a user."""
    conditions = [APICollection.user_id == user_id]
    
    if include_shared:
        conditions = [
            or_(
                APICollection.user_id == user_id,
                APICollection.is_shared == True,
            )
        ]
    
    result = db.execute(
        select(APICollection)
        .where(*conditions)
        .order_by(APICollection.name)
    )
    collections = result.scalars().all()
    
    dtos = []
    for c in collections:
        dto = _collection_to_dto(c)
        # Get counts
        folder_count = db.execute(
            select(func.count(APIFolder.id)).where(APIFolder.collection_id == c.id)
        )
        request_count = db.execute(
            select(func.count(APIRequest.id)).where(APIRequest.collection_id == c.id)
        )
        dto.folder_count = folder_count.scalar() or 0
        dto.request_count = request_count.scalar() or 0
        dtos.append(dto)
    
    return dtos


def get_collection(
    db: Session,
    collection_id: int,
    user_id: int,
    include_contents: bool = True,
) -> Optional[CollectionDTO]:
    """Get a single collection with optional contents."""
    result = db.execute(
        select(APICollection).where(
            APICollection.id == collection_id,
            or_(
                APICollection.user_id == user_id,
                APICollection.is_shared == True,
            )
        )
    )
    collection = result.scalar_one_or_none()
    
    if not collection:
        return None
    
    dto = _collection_to_dto(collection)
    
    if include_contents:
        # Get folders (build tree)
        folders_result = db.execute(
            select(APIFolder)
            .where(APIFolder.collection_id == collection_id)
            .order_by(APIFolder.sort_order, APIFolder.name)
        )
        all_folders = folders_result.scalars().all()
        
        # Get requests
        requests_result = db.execute(
            select(APIRequest)
            .where(APIRequest.collection_id == collection_id)
            .order_by(APIRequest.sort_order, APIRequest.name)
        )
        all_requests = requests_result.scalars().all()
        
        # Build folder tree
        folder_map = {f.id: _folder_to_dto(f) for f in all_folders}
        root_folders = []
        
        for f in all_folders:
            folder_dto = folder_map[f.id]
            if f.parent_folder_id:
                if f.parent_folder_id in folder_map:
                    folder_map[f.parent_folder_id].subfolders.append(folder_dto)
            else:
                root_folders.append(folder_dto)
        
        # Assign requests to folders or collection root
        for r in all_requests:
            request_dto = _request_to_dto(r)
            if r.folder_id and r.folder_id in folder_map:
                folder_map[r.folder_id].requests.append(request_dto)
            else:
                dto.requests.append(request_dto)
        
        dto.folders = root_folders
        dto.folder_count = len(all_folders)
        dto.request_count = len(all_requests)
    
    return dto


def update_collection(
    db: Session,
    collection_id: int,
    user_id: int,
    **kwargs,
) -> Optional[CollectionDTO]:
    """Update a collection."""
    result = db.execute(
        select(APICollection).where(
            APICollection.id == collection_id,
            APICollection.user_id == user_id,
        )
    )
    collection = result.scalar_one_or_none()
    
    if not collection:
        return None
    
    # Update allowed fields
    allowed_fields = {
        "name", "description", "variables", "headers",
        "auth_type", "auth_config", "pre_request_script",
        "test_script", "is_shared",
    }
    
    for key, value in kwargs.items():
        if key in allowed_fields and value is not None:
            setattr(collection, key, value)
    
    db.commit()
    db.refresh(collection)
    
    return _collection_to_dto(collection)


def delete_collection(
    db: Session,
    collection_id: int,
    user_id: int,
) -> bool:
    """Delete a collection and all its contents."""
    result = db.execute(
        select(APICollection).where(
            APICollection.id == collection_id,
            APICollection.user_id == user_id,
        )
    )
    collection = result.scalar_one_or_none()
    
    if not collection:
        return False
    
    db.delete(collection)
    db.commit()
    return True


def duplicate_collection(
    db: Session,
    collection_id: int,
    user_id: int,
    new_name: Optional[str] = None,
) -> Optional[CollectionDTO]:
    """Duplicate a collection with all its contents."""
    original = get_collection(db, collection_id, user_id, include_contents=True)
    if not original:
        return None
    
    # Create new collection
    new_collection = create_collection(
        db=db,
        user_id=user_id,
        name=new_name or f"{original.name} (Copy)",
        description=original.description,
        variables=original.variables,
        headers=original.headers,
        auth_type=original.auth_type,
        auth_config=original.auth_config,
        pre_request_script=original.pre_request_script,
        test_script=original.test_script,
    )
    
    # Map old folder IDs to new folder IDs
    folder_id_map = {}
    
    # Duplicate folders (recursive helper)
    def duplicate_folder(folder: FolderDTO, parent_id: Optional[int] = None):
        new_folder = create_folder(
            db=db,
            collection_id=new_collection.id,
            user_id=user_id,
            name=folder.name,
            description=folder.description,
            parent_folder_id=parent_id,
            auth_type=folder.auth_type,
            auth_config=folder.auth_config,
            pre_request_script=folder.pre_request_script,
            test_script=folder.test_script,
            sort_order=folder.sort_order,
        )
        folder_id_map[folder.id] = new_folder.id
        
        # Duplicate subfolders
        for subfolder in folder.subfolders:
            duplicate_folder(subfolder, new_folder.id)
        
        # Duplicate requests in folder
        for request in folder.requests:
            create_request(
                db=db,
                collection_id=new_collection.id,
                user_id=user_id,
                folder_id=new_folder.id,
                name=request.name,
                description=request.description,
                method=request.method,
                url=request.url,
                params=request.params,
                headers=request.headers,
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
                sort_order=request.sort_order,
            )
    
    # Duplicate root folders
    for folder in original.folders:
        duplicate_folder(folder)
    
    # Duplicate root-level requests
    for request in original.requests:
        create_request(
            db=db,
            collection_id=new_collection.id,
            user_id=user_id,
            name=request.name,
            description=request.description,
            method=request.method,
            url=request.url,
            params=request.params,
            headers=request.headers,
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
            sort_order=request.sort_order,
        )
    
    return get_collection(db, new_collection.id, user_id, include_contents=True)


# =============================================================================
# Folder Operations
# =============================================================================

def create_folder(
    db: Session,
    collection_id: int,
    user_id: int,
    name: str,
    description: str = "",
    parent_folder_id: Optional[int] = None,
    auth_type: Optional[str] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    pre_request_script: str = "",
    test_script: str = "",
    sort_order: int = 0,
) -> Optional[FolderDTO]:
    """Create a new folder in a collection."""
    # Verify collection ownership
    collection_result = db.execute(
        select(APICollection).where(
            APICollection.id == collection_id,
            APICollection.user_id == user_id,
        )
    )
    if not collection_result.scalar_one_or_none():
        return None
    
    # If parent folder specified, verify it exists in same collection
    if parent_folder_id:
        parent_result = db.execute(
            select(APIFolder).where(
                APIFolder.id == parent_folder_id,
                APIFolder.collection_id == collection_id,
            )
        )
        if not parent_result.scalar_one_or_none():
            return None
    
    folder = APIFolder(
        collection_id=collection_id,
        parent_folder_id=parent_folder_id,
        name=name,
        description=description,
        auth_type=auth_type,
        auth_config=auth_config,
        pre_request_script=pre_request_script,
        test_script=test_script,
        sort_order=sort_order,
    )
    db.add(folder)
    db.commit()
    db.refresh(folder)
    
    return _folder_to_dto(folder)


def get_folder(
    db: Session,
    folder_id: int,
    user_id: int,
) -> Optional[FolderDTO]:
    """Get a folder with its contents."""
    result = db.execute(
        select(APIFolder)
        .join(APICollection, APIFolder.collection_id == APICollection.id)
        .where(
            APIFolder.id == folder_id,
            or_(
                APICollection.user_id == user_id,
                APICollection.is_shared == True,
            )
        )
    )
    folder = result.scalar_one_or_none()
    
    if not folder:
        return None
    
    dto = _folder_to_dto(folder)
    
    # Get subfolders
    subfolders_result = db.execute(
        select(APIFolder)
        .where(APIFolder.parent_folder_id == folder_id)
        .order_by(APIFolder.sort_order, APIFolder.name)
    )
    dto.subfolders = [_folder_to_dto(f) for f in subfolders_result.scalars().all()]
    
    # Get requests
    requests_result = db.execute(
        select(APIRequest)
        .where(APIRequest.folder_id == folder_id)
        .order_by(APIRequest.sort_order, APIRequest.name)
    )
    dto.requests = [_request_to_dto(r) for r in requests_result.scalars().all()]
    
    return dto


def update_folder(
    db: Session,
    folder_id: int,
    user_id: int,
    **kwargs,
) -> Optional[FolderDTO]:
    """Update a folder."""
    result = db.execute(
        select(APIFolder)
        .join(APICollection, APIFolder.collection_id == APICollection.id)
        .where(
            APIFolder.id == folder_id,
            APICollection.user_id == user_id,
        )
    )
    folder = result.scalar_one_or_none()
    
    if not folder:
        return None
    
    allowed_fields = {
        "name", "description", "parent_folder_id",
        "auth_type", "auth_config", "pre_request_script",
        "test_script", "sort_order",
    }
    
    for key, value in kwargs.items():
        if key in allowed_fields:
            setattr(folder, key, value)
    
    db.commit()
    db.refresh(folder)
    
    return _folder_to_dto(folder)


def delete_folder(
    db: Session,
    folder_id: int,
    user_id: int,
) -> bool:
    """Delete a folder and all its contents."""
    result = db.execute(
        select(APIFolder)
        .join(APICollection, APIFolder.collection_id == APICollection.id)
        .where(
            APIFolder.id == folder_id,
            APICollection.user_id == user_id,
        )
    )
    folder = result.scalar_one_or_none()
    
    if not folder:
        return False
    
    db.delete(folder)
    db.commit()
    return True


def move_folder(
    db: Session,
    folder_id: int,
    user_id: int,
    new_parent_folder_id: Optional[int],
    new_collection_id: Optional[int] = None,
) -> Optional[FolderDTO]:
    """Move a folder to a new parent or collection."""
    result = db.execute(
        select(APIFolder)
        .join(APICollection, APIFolder.collection_id == APICollection.id)
        .where(
            APIFolder.id == folder_id,
            APICollection.user_id == user_id,
        )
    )
    folder = result.scalar_one_or_none()
    
    if not folder:
        return None
    
    # Prevent moving folder into itself or its descendants
    if new_parent_folder_id:
        # Check for circular reference
        current = new_parent_folder_id
        while current:
            if current == folder_id:
                return None  # Would create circular reference
            parent_result = db.execute(
                select(APIFolder.parent_folder_id).where(APIFolder.id == current)
            )
            current = parent_result.scalar_one_or_none()
    
    if new_collection_id:
        # Verify ownership of target collection
        target_result = db.execute(
            select(APICollection).where(
                APICollection.id == new_collection_id,
                APICollection.user_id == user_id,
            )
        )
        if not target_result.scalar_one_or_none():
            return None
        folder.collection_id = new_collection_id
    
    folder.parent_folder_id = new_parent_folder_id
    db.commit()
    db.refresh(folder)
    
    return _folder_to_dto(folder)


# =============================================================================
# Request Operations
# =============================================================================

def create_request(
    db: Session,
    collection_id: int,
    user_id: int,
    name: str,
    method: str = "GET",
    url: str = "",
    description: str = "",
    folder_id: Optional[int] = None,
    params: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[List[Dict[str, Any]]] = None,
    body_type: Optional[str] = None,
    body_content: str = "",
    body_form_data: Optional[List[Dict[str, Any]]] = None,
    graphql_query: str = "",
    graphql_variables: Optional[Dict[str, Any]] = None,
    auth_type: Optional[str] = None,
    auth_config: Optional[Dict[str, Any]] = None,
    pre_request_script: str = "",
    test_script: str = "",
    timeout_ms: int = 30000,
    follow_redirects: bool = True,
    sort_order: int = 0,
) -> Optional[RequestDTO]:
    """Create a new request in a collection."""
    # Verify collection ownership
    collection_result = db.execute(
        select(APICollection).where(
            APICollection.id == collection_id,
            APICollection.user_id == user_id,
        )
    )
    if not collection_result.scalar_one_or_none():
        return None
    
    # If folder specified, verify it exists in same collection
    if folder_id:
        folder_result = db.execute(
            select(APIFolder).where(
                APIFolder.id == folder_id,
                APIFolder.collection_id == collection_id,
            )
        )
        if not folder_result.scalar_one_or_none():
            return None
    
    request = APIRequest(
        collection_id=collection_id,
        folder_id=folder_id,
        name=name,
        description=description,
        method=method.upper(),
        url=url,
        params=params or [],
        headers=headers or [],
        body_type=body_type,
        body_content=body_content,
        body_form_data=body_form_data or [],
        graphql_query=graphql_query,
        graphql_variables=graphql_variables,
        auth_type=auth_type,
        auth_config=auth_config,
        pre_request_script=pre_request_script,
        test_script=test_script,
        timeout_ms=timeout_ms,
        follow_redirects=follow_redirects,
        sort_order=sort_order,
    )
    db.add(request)
    db.commit()
    db.refresh(request)
    
    return _request_to_dto(request)


def get_request(
    db: Session,
    request_id: int,
    user_id: int,
) -> Optional[RequestDTO]:
    """Get a single request."""
    result = db.execute(
        select(APIRequest)
        .join(APICollection, APIRequest.collection_id == APICollection.id)
        .where(
            APIRequest.id == request_id,
            or_(
                APICollection.user_id == user_id,
                APICollection.is_shared == True,
            )
        )
    )
    request = result.scalar_one_or_none()
    
    if not request:
        return None
    
    return _request_to_dto(request)


def update_request(
    db: Session,
    request_id: int,
    user_id: int,
    **kwargs,
) -> Optional[RequestDTO]:
    """Update a request."""
    result = db.execute(
        select(APIRequest)
        .join(APICollection, APIRequest.collection_id == APICollection.id)
        .where(
            APIRequest.id == request_id,
            APICollection.user_id == user_id,
        )
    )
    request = result.scalar_one_or_none()
    
    if not request:
        return None
    
    allowed_fields = {
        "name", "description", "method", "url", "params", "headers",
        "body_type", "body_content", "body_form_data",
        "graphql_query", "graphql_variables",
        "auth_type", "auth_config", "pre_request_script", "test_script",
        "timeout_ms", "follow_redirects", "saved_responses", "sort_order",
        "folder_id",
    }
    
    for key, value in kwargs.items():
        if key in allowed_fields:
            if key == "method" and value:
                value = value.upper()
            setattr(request, key, value)
    
    db.commit()
    db.refresh(request)
    
    return _request_to_dto(request)


def delete_request(
    db: Session,
    request_id: int,
    user_id: int,
) -> bool:
    """Delete a request."""
    result = db.execute(
        select(APIRequest)
        .join(APICollection, APIRequest.collection_id == APICollection.id)
        .where(
            APIRequest.id == request_id,
            APICollection.user_id == user_id,
        )
    )
    request = result.scalar_one_or_none()
    
    if not request:
        return False
    
    db.delete(request)
    db.commit()
    return True


def duplicate_request(
    db: Session,
    request_id: int,
    user_id: int,
    new_name: Optional[str] = None,
    target_folder_id: Optional[int] = None,
    target_collection_id: Optional[int] = None,
) -> Optional[RequestDTO]:
    """Duplicate a request."""
    original = get_request(db, request_id, user_id)
    if not original:
        return None
    
    return create_request(
        db=db,
        collection_id=target_collection_id or original.collection_id,
        user_id=user_id,
        folder_id=target_folder_id if target_folder_id is not None else original.folder_id,
        name=new_name or f"{original.name} (Copy)",
        description=original.description,
        method=original.method,
        url=original.url,
        params=original.params,
        headers=original.headers,
        body_type=original.body_type,
        body_content=original.body_content,
        body_form_data=original.body_form_data,
        graphql_query=original.graphql_query,
        graphql_variables=original.graphql_variables,
        auth_type=original.auth_type,
        auth_config=original.auth_config,
        pre_request_script=original.pre_request_script,
        test_script=original.test_script,
        timeout_ms=original.timeout_ms,
        follow_redirects=original.follow_redirects,
        sort_order=original.sort_order + 1,
    )


def move_request(
    db: Session,
    request_id: int,
    user_id: int,
    target_folder_id: Optional[int],
    target_collection_id: Optional[int] = None,
) -> Optional[RequestDTO]:
    """Move a request to a different folder or collection."""
    result = db.execute(
        select(APIRequest)
        .join(APICollection, APIRequest.collection_id == APICollection.id)
        .where(
            APIRequest.id == request_id,
            APICollection.user_id == user_id,
        )
    )
    request = result.scalar_one_or_none()
    
    if not request:
        return None
    
    if target_collection_id:
        # Verify ownership of target collection
        target_result = db.execute(
            select(APICollection).where(
                APICollection.id == target_collection_id,
                APICollection.user_id == user_id,
            )
        )
        if not target_result.scalar_one_or_none():
            return None
        request.collection_id = target_collection_id
        
        # If moving to new collection, verify folder exists there
        if target_folder_id:
            folder_result = db.execute(
                select(APIFolder).where(
                    APIFolder.id == target_folder_id,
                    APIFolder.collection_id == target_collection_id,
                )
            )
            if not folder_result.scalar_one_or_none():
                target_folder_id = None  # Put in collection root
    
    request.folder_id = target_folder_id
    db.commit()
    db.refresh(request)
    
    return _request_to_dto(request)


def save_response_example(
    db: Session,
    request_id: int,
    user_id: int,
    name: str,
    status: int,
    headers: Dict[str, str],
    body: str,
) -> Optional[RequestDTO]:
    """Save a response example to a request."""
    result = db.execute(
        select(APIRequest)
        .join(APICollection, APIRequest.collection_id == APICollection.id)
        .where(
            APIRequest.id == request_id,
            APICollection.user_id == user_id,
        )
    )
    request = result.scalar_one_or_none()
    
    if not request:
        return None
    
    saved_responses = request.saved_responses or []
    saved_responses.append({
        "name": name,
        "status": status,
        "headers": headers,
        "body": body,
        "saved_at": datetime.now().isoformat(),
    })
    request.saved_responses = saved_responses
    
    db.commit()
    db.refresh(request)
    
    return _request_to_dto(request)


# =============================================================================
# Bulk Operations
# =============================================================================

def reorder_items(
    db: Session,
    user_id: int,
    items: List[Dict[str, Any]],
) -> bool:
    """
    Reorder folders and requests.
    
    items: [{"type": "folder"|"request", "id": 1, "sort_order": 0}, ...]
    """
    for item in items:
        item_type = item.get("type")
        item_id = item.get("id")
        sort_order = item.get("sort_order", 0)
        
        if item_type == "folder":
            db.execute(
                select(APIFolder)
                .join(APICollection, APIFolder.collection_id == APICollection.id)
                .where(
                    APIFolder.id == item_id,
                    APICollection.user_id == user_id,
                )
            )
            result = db.execute(
                select(APIFolder).where(APIFolder.id == item_id)
            )
            folder = result.scalar_one_or_none()
            if folder:
                folder.sort_order = sort_order
        
        elif item_type == "request":
            result = db.execute(
                select(APIRequest).where(APIRequest.id == item_id)
            )
            request = result.scalar_one_or_none()
            if request:
                request.sort_order = sort_order
    
    db.commit()
    return True


# =============================================================================
# Import/Export
# =============================================================================

def export_collection(
    db: Session,
    collection_id: int,
    user_id: int,
    format: str = "json",
) -> Optional[Dict[str, Any]]:
    """Export a collection to JSON format (compatible with Postman import)."""
    collection = get_collection(db, collection_id, user_id, include_contents=True)
    if not collection:
        return None
    
    if format == "postman":
        return _to_postman_format(collection)
    else:
        return collection.to_dict()


def import_collection(
    db: Session,
    user_id: int,
    data: Dict[str, Any],
    format: str = "auto",
) -> Optional[CollectionDTO]:
    """Import a collection from JSON (supports Postman format)."""
    # Auto-detect format
    if format == "auto":
        if "info" in data and "_postman_id" in data.get("info", {}):
            format = "postman"
        else:
            format = "native"
    
    if format == "postman":
        return _import_postman_collection(db, user_id, data)
    else:
        return _import_native_collection(db, user_id, data)


def _import_postman_collection(
    db: Session,
    user_id: int,
    data: Dict[str, Any],
) -> Optional[CollectionDTO]:
    """Import a Postman collection."""
    info = data.get("info", {})
    
    # Create collection
    collection = create_collection(
        db=db,
        user_id=user_id,
        name=info.get("name", "Imported Collection"),
        description=info.get("description", ""),
        variables=[
            {"key": v.get("key"), "value": v.get("value"), "enabled": not v.get("disabled", False)}
            for v in data.get("variable", [])
        ],
    )
    
    # Import items (recursive)
    def import_items(items: List[Dict], parent_folder_id: Optional[int] = None):
        for item in items:
            if "item" in item:
                # It's a folder
                folder = create_folder(
                    db=db,
                    collection_id=collection.id,
                    user_id=user_id,
                    name=item.get("name", "Folder"),
                    description=item.get("description", ""),
                    parent_folder_id=parent_folder_id,
                )
                import_items(item["item"], folder.id)
            else:
                # It's a request
                request_data = item.get("request", {})
                if isinstance(request_data, str):
                    # Simple URL string
                    url = request_data
                    method = "GET"
                    headers = []
                    body_content = ""
                    body_type = None
                else:
                    url_obj = request_data.get("url", {})
                    if isinstance(url_obj, str):
                        url = url_obj
                    else:
                        url = url_obj.get("raw", "")
                    
                    method = request_data.get("method", "GET")
                    headers = [
                        {"key": h.get("key"), "value": h.get("value"), "enabled": not h.get("disabled", False)}
                        for h in request_data.get("header", [])
                    ]
                    
                    body = request_data.get("body", {})
                    body_type = body.get("mode")
                    body_content = body.get("raw", "")
                
                create_request(
                    db=db,
                    collection_id=collection.id,
                    user_id=user_id,
                    folder_id=parent_folder_id,
                    name=item.get("name", "Request"),
                    method=method,
                    url=url,
                    headers=headers,
                    body_type=body_type,
                    body_content=body_content,
                )
    
    if "item" in data:
        import_items(data["item"])
    
    return get_collection(db, collection.id, user_id, include_contents=True)


def _import_native_collection(
    db: Session,
    user_id: int,
    data: Dict[str, Any],
) -> Optional[CollectionDTO]:
    """Import a native format collection."""
    collection = create_collection(
        db=db,
        user_id=user_id,
        name=data.get("name", "Imported Collection"),
        description=data.get("description", ""),
        variables=data.get("variables", []),
        headers=data.get("headers", []),
        auth_type=data.get("auth_type"),
        auth_config=data.get("auth_config"),
        pre_request_script=data.get("pre_request_script", ""),
        test_script=data.get("test_script", ""),
    )
    
    # Import folders recursively
    def import_folder(folder_data: Dict, parent_id: Optional[int] = None):
        folder = create_folder(
            db=db,
            collection_id=collection.id,
            user_id=user_id,
            name=folder_data.get("name", "Folder"),
            description=folder_data.get("description", ""),
            parent_folder_id=parent_id,
            auth_type=folder_data.get("auth_type"),
            auth_config=folder_data.get("auth_config"),
            pre_request_script=folder_data.get("pre_request_script", ""),
            test_script=folder_data.get("test_script", ""),
            sort_order=folder_data.get("sort_order", 0),
        )
        
        for subfolder in folder_data.get("subfolders", []):
            import_folder(subfolder, folder.id)
        
        for req in folder_data.get("requests", []):
            import_request(req, folder.id)
    
    def import_request(req_data: Dict, folder_id: Optional[int] = None):
        create_request(
            db=db,
            collection_id=collection.id,
            user_id=user_id,
            folder_id=folder_id,
            name=req_data.get("name", "Request"),
            description=req_data.get("description", ""),
            method=req_data.get("method", "GET"),
            url=req_data.get("url", ""),
            params=req_data.get("params", []),
            headers=req_data.get("headers", []),
            body_type=req_data.get("body_type"),
            body_content=req_data.get("body_content", ""),
            body_form_data=req_data.get("body_form_data", []),
            graphql_query=req_data.get("graphql_query", ""),
            graphql_variables=req_data.get("graphql_variables"),
            auth_type=req_data.get("auth_type"),
            auth_config=req_data.get("auth_config"),
            pre_request_script=req_data.get("pre_request_script", ""),
            test_script=req_data.get("test_script", ""),
            timeout_ms=req_data.get("timeout_ms", 30000),
            follow_redirects=req_data.get("follow_redirects", True),
            sort_order=req_data.get("sort_order", 0),
        )
    
    for folder in data.get("folders", []):
        import_folder(folder)
    
    for req in data.get("requests", []):
        import_request(req)
    
    return get_collection(db, collection.id, user_id, include_contents=True)


def _to_postman_format(collection: CollectionDTO) -> Dict[str, Any]:
    """Convert collection to Postman format."""
    import uuid
    
    def convert_request(req: RequestDTO) -> Dict[str, Any]:
        body = {}
        if req.body_type:
            body = {
                "mode": req.body_type,
                "raw": req.body_content,
            }
            if req.body_type == "json":
                body["options"] = {"raw": {"language": "json"}}
        
        return {
            "name": req.name,
            "request": {
                "method": req.method,
                "header": [
                    {"key": h.get("key"), "value": h.get("value"), "disabled": not h.get("enabled", True)}
                    for h in req.headers
                ],
                "body": body if body else None,
                "url": {
                    "raw": req.url,
                },
                "description": req.description,
            },
        }
    
    def convert_folder(folder: FolderDTO) -> Dict[str, Any]:
        items = []
        for subfolder in folder.subfolders:
            items.append(convert_folder(subfolder))
        for req in folder.requests:
            items.append(convert_request(req))
        
        return {
            "name": folder.name,
            "description": folder.description,
            "item": items,
        }
    
    items = []
    for folder in collection.folders:
        items.append(convert_folder(folder))
    for req in collection.requests:
        items.append(convert_request(req))
    
    return {
        "info": {
            "_postman_id": str(uuid.uuid4()),
            "name": collection.name,
            "description": collection.description,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
        "variable": [
            {"key": v.get("key"), "value": v.get("value"), "disabled": not v.get("enabled", True)}
            for v in collection.variables
        ],
    }


# =============================================================================
# Helpers
# =============================================================================

def _collection_to_dto(collection: APICollection) -> CollectionDTO:
    """Convert SQLAlchemy model to DTO."""
    return CollectionDTO(
        id=collection.id,
        name=collection.name,
        description=collection.description or "",
        variables=collection.variables or [],
        pre_request_script=collection.pre_request_script or "",
        test_script=collection.test_script or "",
        auth_type=collection.auth_type,
        auth_config=collection.auth_config,
        headers=collection.headers or [],
        is_shared=collection.is_shared,
        created_at=collection.created_at.isoformat() if collection.created_at else None,
        updated_at=collection.updated_at.isoformat() if collection.updated_at else None,
    )


def _folder_to_dto(folder: APIFolder) -> FolderDTO:
    """Convert SQLAlchemy model to DTO."""
    return FolderDTO(
        id=folder.id,
        collection_id=folder.collection_id,
        parent_folder_id=folder.parent_folder_id,
        name=folder.name,
        description=folder.description or "",
        auth_type=folder.auth_type,
        auth_config=folder.auth_config,
        pre_request_script=folder.pre_request_script or "",
        test_script=folder.test_script or "",
        sort_order=folder.sort_order,
        created_at=folder.created_at.isoformat() if folder.created_at else None,
        updated_at=folder.updated_at.isoformat() if folder.updated_at else None,
    )


def _request_to_dto(request: APIRequest) -> RequestDTO:
    """Convert SQLAlchemy model to DTO."""
    return RequestDTO(
        id=request.id,
        collection_id=request.collection_id,
        folder_id=request.folder_id,
        name=request.name,
        description=request.description or "",
        method=request.method,
        url=request.url,
        params=request.params or [],
        headers=request.headers or [],
        body_type=request.body_type,
        body_content=request.body_content or "",
        body_form_data=request.body_form_data or [],
        graphql_query=request.graphql_query or "",
        graphql_variables=request.graphql_variables,
        auth_type=request.auth_type,
        auth_config=request.auth_config,
        pre_request_script=request.pre_request_script or "",
        test_script=request.test_script or "",
        timeout_ms=request.timeout_ms,
        follow_redirects=request.follow_redirects,
        saved_responses=request.saved_responses or [],
        sort_order=request.sort_order,
        created_at=request.created_at.isoformat() if request.created_at else None,
        updated_at=request.updated_at.isoformat() if request.updated_at else None,
    )


def _environment_to_dto(env: APIEnvironment) -> EnvironmentDTO:
    """Convert SQLAlchemy model to DTO."""
    return EnvironmentDTO(
        id=env.id,
        name=env.name,
        description=env.description or "",
        variables=env.variables or [],
        is_active=env.is_active,
        color=env.color or "#4caf50",
        created_at=env.created_at.isoformat() if env.created_at else None,
        updated_at=env.updated_at.isoformat() if env.updated_at else None,
    )


def _global_variable_to_dto(var: APIGlobalVariable) -> GlobalVariableDTO:
    """Convert SQLAlchemy model to DTO."""
    return GlobalVariableDTO(
        id=var.id,
        key=var.key,
        value=var.value if not var.is_secret else "********",
        description=var.description or "",
        is_secret=var.is_secret,
        created_at=var.created_at.isoformat() if var.created_at else None,
        updated_at=var.updated_at.isoformat() if var.updated_at else None,
    )


# =============================================================================
# Environment Operations
# =============================================================================

def create_environment(
    db: Session,
    user_id: int,
    name: str,
    description: str = "",
    variables: Optional[List[Dict[str, Any]]] = None,
    color: str = "#4caf50",
) -> Tuple[bool, str, Optional[EnvironmentDTO]]:
    """Create a new environment."""
    try:
        env = APIEnvironment(
            user_id=user_id,
            name=name,
            description=description,
            variables=variables or [],
            is_active=False,
            color=color,
        )
        db.add(env)
        db.commit()
        db.refresh(env)
        
        logger.info(f"Created environment {env.id}: {name}")
        return True, "Environment created successfully", _environment_to_dto(env)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create environment: {e}")
        return False, str(e), None


def get_environments(
    db: Session,
    user_id: int,
) -> Tuple[bool, str, List[EnvironmentDTO]]:
    """Get all environments for a user."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(APIEnvironment.user_id == user_id)
            .order_by(APIEnvironment.name)
        )
        environments = result.scalars().all()
        
        return True, "OK", [_environment_to_dto(e) for e in environments]
    except Exception as e:
        logger.error(f"Failed to get environments: {e}")
        return False, str(e), []


def get_environment(
    db: Session,
    user_id: int,
    environment_id: int,
) -> Tuple[bool, str, Optional[EnvironmentDTO]]:
    """Get a specific environment."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.id == environment_id,
                    APIEnvironment.user_id == user_id,
                )
            )
        )
        env = result.scalar_one_or_none()
        
        if not env:
            return False, "Environment not found", None
        
        return True, "OK", _environment_to_dto(env)
    except Exception as e:
        logger.error(f"Failed to get environment: {e}")
        return False, str(e), None


def get_active_environment(
    db: Session,
    user_id: int,
) -> Tuple[bool, str, Optional[EnvironmentDTO]]:
    """Get the currently active environment."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.user_id == user_id,
                    APIEnvironment.is_active == True,
                )
            )
        )
        env = result.scalar_one_or_none()
        
        if not env:
            return True, "No active environment", None
        
        return True, "OK", _environment_to_dto(env)
    except Exception as e:
        logger.error(f"Failed to get active environment: {e}")
        return False, str(e), None


def update_environment(
    db: Session,
    user_id: int,
    environment_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    variables: Optional[List[Dict[str, Any]]] = None,
    color: Optional[str] = None,
) -> Tuple[bool, str, Optional[EnvironmentDTO]]:
    """Update an environment."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.id == environment_id,
                    APIEnvironment.user_id == user_id,
                )
            )
        )
        env = result.scalar_one_or_none()
        
        if not env:
            return False, "Environment not found", None
        
        if name is not None:
            env.name = name
        if description is not None:
            env.description = description
        if variables is not None:
            env.variables = variables
        if color is not None:
            env.color = color
        
        env.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(env)
        
        logger.info(f"Updated environment {environment_id}")
        return True, "Environment updated successfully", _environment_to_dto(env)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update environment: {e}")
        return False, str(e), None


def set_active_environment(
    db: Session,
    user_id: int,
    environment_id: Optional[int],
) -> Tuple[bool, str]:
    """Set the active environment. Pass None to deactivate all."""
    try:
        # First, deactivate all environments for this user
        result = db.execute(
            select(APIEnvironment)
            .where(APIEnvironment.user_id == user_id)
        )
        environments = result.scalars().all()
        
        for env in environments:
            env.is_active = (env.id == environment_id)
            env.updated_at = datetime.utcnow()
        
        db.commit()
        
        if environment_id:
            logger.info(f"Set active environment to {environment_id}")
            return True, "Active environment set"
        else:
            logger.info(f"Deactivated all environments for user {user_id}")
            return True, "All environments deactivated"
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to set active environment: {e}")
        return False, str(e)


def delete_environment(
    db: Session,
    user_id: int,
    environment_id: int,
) -> Tuple[bool, str]:
    """Delete an environment."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.id == environment_id,
                    APIEnvironment.user_id == user_id,
                )
            )
        )
        env = result.scalar_one_or_none()
        
        if not env:
            return False, "Environment not found"
        
        db.delete(env)
        db.commit()
        
        logger.info(f"Deleted environment {environment_id}")
        return True, "Environment deleted successfully"
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete environment: {e}")
        return False, str(e)


def duplicate_environment(
    db: Session,
    user_id: int,
    environment_id: int,
    new_name: Optional[str] = None,
) -> Tuple[bool, str, Optional[EnvironmentDTO]]:
    """Duplicate an environment."""
    try:
        result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.id == environment_id,
                    APIEnvironment.user_id == user_id,
                )
            )
        )
        env = result.scalar_one_or_none()
        
        if not env:
            return False, "Environment not found", None
        
        new_env = APIEnvironment(
            user_id=user_id,
            name=new_name or f"{env.name} (Copy)",
            description=env.description,
            variables=env.variables.copy() if env.variables else [],
            is_active=False,
            color=env.color,
        )
        db.add(new_env)
        db.commit()
        db.refresh(new_env)
        
        logger.info(f"Duplicated environment {environment_id} to {new_env.id}")
        return True, "Environment duplicated successfully", _environment_to_dto(new_env)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to duplicate environment: {e}")
        return False, str(e), None


# =============================================================================
# Global Variable Operations
# =============================================================================

def create_global_variable(
    db: Session,
    user_id: int,
    key: str,
    value: str,
    description: str = "",
    is_secret: bool = False,
) -> Tuple[bool, str, Optional[GlobalVariableDTO]]:
    """Create a new global variable."""
    try:
        # Check for duplicate key
        result = db.execute(
            select(APIGlobalVariable)
            .where(
                and_(
                    APIGlobalVariable.user_id == user_id,
                    APIGlobalVariable.key == key,
                )
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return False, f"Global variable '{key}' already exists", None
        
        var = APIGlobalVariable(
            user_id=user_id,
            key=key,
            value=value,
            description=description,
            is_secret=is_secret,
        )
        db.add(var)
        db.commit()
        db.refresh(var)
        
        logger.info(f"Created global variable {var.id}: {key}")
        return True, "Global variable created successfully", _global_variable_to_dto(var)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create global variable: {e}")
        return False, str(e), None


def get_global_variables(
    db: Session,
    user_id: int,
) -> Tuple[bool, str, List[GlobalVariableDTO]]:
    """Get all global variables for a user."""
    try:
        result = db.execute(
            select(APIGlobalVariable)
            .where(APIGlobalVariable.user_id == user_id)
            .order_by(APIGlobalVariable.key)
        )
        variables = result.scalars().all()
        
        return True, "OK", [_global_variable_to_dto(v) for v in variables]
    except Exception as e:
        logger.error(f"Failed to get global variables: {e}")
        return False, str(e), []


def get_global_variable(
    db: Session,
    user_id: int,
    variable_id: int,
    include_secret: bool = False,
) -> Tuple[bool, str, Optional[GlobalVariableDTO]]:
    """Get a specific global variable."""
    try:
        result = db.execute(
            select(APIGlobalVariable)
            .where(
                and_(
                    APIGlobalVariable.id == variable_id,
                    APIGlobalVariable.user_id == user_id,
                )
            )
        )
        var = result.scalar_one_or_none()
        
        if not var:
            return False, "Global variable not found", None
        
        dto = _global_variable_to_dto(var)
        if include_secret and var.is_secret:
            dto.value = var.value
        
        return True, "OK", dto
    except Exception as e:
        logger.error(f"Failed to get global variable: {e}")
        return False, str(e), None


def update_global_variable(
    db: Session,
    user_id: int,
    variable_id: int,
    key: Optional[str] = None,
    value: Optional[str] = None,
    description: Optional[str] = None,
    is_secret: Optional[bool] = None,
) -> Tuple[bool, str, Optional[GlobalVariableDTO]]:
    """Update a global variable."""
    try:
        result = db.execute(
            select(APIGlobalVariable)
            .where(
                and_(
                    APIGlobalVariable.id == variable_id,
                    APIGlobalVariable.user_id == user_id,
                )
            )
        )
        var = result.scalar_one_or_none()
        
        if not var:
            return False, "Global variable not found", None
        
        if key is not None:
            # Check for duplicate key
            result = db.execute(
                select(APIGlobalVariable)
                .where(
                    and_(
                        APIGlobalVariable.user_id == user_id,
                        APIGlobalVariable.key == key,
                        APIGlobalVariable.id != variable_id,
                    )
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                return False, f"Global variable '{key}' already exists", None
            var.key = key
        
        if value is not None:
            var.value = value
        if description is not None:
            var.description = description
        if is_secret is not None:
            var.is_secret = is_secret
        
        var.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(var)
        
        logger.info(f"Updated global variable {variable_id}")
        return True, "Global variable updated successfully", _global_variable_to_dto(var)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update global variable: {e}")
        return False, str(e), None


def delete_global_variable(
    db: Session,
    user_id: int,
    variable_id: int,
) -> Tuple[bool, str]:
    """Delete a global variable."""
    try:
        result = db.execute(
            select(APIGlobalVariable)
            .where(
                and_(
                    APIGlobalVariable.id == variable_id,
                    APIGlobalVariable.user_id == user_id,
                )
            )
        )
        var = result.scalar_one_or_none()
        
        if not var:
            return False, "Global variable not found"
        
        db.delete(var)
        db.commit()
        
        logger.info(f"Deleted global variable {variable_id}")
        return True, "Global variable deleted successfully"
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete global variable: {e}")
        return False, str(e)


# =============================================================================
# Variable Substitution
# =============================================================================

import re

def substitute_variables(
    text: str,
    environment_variables: Optional[List[Dict[str, Any]]] = None,
    global_variables: Optional[List[Dict[str, Any]]] = None,
    collection_variables: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Substitute {{variable}} placeholders in text.
    
    Priority order (highest to lowest):
    1. Environment variables
    2. Collection variables  
    3. Global variables
    
    Args:
        text: The text containing {{variable}} placeholders
        environment_variables: Variables from the active environment
        global_variables: User's global variables
        collection_variables: Variables from the collection
        
    Returns:
        Text with variables substituted
    """
    if not text:
        return text
    
    # Build variable lookup dictionary (lower priority first, higher overwrites)
    variables = {}
    
    # Global variables (lowest priority)
    if global_variables:
        for var in global_variables:
            if var.get("enabled", True) and var.get("key"):
                variables[var["key"]] = var.get("value", "")
    
    # Collection variables
    if collection_variables:
        for var in collection_variables:
            if var.get("enabled", True) and var.get("key"):
                variables[var["key"]] = var.get("value", "")
    
    # Environment variables (highest priority)
    if environment_variables:
        for var in environment_variables:
            if var.get("enabled", True) and var.get("key"):
                variables[var["key"]] = var.get("value", "")
    
    # Replace {{variable}} patterns
    def replace_var(match):
        var_name = match.group(1).strip()
        return variables.get(var_name, match.group(0))  # Keep original if not found
    
    return re.sub(r'\{\{([^}]+)\}\}', replace_var, text)


def substitute_in_request(
    request_dto: RequestDTO,
    environment_variables: Optional[List[Dict[str, Any]]] = None,
    global_variables: Optional[List[Dict[str, Any]]] = None,
    collection_variables: Optional[List[Dict[str, Any]]] = None,
) -> RequestDTO:
    """
    Apply variable substitution to all parts of a request.
    
    Returns a new RequestDTO with variables substituted.
    """
    sub = lambda text: substitute_variables(
        text, 
        environment_variables, 
        global_variables, 
        collection_variables
    )
    
    # Create a copy with substituted values
    return RequestDTO(
        id=request_dto.id,
        collection_id=request_dto.collection_id,
        folder_id=request_dto.folder_id,
        name=request_dto.name,
        description=request_dto.description,
        method=request_dto.method,
        url=sub(request_dto.url),
        params=[
            {**p, "value": sub(p.get("value", ""))} 
            for p in request_dto.params
        ],
        headers=[
            {**h, "value": sub(h.get("value", ""))} 
            for h in request_dto.headers
        ],
        body_type=request_dto.body_type,
        body_content=sub(request_dto.body_content),
        body_form_data=[
            {**f, "value": sub(f.get("value", ""))} 
            for f in request_dto.body_form_data
        ],
        graphql_query=sub(request_dto.graphql_query),
        graphql_variables=request_dto.graphql_variables,
        auth_type=request_dto.auth_type,
        auth_config=request_dto.auth_config,
        pre_request_script=request_dto.pre_request_script,
        test_script=request_dto.test_script,
        timeout_ms=request_dto.timeout_ms,
        follow_redirects=request_dto.follow_redirects,
        saved_responses=request_dto.saved_responses,
        sort_order=request_dto.sort_order,
        created_at=request_dto.created_at,
        updated_at=request_dto.updated_at,
    )


def get_all_variables_for_substitution(
    db: Session,
    user_id: int,
    collection_id: Optional[int] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all variables needed for substitution.
    
    Returns a dict with:
    - environment_variables: From active environment
    - global_variables: User's global variables
    - collection_variables: From specified collection
    """
    result = {
        "environment_variables": [],
        "global_variables": [],
        "collection_variables": [],
    }
    
    try:
        # Get active environment variables
        env_result = db.execute(
            select(APIEnvironment)
            .where(
                and_(
                    APIEnvironment.user_id == user_id,
                    APIEnvironment.is_active == True,
                )
            )
        )
        active_env = env_result.scalar_one_or_none()
        if active_env and active_env.variables:
            result["environment_variables"] = active_env.variables
        
        # Get global variables
        glob_result = db.execute(
            select(APIGlobalVariable)
            .where(APIGlobalVariable.user_id == user_id)
        )
        global_vars = glob_result.scalars().all()
        result["global_variables"] = [
            {"key": v.key, "value": v.value, "enabled": True}
            for v in global_vars
        ]
        
        # Get collection variables
        if collection_id:
            coll_result = db.execute(
                select(APICollection)
                .where(
                    and_(
                        APICollection.id == collection_id,
                        APICollection.user_id == user_id,
                    )
                )
            )
            collection = coll_result.scalar_one_or_none()
            if collection and collection.variables:
                result["collection_variables"] = collection.variables
        
    except Exception as e:
        logger.error(f"Failed to get variables for substitution: {e}")
    
    return result


# =============================================================================
# Request History DTO
# =============================================================================

@dataclass
class HistoryEntryDTO:
    """Request history entry data transfer object."""
    id: Optional[int] = None
    collection_id: Optional[int] = None
    request_id: Optional[int] = None
    method: str = "GET"
    url: str = ""
    original_url: Optional[str] = None
    headers: Optional[List[Dict[str, Any]]] = None
    body: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_body: Optional[str] = None
    response_size_bytes: Optional[int] = None
    response_time_ms: Optional[float] = None
    request_cookies: Optional[List[Dict[str, Any]]] = None
    response_cookies: Optional[List[Dict[str, Any]]] = None
    test_results: Optional[List[Dict[str, Any]]] = None
    tests_passed: int = 0
    tests_failed: int = 0
    security_findings: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    environment_id: Optional[int] = None
    environment_name: Optional[str] = None
    executed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "collection_id": self.collection_id,
            "request_id": self.request_id,
            "method": self.method,
            "url": self.url,
            "original_url": self.original_url,
            "headers": self.headers,
            "body": self.body,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "response_size_bytes": self.response_size_bytes,
            "response_time_ms": self.response_time_ms,
            "request_cookies": self.request_cookies,
            "response_cookies": self.response_cookies,
            "test_results": self.test_results,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "security_findings": self.security_findings,
            "error": self.error,
            "environment_id": self.environment_id,
            "environment_name": self.environment_name,
            "executed_at": self.executed_at,
        }


def _history_to_dto(history: APIRequestHistory) -> HistoryEntryDTO:
    """Convert APIRequestHistory model to DTO."""
    return HistoryEntryDTO(
        id=history.id,
        collection_id=history.collection_id,
        request_id=history.request_id,
        method=history.method,
        url=history.url,
        original_url=history.original_url,
        headers=history.headers,
        body=history.body,
        status_code=history.status_code,
        status_text=history.status_text,
        response_headers=history.response_headers,
        response_body=history.response_body,
        response_size_bytes=history.response_size_bytes,
        response_time_ms=history.response_time_ms,
        request_cookies=history.request_cookies,
        response_cookies=history.response_cookies,
        test_results=history.test_results,
        tests_passed=history.tests_passed or 0,
        tests_failed=history.tests_failed or 0,
        security_findings=history.security_findings,
        error=history.error,
        environment_id=history.environment_id,
        environment_name=history.environment_name,
        executed_at=history.executed_at.isoformat() if history.executed_at else None,
    )


# =============================================================================
# Request History Service Functions
# =============================================================================

def create_history_entry(
    db: Session,
    user_id: int,
    method: str,
    url: str,
    original_url: Optional[str] = None,
    headers: Optional[List[Dict[str, Any]]] = None,
    body: Optional[str] = None,
    collection_id: Optional[int] = None,
    request_id: Optional[int] = None,
    status_code: Optional[int] = None,
    status_text: Optional[str] = None,
    response_headers: Optional[Dict[str, Any]] = None,
    response_body: Optional[str] = None,
    response_size_bytes: Optional[int] = None,
    response_time_ms: Optional[float] = None,
    request_cookies: Optional[List[Dict[str, Any]]] = None,
    response_cookies: Optional[List[Dict[str, Any]]] = None,
    test_results: Optional[List[Dict[str, Any]]] = None,
    security_findings: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
    environment_id: Optional[int] = None,
    environment_name: Optional[str] = None,
) -> HistoryEntryDTO:
    """
    Create a new request history entry.
    """
    try:
        # Calculate test pass/fail counts
        tests_passed = 0
        tests_failed = 0
        if test_results:
            for test in test_results:
                if test.get("passed"):
                    tests_passed += 1
                else:
                    tests_failed += 1
        
        # Truncate response body if too large (keep first 1MB)
        truncated_response = response_body
        if response_body and len(response_body) > 1_000_000:
            truncated_response = response_body[:1_000_000] + "\n\n[Response truncated - exceeded 1MB]"
        
        history = APIRequestHistory(
            user_id=user_id,
            collection_id=collection_id,
            request_id=request_id,
            method=method.upper(),
            url=url,
            original_url=original_url,
            headers=headers,
            body=body,
            status_code=status_code,
            status_text=status_text,
            response_headers=response_headers,
            response_body=truncated_response,
            response_size_bytes=response_size_bytes,
            response_time_ms=response_time_ms,
            request_cookies=request_cookies,
            response_cookies=response_cookies,
            test_results=test_results,
            tests_passed=tests_passed,
            tests_failed=tests_failed,
            security_findings=security_findings,
            error=error,
            environment_id=environment_id,
            environment_name=environment_name,
        )
        
        db.add(history)
        db.commit()
        db.refresh(history)
        
        logger.info(f"Created history entry {history.id} for user {user_id}")
        return _history_to_dto(history)
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create history entry: {e}")
        raise


def get_history(
    db: Session,
    user_id: int,
    limit: int = 100,
    offset: int = 0,
    method_filter: Optional[str] = None,
    url_filter: Optional[str] = None,
    status_filter: Optional[str] = None,  # "success", "error", "redirect"
    collection_id: Optional[int] = None,
    from_date: Optional[datetime] = None,
    to_date: Optional[datetime] = None,
) -> Tuple[List[HistoryEntryDTO], int]:
    """
    Get request history with filtering and pagination.
    
    Returns: (list of history entries, total count)
    """
    try:
        # Build base query
        conditions = [APIRequestHistory.user_id == user_id]
        
        if method_filter:
            conditions.append(APIRequestHistory.method == method_filter.upper())
        
        if url_filter:
            conditions.append(APIRequestHistory.url.ilike(f"%{url_filter}%"))
        
        if status_filter:
            if status_filter == "success":
                conditions.append(
                    and_(
                        APIRequestHistory.status_code >= 200,
                        APIRequestHistory.status_code < 300,
                    )
                )
            elif status_filter == "error":
                conditions.append(
                    or_(
                        APIRequestHistory.status_code >= 400,
                        APIRequestHistory.error.isnot(None),
                    )
                )
            elif status_filter == "redirect":
                conditions.append(
                    and_(
                        APIRequestHistory.status_code >= 300,
                        APIRequestHistory.status_code < 400,
                    )
                )
        
        if collection_id:
            conditions.append(APIRequestHistory.collection_id == collection_id)
        
        if from_date:
            conditions.append(APIRequestHistory.executed_at >= from_date)
        
        if to_date:
            conditions.append(APIRequestHistory.executed_at <= to_date)
        
        # Get total count
        count_result = db.execute(
            select(func.count(APIRequestHistory.id))
            .where(and_(*conditions))
        )
        total = count_result.scalar() or 0
        
        # Get paginated results
        query = (
            select(APIRequestHistory)
            .where(and_(*conditions))
            .order_by(APIRequestHistory.executed_at.desc())
            .offset(offset)
            .limit(limit)
        )
        
        result = db.execute(query)
        entries = result.scalars().all()
        
        return [_history_to_dto(e) for e in entries], total
        
    except Exception as e:
        logger.error(f"Failed to get history: {e}")
        return [], 0


def get_history_entry(
    db: Session,
    user_id: int,
    history_id: int,
) -> Optional[HistoryEntryDTO]:
    """
    Get a specific history entry by ID.
    """
    try:
        result = db.execute(
            select(APIRequestHistory)
            .where(
                and_(
                    APIRequestHistory.id == history_id,
                    APIRequestHistory.user_id == user_id,
                )
            )
        )
        entry = result.scalar_one_or_none()
        
        if not entry:
            return None
        
        return _history_to_dto(entry)
        
    except Exception as e:
        logger.error(f"Failed to get history entry {history_id}: {e}")
        return None


def delete_history_entry(
    db: Session,
    user_id: int,
    history_id: int,
) -> bool:
    """
    Delete a specific history entry.
    """
    try:
        result = db.execute(
            select(APIRequestHistory)
            .where(
                and_(
                    APIRequestHistory.id == history_id,
                    APIRequestHistory.user_id == user_id,
                )
            )
        )
        entry = result.scalar_one_or_none()
        
        if not entry:
            return False
        
        db.delete(entry)
        db.commit()
        
        logger.info(f"Deleted history entry {history_id}")
        return True
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete history entry {history_id}: {e}")
        return False


def clear_history(
    db: Session,
    user_id: int,
    older_than: Optional[datetime] = None,
    collection_id: Optional[int] = None,
) -> int:
    """
    Clear history entries.
    
    Args:
        older_than: If provided, only delete entries older than this date
        collection_id: If provided, only delete entries for this collection
    
    Returns: Number of entries deleted
    """
    try:
        conditions = [APIRequestHistory.user_id == user_id]
        
        if older_than:
            conditions.append(APIRequestHistory.executed_at < older_than)
        
        if collection_id:
            conditions.append(APIRequestHistory.collection_id == collection_id)
        
        # Get entries to delete
        result = db.execute(
            select(APIRequestHistory)
            .where(and_(*conditions))
        )
        entries = result.scalars().all()
        count = len(entries)
        
        # Delete them
        for entry in entries:
            db.delete(entry)
        
        db.commit()
        
        logger.info(f"Cleared {count} history entries for user {user_id}")
        return count
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to clear history: {e}")
        return 0


def get_history_stats(
    db: Session,
    user_id: int,
) -> Dict[str, Any]:
    """
    Get statistics about request history.
    """
    try:
        # Total count
        total_result = db.execute(
            select(func.count(APIRequestHistory.id))
            .where(APIRequestHistory.user_id == user_id)
        )
        total = total_result.scalar() or 0
        
        # Method breakdown
        method_result = db.execute(
            select(APIRequestHistory.method, func.count(APIRequestHistory.id))
            .where(APIRequestHistory.user_id == user_id)
            .group_by(APIRequestHistory.method)
        )
        methods = {row[0]: row[1] for row in method_result.fetchall()}
        
        # Status breakdown
        success_result = db.execute(
            select(func.count(APIRequestHistory.id))
            .where(
                and_(
                    APIRequestHistory.user_id == user_id,
                    APIRequestHistory.status_code >= 200,
                    APIRequestHistory.status_code < 300,
                )
            )
        )
        success_count = success_result.scalar() or 0
        
        error_result = db.execute(
            select(func.count(APIRequestHistory.id))
            .where(
                and_(
                    APIRequestHistory.user_id == user_id,
                    or_(
                        APIRequestHistory.status_code >= 400,
                        APIRequestHistory.error.isnot(None),
                    ),
                )
            )
        )
        error_count = error_result.scalar() or 0
        
        # Average response time
        avg_time_result = db.execute(
            select(func.avg(APIRequestHistory.response_time_ms))
            .where(
                and_(
                    APIRequestHistory.user_id == user_id,
                    APIRequestHistory.response_time_ms.isnot(None),
                )
            )
        )
        avg_response_time = avg_time_result.scalar()
        
        return {
            "total_requests": total,
            "methods": methods,
            "success_count": success_count,
            "error_count": error_count,
            "success_rate": (success_count / total * 100) if total > 0 else 0,
            "avg_response_time_ms": round(avg_response_time, 2) if avg_response_time else None,
        }
        
    except Exception as e:
        logger.error(f"Failed to get history stats: {e}")
        return {
            "total_requests": 0,
            "methods": {},
            "success_count": 0,
            "error_count": 0,
            "success_rate": 0,
            "avg_response_time_ms": None,
        }
