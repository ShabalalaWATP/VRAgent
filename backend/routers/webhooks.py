"""
Webhook configuration endpoints for project notifications.
"""
from typing import List, Optional
from pydantic import BaseModel, HttpUrl

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend import models
from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.services.webhook_service import (
    WebhookConfig,
    WebhookType,
    register_webhook,
    get_webhooks,
    clear_webhooks,
)

logger = get_logger(__name__)

router = APIRouter()


class WebhookCreate(BaseModel):
    """Request model for creating a webhook."""
    url: str
    webhook_type: WebhookType = WebhookType.GENERIC
    secret: Optional[str] = None


class WebhookResponse(BaseModel):
    """Response model for webhook configuration."""
    url: str
    webhook_type: WebhookType
    enabled: bool


@router.post("/{project_id}/webhooks", response_model=WebhookResponse)
def create_webhook(
    project_id: int,
    webhook: WebhookCreate,
    db: Session = Depends(get_db)
):
    """
    Register a webhook for scan notifications.
    
    Supported webhook types:
    - **slack**: Slack incoming webhook (Block Kit format)
    - **teams**: Microsoft Teams webhook (Adaptive Card format)
    - **discord**: Discord webhook (embed format)
    - **generic**: Generic JSON payload with full scan data
    
    Webhooks are triggered when a scan completes.
    """
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    config = WebhookConfig(
        url=webhook.url,
        webhook_type=webhook.webhook_type,
        secret=webhook.secret,
        enabled=True
    )
    
    register_webhook(project_id, config)
    logger.info(f"Registered {webhook.webhook_type} webhook for project {project_id}")
    
    return WebhookResponse(
        url=webhook.url,
        webhook_type=webhook.webhook_type,
        enabled=True
    )


@router.get("/{project_id}/webhooks", response_model=List[WebhookResponse])
def list_webhooks(
    project_id: int,
    db: Session = Depends(get_db)
):
    """List all webhooks configured for a project."""
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    webhooks = get_webhooks(project_id)
    return [
        WebhookResponse(
            url=w.url,
            webhook_type=w.webhook_type,
            enabled=w.enabled
        )
        for w in webhooks
    ]


@router.delete("/{project_id}/webhooks")
def delete_all_webhooks(
    project_id: int,
    db: Session = Depends(get_db)
):
    """Remove all webhooks for a project."""
    project = db.get(models.Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    clear_webhooks(project_id)
    logger.info(f"Cleared all webhooks for project {project_id}")
    
    return {"message": "All webhooks removed"}
