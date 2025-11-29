"""
Webhook notification service for sending scan results to external systems.
Supports Slack, Microsoft Teams, Discord, and generic webhooks.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from backend import models
from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


class WebhookType(str, Enum):
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    url: str
    webhook_type: WebhookType = WebhookType.GENERIC
    secret: Optional[str] = None
    enabled: bool = True


# In-memory webhook registry (in production, store in database)
_webhook_registry: Dict[int, List[WebhookConfig]] = {}


def register_webhook(project_id: int, config: WebhookConfig) -> None:
    """Register a webhook for a project."""
    if project_id not in _webhook_registry:
        _webhook_registry[project_id] = []
    _webhook_registry[project_id].append(config)
    logger.info(f"Registered {config.webhook_type} webhook for project {project_id}")


def get_webhooks(project_id: int) -> List[WebhookConfig]:
    """Get all webhooks for a project."""
    return _webhook_registry.get(project_id, [])


def clear_webhooks(project_id: int) -> None:
    """Remove all webhooks for a project."""
    _webhook_registry.pop(project_id, None)


def _build_slack_payload(
    project: models.Project,
    report: models.Report,
    findings_summary: Dict[str, int]
) -> Dict[str, Any]:
    """Build Slack Block Kit message payload."""
    total = sum(findings_summary.values())
    critical = findings_summary.get("critical", 0)
    high = findings_summary.get("high", 0)
    
    # Color based on severity
    color = "#36a64f"  # green
    if critical > 0:
        color = "#dc3545"  # red
    elif high > 0:
        color = "#fd7e14"  # orange
    
    return {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🔒 VRAgent Scan Complete: {project.name}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:*\n{report.overall_risk_score or 'N/A'}"},
                        {"type": "mrkdwn", "text": f"*Critical:* {critical}"},
                        {"type": "mrkdwn", "text": f"*High:* {high}"},
                        {"type": "mrkdwn", "text": f"*Medium:* {findings_summary.get('medium', 0)}"},
                        {"type": "mrkdwn", "text": f"*Low:* {findings_summary.get('low', 0)}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Report ID: {report.id} | Scanned: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}
                    ]
                }
            ]
        }]
    }


def _build_teams_payload(
    project: models.Project,
    report: models.Report,
    findings_summary: Dict[str, int]
) -> Dict[str, Any]:
    """Build Microsoft Teams Adaptive Card payload."""
    total = sum(findings_summary.values())
    critical = findings_summary.get("critical", 0)
    high = findings_summary.get("high", 0)
    
    theme_color = "00FF00"
    if critical > 0:
        theme_color = "FF0000"
    elif high > 0:
        theme_color = "FFA500"
    
    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"VRAgent Scan Complete: {project.name}",
        "sections": [{
            "activityTitle": f"🔒 VRAgent Scan Complete: {project.name}",
            "facts": [
                {"name": "Total Findings", "value": str(total)},
                {"name": "Critical", "value": str(critical)},
                {"name": "High", "value": str(high)},
                {"name": "Medium", "value": str(findings_summary.get("medium", 0))},
                {"name": "Low", "value": str(findings_summary.get("low", 0))},
                {"name": "Risk Score", "value": str(report.overall_risk_score or "N/A")},
            ],
            "markdown": True
        }]
    }


def _build_discord_payload(
    project: models.Project,
    report: models.Report,
    findings_summary: Dict[str, int]
) -> Dict[str, Any]:
    """Build Discord embed payload."""
    total = sum(findings_summary.values())
    critical = findings_summary.get("critical", 0)
    high = findings_summary.get("high", 0)
    
    color = 0x36a64f
    if critical > 0:
        color = 0xdc3545
    elif high > 0:
        color = 0xfd7e14
    
    return {
        "embeds": [{
            "title": f"🔒 VRAgent Scan Complete: {project.name}",
            "color": color,
            "fields": [
                {"name": "Total Findings", "value": str(total), "inline": True},
                {"name": "Risk Score", "value": str(report.overall_risk_score or "N/A"), "inline": True},
                {"name": "Critical", "value": str(critical), "inline": True},
                {"name": "High", "value": str(high), "inline": True},
                {"name": "Medium", "value": str(findings_summary.get("medium", 0)), "inline": True},
                {"name": "Low", "value": str(findings_summary.get("low", 0)), "inline": True},
            ],
            "footer": {"text": f"Report ID: {report.id}"},
            "timestamp": datetime.utcnow().isoformat()
        }]
    }


def _build_generic_payload(
    project: models.Project,
    report: models.Report,
    findings_summary: Dict[str, int],
    findings: List[models.Finding]
) -> Dict[str, Any]:
    """Build generic JSON payload with full data."""
    return {
        "event": "scan_complete",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "project": {
            "id": project.id,
            "name": project.name,
            "git_url": project.git_url,
        },
        "report": {
            "id": report.id,
            "title": report.title,
            "risk_score": report.overall_risk_score,
            "created_at": report.created_at.isoformat() if report.created_at else None,
        },
        "summary": {
            "total": sum(findings_summary.values()),
            "by_severity": findings_summary,
        },
        "findings": [
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "summary": f.summary,
                "file_path": f.file_path,
                "line": f.start_line,
            }
            for f in findings[:50]  # Limit to 50 findings in webhook
        ]
    }


async def send_webhook(
    config: WebhookConfig,
    payload: Dict[str, Any]
) -> bool:
    """Send a webhook notification."""
    if not config.enabled:
        return False
    
    headers = {"Content-Type": "application/json"}
    if config.secret:
        headers["X-Webhook-Secret"] = config.secret
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(config.url, json=payload, headers=headers)
            resp.raise_for_status()
            logger.info(f"Webhook sent successfully to {config.webhook_type}: {config.url[:50]}...")
            return True
    except httpx.TimeoutException:
        logger.warning(f"Webhook timeout: {config.url[:50]}...")
        return False
    except httpx.HTTPStatusError as e:
        logger.error(f"Webhook HTTP error {e.response.status_code}: {config.url[:50]}...")
        return False
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return False


async def notify_scan_complete(
    db: Session,
    project: models.Project,
    report: models.Report
) -> Dict[str, bool]:
    """
    Send notifications to all registered webhooks for a project.
    
    Returns dict mapping webhook URLs to success status.
    """
    webhooks = get_webhooks(project.id)
    if not webhooks:
        return {}
    
    # Fetch findings and build summary
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    
    findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in findings_summary:
            findings_summary[f.severity] += 1
    
    results = {}
    
    for config in webhooks:
        # Build appropriate payload
        if config.webhook_type == WebhookType.SLACK:
            payload = _build_slack_payload(project, report, findings_summary)
        elif config.webhook_type == WebhookType.TEAMS:
            payload = _build_teams_payload(project, report, findings_summary)
        elif config.webhook_type == WebhookType.DISCORD:
            payload = _build_discord_payload(project, report, findings_summary)
        else:
            payload = _build_generic_payload(project, report, findings_summary, findings)
        
        success = await send_webhook(config, payload)
        results[config.url] = success
    
    logger.info(f"Sent {sum(results.values())}/{len(results)} webhook notifications for project {project.id}")
    return results
