"""
Mermaid Icon Pack Reference for AI-Generated Diagrams

This module provides documentation and constants for the icon packs available
in Mermaid diagrams. Use these icons in AI prompts that generate Mermaid diagrams
to create more visually informative visualizations.

SYNTAX: prefix:icon-name
Example: fa6-solid:shield, mdi:android, lucide:lock
"""

# ============================================================================
# AVAILABLE ICON PACKS WITH EXAMPLES
# ============================================================================

MERMAID_ICON_PACKS = """
============================================================================
MERMAID ICON PACKS - Available for use in diagrams
============================================================================

SYNTAX: Use icons in node labels like: A[prefix:icon-name Label Text]

FONT AWESOME 6 SOLID (fa6-solid:) - General purpose icons
  Security:    fa6-solid:shield, fa6-solid:lock, fa6-solid:key, fa6-solid:bug, 
               fa6-solid:shield-halved, fa6-solid:user-shield, fa6-solid:fingerprint
  UI/Actions:  fa6-solid:gear, fa6-solid:check, fa6-solid:xmark, fa6-solid:plus,
               fa6-solid:play, fa6-solid:stop, fa6-solid:trash, fa6-solid:pen
  Files:       fa6-solid:file, fa6-solid:folder, fa6-solid:database, fa6-solid:code
  Network:     fa6-solid:server, fa6-solid:network-wired, fa6-solid:cloud, fa6-solid:globe
  Alerts:      fa6-solid:triangle-exclamation, fa6-solid:circle-info, fa6-solid:bell
  People:      fa6-solid:user, fa6-solid:users, fa6-solid:user-secret
  Mobile:      fa6-solid:mobile, fa6-solid:tablet, fa6-solid:laptop

FONT AWESOME 6 BRANDS (fa6-brands:) - Brand/platform icons
  Platforms:   fa6-brands:android, fa6-brands:apple, fa6-brands:windows, fa6-brands:linux
  Dev:         fa6-brands:github, fa6-brands:docker, fa6-brands:python, fa6-brands:java
  Cloud:       fa6-brands:aws, fa6-brands:google, fa6-brands:microsoft

MATERIAL DESIGN ICONS (mdi:) - 7000+ icons, excellent coverage
  Security:    mdi:shield, mdi:lock, mdi:key, mdi:bug, mdi:security, mdi:incognito
  Files:       mdi:file, mdi:folder, mdi:database, mdi:code-braces, mdi:file-code
  Network:     mdi:server, mdi:lan, mdi:cloud, mdi:web, mdi:api, mdi:webhook
  Android:     mdi:android, mdi:cellphone, mdi:application, mdi:package-variant
  Alerts:      mdi:alert, mdi:information, mdi:check-circle, mdi:close-circle
  Actions:     mdi:play, mdi:stop, mdi:refresh, mdi:download, mdi:upload, mdi:send
  Data:        mdi:chart-bar, mdi:table, mdi:format-list-bulleted, mdi:graph

LUCIDE (lucide:) - Clean modern icons
  Security:    lucide:shield, lucide:lock, lucide:key, lucide:bug, lucide:scan
  Files:       lucide:file, lucide:folder, lucide:database, lucide:code
  Network:     lucide:server, lucide:wifi, lucide:cloud, lucide:globe
  UI:          lucide:check, lucide:x, lucide:plus, lucide:minus, lucide:search

TABLER (tabler:) - UI/Developer focused
  Security:    tabler:shield, tabler:lock, tabler:key, tabler:bug, tabler:spy
  Dev:         tabler:code, tabler:terminal, tabler:git-branch, tabler:api
  Network:     tabler:server, tabler:cloud, tabler:world, tabler:network

CARBON (carbon:) - IBM design system icons
  Security:    carbon:security, carbon:locked, carbon:password, carbon:fingerprint
  Enterprise:  carbon:enterprise, carbon:application, carbon:api, carbon:data-base
  Cloud:       carbon:cloud, carbon:kubernetes, carbon:container-software
"""

# Recommended icons for specific security diagram contexts
SECURITY_ICONS = {
    # Severity indicators
    "critical": "fa6-solid:skull-crossbones",
    "high": "fa6-solid:circle-exclamation",
    "medium": "fa6-solid:triangle-exclamation",
    "low": "fa6-solid:circle-info",
    "info": "fa6-solid:circle-question",
    
    # Component types - Android
    "activity": "mdi:application",
    "service": "mdi:cog",
    "receiver": "mdi:broadcast",
    "provider": "mdi:database",
    "app": "fa6-brands:android",
    "apk": "mdi:package-variant",
    
    # Security concepts
    "vulnerability": "fa6-solid:bug",
    "exploit": "fa6-solid:user-secret",
    "attack": "fa6-solid:crosshairs",
    "defense": "fa6-solid:shield-halved",
    "authentication": "fa6-solid:fingerprint",
    "authorization": "fa6-solid:user-shield",
    "encryption": "fa6-solid:lock",
    "key": "fa6-solid:key",
    "certificate": "mdi:certificate",
    "secret": "mdi:key-variant",
    
    # Data flow
    "input": "fa6-solid:arrow-right-to-bracket",
    "output": "fa6-solid:arrow-right-from-bracket",
    "data": "mdi:database",
    "network": "fa6-solid:network-wired",
    "api": "mdi:api",
    "storage": "mdi:harddisk",
    "file": "fa6-solid:file",
    "log": "mdi:text-box-outline",
    
    # Actions/states
    "warning": "fa6-solid:triangle-exclamation",
    "error": "fa6-solid:circle-xmark",
    "success": "fa6-solid:circle-check",
    "process": "fa6-solid:gear",
    "scan": "lucide:scan",
    "analyze": "mdi:magnify",
    
    # Network/Communication
    "server": "fa6-solid:server",
    "cloud": "fa6-solid:cloud",
    "internet": "fa6-solid:globe",
    "webhook": "mdi:webhook",
    "websocket": "mdi:lan-connect",
    
    # Mobile specific
    "mobile": "fa6-solid:mobile",
    "permission": "mdi:shield-key",
    "intent": "mdi:arrow-decision",
    "deeplink": "mdi:link-variant",
}

# Attack tree specific icons
ATTACK_TREE_ICONS = {
    "root": "fa6-solid:crosshairs",
    "attack_vector": "fa6-solid:route",
    "exported_activity": "mdi:application-export",
    "exported_service": "mdi:cog-transfer",
    "exported_receiver": "mdi:broadcast",
    "exported_provider": "mdi:database-export",
    "deep_link": "mdi:link-variant",
    "intent": "mdi:arrow-decision",
    "sql_injection": "mdi:database-alert",
    "path_traversal": "mdi:folder-alert",
    "auth_bypass": "fa6-solid:door-open",
    "data_leak": "fa6-solid:droplet",
    "priv_escalation": "fa6-solid:stairs",
}

# Manifest visualization icons
MANIFEST_ICONS = {
    "package": "mdi:package-variant",
    "activity": "mdi:application",
    "main_activity": "mdi:rocket-launch",
    "service": "mdi:cog",
    "receiver": "mdi:broadcast",
    "provider": "mdi:database",
    "permission": "mdi:shield-key",
    "dangerous_permission": "fa6-solid:triangle-exclamation",
    "exported": "mdi:export",
    "protected": "mdi:shield-check",
}


def get_icon(category: str, icon_type: str = "default") -> str:
    """
    Get the recommended icon for a category.
    
    Args:
        category: The icon category (e.g., "security", "attack_tree", "manifest")
        icon_type: The specific icon type within the category
    
    Returns:
        Icon string in format "prefix:icon-name"
    """
    icon_maps = {
        "security": SECURITY_ICONS,
        "attack_tree": ATTACK_TREE_ICONS,
        "manifest": MANIFEST_ICONS,
    }
    
    icon_map = icon_maps.get(category, SECURITY_ICONS)
    return icon_map.get(icon_type, "fa6-solid:circle")


def get_severity_icon(severity: str) -> str:
    """Get icon for severity level."""
    severity_map = {
        "critical": "fa6-solid:skull-crossbones",
        "high": "fa6-solid:circle-exclamation", 
        "medium": "fa6-solid:triangle-exclamation",
        "low": "fa6-solid:circle-info",
        "info": "fa6-solid:circle-question",
    }
    return severity_map.get(severity.lower(), "fa6-solid:circle")


# AI prompt instructions for generating Mermaid diagrams with icons
MERMAID_AI_INSTRUCTIONS = """
When generating Mermaid diagrams, use icons to make them more informative.

ICON SYNTAX: Include icons in node labels using prefix:icon-name format
Example: A[fa6-solid:shield Security Check]

RECOMMENDED ICONS FOR SECURITY DIAGRAMS:

Severity Indicators:
- Critical: fa6-solid:skull-crossbones
- High: fa6-solid:circle-exclamation  
- Medium: fa6-solid:triangle-exclamation
- Low: fa6-solid:circle-info

Android Components:
- Activity: mdi:application
- Service: mdi:cog
- Receiver: mdi:broadcast
- Provider: mdi:database
- APK/App: fa6-brands:android

Security Concepts:
- Vulnerability: fa6-solid:bug
- Attack: fa6-solid:crosshairs
- Defense: fa6-solid:shield-halved
- Auth: fa6-solid:fingerprint
- Encryption: fa6-solid:lock
- Key: fa6-solid:key

Data Flow:
- Input: fa6-solid:arrow-right-to-bracket
- Output: fa6-solid:arrow-right-from-bracket
- Database: mdi:database
- Network: fa6-solid:network-wired
- API: mdi:api
- File: fa6-solid:file

Status:
- Warning: fa6-solid:triangle-exclamation
- Error: fa6-solid:circle-xmark
- Success: fa6-solid:circle-check

EXAMPLE DIAGRAM:
```mermaid
flowchart TD
    A[fa6-brands:android APK] --> B[mdi:application MainActivity]
    B --> C{fa6-solid:shield-halved Auth Check}
    C -->|Pass| D[mdi:database User Data]
    C -->|Fail| E[fa6-solid:circle-xmark Denied]
    D --> F[fa6-solid:bug Vulnerability Found]
```
"""
