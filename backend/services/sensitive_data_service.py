"""
Sensitive Data Inventory Service

Extracts potentially sensitive data (names, usernames, passwords, emails, phone numbers,
API keys/tokens) from a scanned codebase and aggregates it into a compact inventory
for display in the report UI.

Approach:
- Fast regex/heuristic extraction (Python techniques)
- Optional Gemini classification to validate/normalize categories

Safety:
- Passwords/API keys are always masked in stored output
- Gemini requests avoid sending raw secrets (metadata/redacted previews only)
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


# --- Gemini client (optional) ------------------------------------------------
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai  # type: ignore

        genai_client = genai.Client(api_key=settings.gemini_api_key)
    except ImportError:
        logger.warning("SensitiveData: google-genai not installed, AI classification disabled")


# --- Limits (tunable via env) ------------------------------------------------
MAX_TOTAL_MATCHES = int(os.getenv("MAX_SENSITIVE_DATA_MATCHES", "5000"))
MAX_ITEMS_TOTAL = int(os.getenv("MAX_SENSITIVE_DATA_ITEMS", "800"))
MAX_OCCURRENCES_PER_ITEM = int(os.getenv("MAX_SENSITIVE_DATA_OCCURRENCES_PER_ITEM", "25"))
MAX_GEMINI_CANDIDATES = int(os.getenv("MAX_SENSITIVE_DATA_AI_CANDIDATES", "200"))

# Enable/disable Gemini classification for the inventory (requires GEMINI_API_KEY)
ENABLE_GEMINI_CLASSIFICATION = os.getenv("ENABLE_SENSITIVE_DATA_AI", "true").lower() in {"1", "true", "yes", "on"}


# --- File scanning rules -----------------------------------------------------
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".tox",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    "target",
    "out",
}

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rb",
    ".php",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".env",
    ".properties",
    ".ini",
    ".conf",
    ".config",
    ".toml",
    ".gradle",
    ".sql",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".scss",
    ".sh",
    ".bash",
    ".zsh",
}

MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_SENSITIVE_DATA_FILE_SIZE_BYTES", str(5 * 1024 * 1024)))  # 5MB


# --- Regex patterns ----------------------------------------------------------
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")

# Broad phone candidate matcher; validated by digit-count heuristics after match.
PHONE_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{8,}\d)(?!\d)")

# Key/value extraction (common config + code patterns)
USERNAME_KV_RE = re.compile(
    r"""(?ix)
    \b(?P<key>username|user_name|login|user_id|userid)\b
    \s*[:=]\s*
    (?P<val>
        "(?:[^"\\]|\\.){1,80}" |
        '(?:[^'\\]|\\.){1,80}' |
        [^\s#;]{1,80}
    )
    """
)

PASSWORD_KV_RE = re.compile(
    r"""(?ix)
    \b(?P<key>password|passwd|pwd|passphrase)\b
    \s*[:=]\s*
    (?P<val>
        "(?:[^"\\]|\\.){1,120}" |
        '(?:[^'\\]|\\.){1,120}' |
        [^\s#;]{1,120}
    )
    """
)

APIKEY_KV_RE = re.compile(
    r"""(?ix)
    \b(?P<key>api[_-]?key|apikey|access[_-]?key|token|auth[_-]?token|secret[_-]?key)\b
    \s*[:=]\s*
    (?P<val>
        "(?:[^"\\]|\\.){6,200}" |
        '(?:[^'\\]|\\.){6,200}' |
        [^\s#;]{6,200}
    )
    """
)

NAME_KV_RE = re.compile(
    r"""(?ix)
    \b(?P<key>full[_-]?name|first[_-]?name|last[_-]?name|author|owner|contact[_-]?name|name)\b
    \s*[:=]\s*
    (?P<val>
        "(?:[^"\\]|\\.){1,80}" |
        '(?:[^'\\]|\\.){1,80}'
    )
    """
)


PLACEHOLDER_VALUE_RE = re.compile(
    r"(?i)\b(example|sample|changeme|change_me|your[_-]?(?:name|user|username|password|token|key)|test|dummy|placeholder|xxxx+)\b"
)


ALLOWED_KINDS = {"name", "username", "password", "email", "phone", "api_key", "other"}


@dataclass
class ExtractedMatch:
    kind: str
    raw_value: str
    file_path: str
    line_number: int
    line_excerpt: str
    key_name: Optional[str] = None


def _iter_text_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune directories
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                if path.suffix.lower() not in TEXT_EXTENSIONS:
                    continue
                if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _looks_like_reference(value: str) -> bool:
    v = value.strip()
    if not v:
        return True
    lowered = v.lower()
    # env / template references
    if lowered.startswith("${") or lowered.startswith("$(") or lowered.startswith("$"):
        return True
    if "os.getenv" in lowered or "process.env" in lowered:
        return True
    if lowered in {"null", "none", "true", "false"}:
        return True
    # Code/templating references
    if any(ch in v for ch in (".", "(", ")", "{", "}", "[", "]")):
        return True
    if any(prefix in lowered for prefix in ("request.", "settings.", "config.", "env.", "os.environ", "process.env")):
        return True
    # Likely env-var placeholders in config files
    if v.isupper() and len(v) >= 4 and ("_" in v or "-" in v):
        return True
    return False


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _mask_generic(value: str, prefix: int = 4, suffix: int = 4) -> str:
    if value is None:
        return ""
    v = value.strip()
    if len(v) <= prefix + suffix + 2:
        return "*" * len(v)
    return f"{v[:prefix]}{'*' * (len(v) - prefix - suffix)}{v[-suffix:]}"


def _mask_email(email: str) -> str:
    email = email.strip()
    if "@" not in email:
        return _mask_generic(email, 2, 2)
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[:1] + "*" * max(0, len(local) - 1)
    else:
        masked_local = local[:1] + "*" * (len(local) - 2) + local[-1:]
    return f"{masked_local}@{domain}"


def _normalize_phone(raw: str) -> Optional[str]:
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10 or len(digits) > 15:
        return None
    return digits


def _mask_phone(normalized_digits: str) -> str:
    if len(normalized_digits) <= 4:
        return "*" * len(normalized_digits)
    return f"{'*' * (len(normalized_digits) - 4)}{normalized_digits[-4:]}"


def _line_excerpt_safe(line: str, raw_value: str, masked_value: str, redact: bool) -> str:
    excerpt = line.strip()
    if not excerpt:
        return ""
    if redact:
        # Replace the raw value if present; otherwise just return the line without risking echoing secrets.
        if raw_value and raw_value in excerpt:
            return excerpt.replace(raw_value, "<redacted>")
        return "<redacted>"
    # Non-secret: show masked in-line to avoid leaking full PII into the UI payload.
    if raw_value and raw_value in excerpt:
        return excerpt.replace(raw_value, masked_value)
    return excerpt[:240]


def _extract_from_file(path: Path, rel_path: str, remaining_budget: int) -> Tuple[List[ExtractedMatch], int]:
    matches: List[ExtractedMatch] = []
    consumed = 0

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                if consumed >= remaining_budget:
                    break
                if not line or len(line) < 3:
                    continue

                # Emails
                for m in EMAIL_RE.finditer(line):
                    raw = m.group(0)
                    masked = _mask_email(raw)
                    matches.append(
                        ExtractedMatch(
                            kind="email",
                            raw_value=raw,
                            file_path=rel_path,
                            line_number=line_number,
                            line_excerpt=_line_excerpt_safe(line, raw, masked, redact=False),
                        )
                    )
                    consumed += 1
                    if consumed >= remaining_budget:
                        break

                if consumed >= remaining_budget:
                    break

                # Phone candidates (validated)
                for m in PHONE_CANDIDATE_RE.finditer(line):
                    raw = m.group(0)
                    normalized = _normalize_phone(raw)
                    if not normalized:
                        continue
                    masked = _mask_phone(normalized)
                    matches.append(
                        ExtractedMatch(
                            kind="phone",
                            raw_value=normalized,  # store normalized digits as value for dedupe
                            file_path=rel_path,
                            line_number=line_number,
                            line_excerpt=_line_excerpt_safe(line, raw, masked, redact=False),
                        )
                    )
                    consumed += 1
                    if consumed >= remaining_budget:
                        break

                if consumed >= remaining_budget:
                    break

                # Key/value patterns (names/usernames/passwords/api keys)
                for rx, kind in (
                    (NAME_KV_RE, "name"),
                    (USERNAME_KV_RE, "username"),
                    (PASSWORD_KV_RE, "password"),
                    (APIKEY_KV_RE, "api_key"),
                ):
                    for m in rx.finditer(line):
                        key_name = m.group("key")
                        raw_val = _strip_quotes(m.group("val"))
                        if not raw_val:
                            continue
                        # Avoid capturing obvious references (env vars etc.)
                        if kind in {"username", "password", "api_key"} and _looks_like_reference(raw_val):
                            continue
                        # Reduce noise on generic "name" keys unless it looks like a person name
                        if kind == "name" and key_name.lower() == "name":
                            if not re.fullmatch(r"[A-Za-z][A-Za-z.'-]*(?:\s+[A-Za-z][A-Za-z.'-]*){1,2}", raw_val.strip()):
                                continue

                        if kind == "name":
                            masked_val = raw_val
                        elif kind == "username":
                            masked_val = _mask_generic(raw_val, 2, 1) if len(raw_val) > 6 else raw_val
                        else:
                            masked_val = _mask_generic(raw_val, 3, 2)
                        redact = kind in {"password", "api_key"}
                        matches.append(
                            ExtractedMatch(
                                kind=kind,
                                raw_value=raw_val,
                                file_path=rel_path,
                                line_number=line_number,
                                line_excerpt=_line_excerpt_safe(line, raw_val, masked_val, redact=redact),
                                key_name=key_name,
                            )
                        )
                        consumed += 1
                        if consumed >= remaining_budget:
                            break
                    if consumed >= remaining_budget:
                        break

                if consumed >= remaining_budget:
                    break

    except Exception:
        return [], 0

    return matches, consumed


def _map_secret_type_to_kind(secret_type: str) -> str:
    st = (secret_type or "").lower()
    if "password" in st:
        return "password"
    if "private key" in st:
        return "api_key"
    if "connection" in st:
        return "api_key"
    if "jwt" in st and "secret" in st:
        return "api_key"
    return "api_key"


def _should_skip_placeholder(raw_value: str) -> bool:
    if not raw_value:
        return True
    if PLACEHOLDER_VALUE_RE.search(raw_value):
        return True
    return False


def _build_gemini_candidates(items_by_hash: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    for value_hash, item in items_by_hash.items():
        if len(candidates) >= MAX_GEMINI_CANDIDATES:
            break
        # Never send raw secrets from secret scanner findings
        if item.get("source") == "secret_scanner":
            continue

        kind = item.get("kind", "other")
        sample_occ = (item.get("occurrences") or [{}])[0]
        raw_value = item.get("_raw_value") or ""
        key_name = item.get("key_name")

        send_value = raw_value
        if kind in {"password", "api_key"}:
            # Avoid sending raw secrets; provide metadata only
            send_value = "<redacted>"

        candidates.append(
            {
                "id": value_hash,
                "detected_kind": kind,
                "key_name": key_name,
                "value": send_value,
                "value_meta": {
                    "length": len(raw_value),
                    "has_at": "@" in raw_value,
                    "digits": len(re.sub(r"\\D", "", raw_value)),
                },
                "file_path": sample_occ.get("file_path"),
                "line_number": sample_occ.get("line_number"),
                "line_excerpt": sample_occ.get("line_excerpt"),
            }
        )
    return candidates


def _gemini_classify(candidates: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not genai_client or not candidates:
        return {}
    try:
        from google.genai import types  # type: ignore
        import json

        prompt = f"""You are classifying strings extracted from a source code scan for a security UI.

Given a JSON array of candidates, classify each entry as one of:
  - name
  - username
  - password
  - email
  - phone
  - api_key
  - other

Return ONLY valid JSON as an array of objects:
[
  {{
    "id": "<same id>",
    "type": "<one of the allowed types>",
    "confidence": 0.0-1.0,
    "likely_placeholder": true/false,
    "reason": "<short reason>"
  }}
]

Rules:
- Do NOT echo secrets. If value is "<redacted>", infer based on key_name/value_meta/line_excerpt.
- If it looks like a placeholder/test/demo value, set likely_placeholder=true.

INPUT:
{json.dumps(candidates, ensure_ascii=False)}
"""

        response = genai_client.models.generate_content(
            model=settings.gemini_model_id or "gemini-3-flash-preview",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=2000,
            ),
        )
        text = (response.text or "").strip()
        # Extract JSON array from the response
        m = re.search(r"\[[\s\S]*\]", text)
        if not m:
            return {}
        payload = m.group(0)
        parsed = json.loads(payload)
        results: Dict[str, Dict[str, Any]] = {}
        if isinstance(parsed, list):
            for entry in parsed:
                if not isinstance(entry, dict):
                    continue
                entry_id = str(entry.get("id") or "")
                entry_type = str(entry.get("type") or "other").lower()
                if not entry_id:
                    continue
                if entry_type not in ALLOWED_KINDS:
                    entry_type = "other"
                results[entry_id] = {
                    "type": entry_type,
                    "confidence": float(entry.get("confidence") or 0.0),
                    "likely_placeholder": bool(entry.get("likely_placeholder") or False),
                    "reason": str(entry.get("reason") or ""),
                }
        return results
    except Exception as e:
        logger.warning(f"SensitiveData: Gemini classification failed: {e}")
        return {}


def build_sensitive_data_inventory(
    source_root: Path,
    findings: List[Any],
) -> Dict[str, Any]:
    """
    Build a sensitive data inventory for a report.

    Args:
        source_root: extracted source directory (temporary)
        findings: list[Finding] (SQLAlchemy models) to reuse secret scanner results

    Returns:
        JSON-serializable dict suitable for storing in report.data.scan_stats
    """
    started = datetime.now(timezone.utc)
    items_by_hash: Dict[str, Dict[str, Any]] = {}
    total_matches = 0
    truncated = False

    # 1) Reuse secret scanner findings already in the scan results
    for f in findings or []:
        try:
            if getattr(f, "type", None) != "secret":
                continue
            details = getattr(f, "details", None) or {}
            secret_type = str(details.get("secret_type") or "Secret")
            masked_value = str(details.get("masked_value") or "")
            kind = _map_secret_type_to_kind(secret_type)
            value_hash = _sha256(f"secret:{kind}:{secret_type}:{masked_value}")

            item = items_by_hash.get(value_hash)
            if not item:
                item = {
                    "kind": kind,
                    "label": secret_type,
                    "masked_value": masked_value,
                    "value_hash": value_hash,
                    "confidence": 0.95,
                    "source": "secret_scanner",
                    "occurrences": [],
                }
                items_by_hash[value_hash] = item
            occ = {
                "file_path": getattr(f, "file_path", None),
                "line_number": getattr(f, "start_line", None),
                "line_excerpt": str(getattr(f, "summary", "") or "")[:240],
            }
            if len(item["occurrences"]) < MAX_OCCURRENCES_PER_ITEM:
                item["occurrences"].append(occ)
        except Exception:
            continue

    # 2) Scan repository text files for emails/phones/names/usernames/passwords/api key assignments
    for path in _iter_text_files(source_root):
        if total_matches >= MAX_TOTAL_MATCHES:
            truncated = True
            break

        try:
            rel_path = str(path.relative_to(source_root))
        except Exception:
            rel_path = str(path)

        extracted, consumed = _extract_from_file(
            path, rel_path, remaining_budget=(MAX_TOTAL_MATCHES - total_matches)
        )
        total_matches += consumed

        for match in extracted:
            if len(items_by_hash) >= MAX_ITEMS_TOTAL:
                truncated = True
                break

            # Skip obvious placeholders for non-email/phone, to reduce noise.
            if match.kind in {"name", "username"} and _should_skip_placeholder(match.raw_value):
                continue

            raw = match.raw_value.strip()
            if not raw:
                continue

            if match.kind == "email":
                masked_value = _mask_email(raw)
                hash_input = f"email:{raw.lower()}"
            elif match.kind == "phone":
                masked_value = _mask_phone(raw)
                hash_input = f"phone:{raw}"
            elif match.kind == "password":
                masked_value = _mask_generic(raw, 3, 2)
                hash_input = f"password:{_sha256(raw)}"
            elif match.kind == "api_key":
                masked_value = _mask_generic(raw, 4, 4)
                hash_input = f"api_key:{_sha256(raw)}"
            elif match.kind == "username":
                masked_value = _mask_generic(raw, 2, 1) if len(raw) > 6 else raw
                hash_input = f"username:{raw.lower()}"
            else:  # name
                masked_value = raw
                hash_input = f"name:{raw.lower()}"

            value_hash = _sha256(hash_input)
            item = items_by_hash.get(value_hash)
            if not item:
                item = {
                    "kind": match.kind,
                    "label": match.key_name or None,
                    "masked_value": masked_value,
                    "value_hash": value_hash,
                    "confidence": 0.7 if match.kind in {"name", "username"} else 0.9,
                    "source": "regex",
                    "occurrences": [],
                    # Internal (not returned) raw value for Gemini metadata/classification
                    "_raw_value": raw,
                    "key_name": match.key_name,
                }
                items_by_hash[value_hash] = item

            if len(item["occurrences"]) < MAX_OCCURRENCES_PER_ITEM:
                item["occurrences"].append(
                    {
                        "file_path": match.file_path,
                        "line_number": match.line_number,
                        "line_excerpt": match.line_excerpt[:240] if match.line_excerpt else "",
                    }
                )

        if truncated:
            break

    # 3) Optional Gemini classification
    gemini_used = False
    gemini_error: Optional[str] = None
    gemini_model = None
    if ENABLE_GEMINI_CLASSIFICATION and genai_client and MAX_GEMINI_CANDIDATES > 0:
        try:
            candidates = _build_gemini_candidates(items_by_hash)
            if candidates:
                gemini_model = settings.gemini_model_id or "gemini-3-flash-preview"
                results = _gemini_classify(candidates)
                if results:
                    gemini_used = True
                    for value_hash, item in items_by_hash.items():
                        r = results.get(value_hash)
                        if not r:
                            continue
                        item["gemini"] = r
                        # Re-map kind when Gemini is confident enough
                        g_type = r.get("type")
                        g_conf = float(r.get("confidence") or 0.0)
                        if g_type in ALLOWED_KINDS and g_type != "other" and g_conf >= 0.75:
                            item["kind"] = g_type
        except Exception as e:
            gemini_error = str(e)

    # 4) Build final grouped inventory payload (remove internal raw values)
    categories: Dict[str, Dict[str, Any]] = {}
    totals: Dict[str, int] = {k: 0 for k in ["names", "usernames", "passwords", "emails", "phones", "api_keys"]}

    def kind_to_bucket(kind: str) -> str:
        return {
            "name": "names",
            "username": "usernames",
            "password": "passwords",
            "email": "emails",
            "phone": "phones",
            "api_key": "api_keys",
        }.get(kind, "other")

    for item in items_by_hash.values():
        kind = str(item.get("kind") or "other")
        bucket = kind_to_bucket(kind)
        if bucket == "other":
            continue

        categories.setdefault(
            bucket,
            {
                "label": {
                    "names": "People Names",
                    "usernames": "Usernames",
                    "passwords": "Passwords",
                    "emails": "Email Addresses",
                    "phones": "Phone Numbers",
                    "api_keys": "API Keys & Tokens",
                }.get(bucket, bucket),
                "count": 0,
                "items": [],
            },
        )

        public_item = {k: v for k, v in item.items() if not k.startswith("_")}
        categories[bucket]["items"].append(public_item)
        categories[bucket]["count"] += 1
        totals[bucket] += 1

    # Sort items (secrets first, then by occurrence count)
    for bucket, cat in categories.items():
        cat["items"].sort(
            key=lambda i: (
                0 if i.get("source") == "secret_scanner" else 1,
                -(len(i.get("occurrences") or [])),
            )
        )

    ended = datetime.now(timezone.utc)
    duration_ms = int((ended - started).total_seconds() * 1000)

    inventory: Dict[str, Any] = {
        "generated_at": started.isoformat(),
        "duration_ms": duration_ms,
        "used_gemini": gemini_used,
        "gemini_model": gemini_model,
        "gemini_error": gemini_error,
        "totals": {**totals, "total": sum(totals.values())},
        "categories": categories,
        "truncated": truncated,
    }
    return inventory
