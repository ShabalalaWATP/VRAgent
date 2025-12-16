from dataclasses import dataclass
from pathlib import Path

from backend.services.sensitive_data_service import build_sensitive_data_inventory


@dataclass
class DummyFinding:
    type: str
    file_path: str = "app.py"
    start_line: int = 1
    summary: str = ""
    details: dict | None = None


def test_build_sensitive_data_inventory_extracts_and_masks(tmp_path: Path):
    code = """
# Contact: Alice Example <alice@example.com>
username: admin
password: "SuperSecret123!"
api_key = "sk_test_FAKE_KEY_FOR_TESTING_ONLY"
phone = "+1 (415) 555-2671"
"""
    (tmp_path / "app.py").write_text(code, encoding="utf-8")

    # Also include a secret finding that should be grouped under API keys/tokens.
    findings = [
        DummyFinding(
            type="secret",
            file_path="app.py",
            start_line=4,
            summary="Potential AWS Access Key ID detected",
            details={"secret_type": "AWS Access Key ID", "masked_value": "AKIA****************1234"},
        )
    ]

    inventory = build_sensitive_data_inventory(tmp_path, findings)

    assert inventory["totals"]["emails"] >= 1
    assert inventory["totals"]["phones"] >= 1
    assert inventory["totals"]["usernames"] >= 1
    assert inventory["totals"]["passwords"] >= 1
    assert inventory["totals"]["api_keys"] >= 1

    # Ensure raw password is not stored anywhere in the payload.
    assert "SuperSecret123!" not in str(inventory)

