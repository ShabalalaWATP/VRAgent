from types import SimpleNamespace

import pytest
import subprocess

from backend.services import cve_service, docker_scan_service, epss_service, nvd_service


def _sample_packages():
    return [
        docker_scan_service.DockerPackage(
            name="openssl",
            version="3.0.0",
            ecosystem="deb",
            pkg_type="os",
            layer=None,
            locations=["/var/lib/dpkg/status"],
        )
    ]


async def _fake_extract_packages(_image_name: str, timeout: int = 300):
    return _sample_packages(), {
        "trivy_available": True,
        "extraction_method": "test",
        "os_detected": "debian",
        "packages_by_type": {"deb": 1},
        "error": None,
    }


async def _fake_lookup_dependencies(_deps):
    return [
        SimpleNamespace(
            dependency_id=0,
            external_id="CVE-2025-1234",
            title="Sample vulnerability",
            description="Sample description",
            severity="high",
            cvss_score=7.5,
            source="osv",
        )
    ]


@pytest.mark.asyncio
async def test_extract_packages_from_image_requires_trivy(monkeypatch):
    monkeypatch.setattr(docker_scan_service, "is_trivy_available", lambda: False)

    packages, metadata = await docker_scan_service.extract_packages_from_image("alpine:3.19")

    assert packages == []
    assert metadata["trivy_available"] is False
    assert metadata["error"] == "Trivy is required for Docker package extraction and CVE scanning"


@pytest.mark.asyncio
async def test_scan_image_packages_for_cves_applies_epss_without_nvd(monkeypatch):
    async def fake_enrich_epss(vulnerabilities):
        vulnerabilities[0]["epss_score"] = 0.91
        vulnerabilities[0]["epss_percentile"] = 0.97
        vulnerabilities[0]["epss_priority"] = "critical"
        return vulnerabilities

    monkeypatch.setattr(docker_scan_service, "extract_packages_from_image", _fake_extract_packages)
    monkeypatch.setattr(cve_service, "lookup_dependencies", _fake_lookup_dependencies)
    monkeypatch.setattr(epss_service, "enrich_vulnerabilities_with_epss", fake_enrich_epss)

    result = await docker_scan_service.scan_image_packages_for_cves(
        "debian:12",
        include_nvd_enrichment=False,
        include_kev=False,
        include_epss=True,
    )

    assert result.error is None
    assert result.enrichment_applied is True
    assert result.high_epss_count == 1
    assert result.vulnerabilities[0]["epss_score"] == pytest.approx(0.91)
    assert result.vulnerabilities[0]["epss_priority"] == "critical"


@pytest.mark.asyncio
async def test_scan_image_packages_for_cves_applies_kev_without_nvd(monkeypatch):
    async def fake_check_kev_status(cve_ids):
        assert cve_ids == ["CVE-2025-1234"]
        return {"CVE-2025-1234": True}

    monkeypatch.setattr(docker_scan_service, "extract_packages_from_image", _fake_extract_packages)
    monkeypatch.setattr(cve_service, "lookup_dependencies", _fake_lookup_dependencies)
    monkeypatch.setattr(nvd_service, "check_kev_status", fake_check_kev_status)

    result = await docker_scan_service.scan_image_packages_for_cves(
        "debian:12",
        include_nvd_enrichment=False,
        include_kev=True,
        include_epss=False,
    )

    assert result.error is None
    assert result.enrichment_applied is True
    assert result.kev_count == 1
    assert result.vulnerabilities[0]["in_kev"] is True


@pytest.mark.asyncio
async def test_scan_image_with_trivy_native_parses_all_enabled_scanners(monkeypatch):
    sample_payload = {
        "ArtifactName": "demo:latest",
        "ArtifactType": "container_image",
        "SchemaVersion": 2,
        "Trivy": "0.69.3",
        "Metadata": {"OS": {"Family": "alpine", "Name": "3.23.3"}},
        "Results": [
            {
                "Target": "demo:latest (alpine 3.23.3)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Packages": [
                    {"ID": "openssl@3.0.0-r0", "Name": "openssl", "Version": "3.0.0-r0"},
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-1000",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.0-r0",
                        "FixedVersion": "3.0.0-r1",
                        "Status": "fixed",
                        "Severity": "HIGH",
                        "Title": "Sample vuln",
                        "Description": "Sample description",
                        "PrimaryURL": "https://example.invalid/CVE-2026-1000",
                        "References": ["https://example.invalid/ref-1"],
                        "Layer": {"Digest": "sha256:abc", "DiffID": "sha256:def"},
                        "DataSource": {"ID": "alpine", "Name": "Alpine Secdb"},
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "DS001",
                        "AVDID": "AVD-DS-001",
                        "Title": "Root user",
                        "Description": "Container runs as root",
                        "Message": "Avoid USER root",
                        "Resolution": "Set a non-root user",
                        "Severity": "CRITICAL",
                        "PrimaryURL": "https://example.invalid/misconfig",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Title": "AWS access key",
                        "Severity": "CRITICAL",
                        "Match": "AKIAIOSFODNN7EXAMPLE",
                        "StartLine": 12,
                        "EndLine": 12,
                    }
                ],
            },
            {
                "Target": "OS Packages",
                "Class": "license",
                "Licenses": [
                    {
                        "Name": "GPL-2.0-only",
                        "Severity": "HIGH",
                        "Category": "restricted",
                        "PkgName": "busybox",
                        "Confidence": 1,
                    }
                ],
            },
        ],
    }

    monkeypatch.setattr(docker_scan_service, "_get_trivy_executable", lambda: "trivy")

    def fake_run(cmd, capture_output, text, timeout):
        assert "--scanners" in cmd
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=docker_scan_service.json.dumps(sample_payload),
            stderr="",
        )

    monkeypatch.setattr(docker_scan_service.subprocess, "run", fake_run)

    result = await docker_scan_service.scan_image_with_trivy_native(
        "demo:latest",
        include_vulnerabilities=True,
        include_misconfigurations=True,
        include_secrets=True,
        include_licenses=True,
    )

    assert result.error is None
    assert result.enabled_scanners == ["vuln", "misconfig", "secret", "license"]
    assert result.package_count == 1
    assert result.vulnerability_severity_counts == {"high": 1}
    assert result.misconfiguration_severity_counts == {"critical": 1}
    assert result.secret_severity_counts == {"critical": 1}
    assert result.license_severity_counts == {"high": 1}
    assert result.vulnerabilities[0]["layer"]["digest"] == "sha256:abc"
    assert result.secrets[0]["match"] == "AKIAIOSFODNN7EXAMPLE"
    assert result.licenses[0]["name"] == "GPL-2.0-only"


def test_generate_trivy_sbom_returns_json_payload(monkeypatch):
    monkeypatch.setattr(docker_scan_service, "_get_trivy_executable", lambda: "trivy")

    def fake_run(cmd, capture_output, text, timeout):
        assert "--format" in cmd
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=b'{"bomFormat":"CycloneDX"}',
            stderr=b"",
        )

    monkeypatch.setattr(docker_scan_service.subprocess, "run", fake_run)

    payload, media_type, error = docker_scan_service.generate_trivy_sbom("demo:latest", format="cyclonedx")

    assert error is None
    assert media_type == "application/json"
    assert payload == b'{"bomFormat":"CycloneDX"}'
