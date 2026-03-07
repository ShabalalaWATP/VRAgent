import sqlite3

from backend.services import cve_service


def _create_local_osv_db(path):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.executescript(
        """
        CREATE TABLE vulnerabilities (
            id TEXT PRIMARY KEY,
            ecosystem TEXT,
            package_name TEXT,
            summary TEXT,
            details TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            published TEXT,
            modified TEXT,
            withdrawn TEXT,
            aliases TEXT,
            related TEXT
        );

        CREATE TABLE affected_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT,
            ecosystem TEXT,
            package_name TEXT,
            range_type TEXT,
            introduced TEXT,
            fixed TEXT,
            last_affected TEXT
        );
        """
    )
    cursor.execute(
        """
        INSERT INTO vulnerabilities
        (id, ecosystem, package_name, summary, details, severity, cvss_score, cvss_vector,
         published, modified, withdrawn, aliases, related)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "ALPINE-CVE-TEST-1",
            "Alpine",
            "curl",
            "curl vulnerability",
            "offline lookup regression",
            "high",
            7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "2026-03-01T00:00:00Z",
            "2026-03-02T00:00:00Z",
            None,
            "CVE-2026-0001",
            "",
        ),
    )
    cursor.execute(
        """
        INSERT INTO affected_ranges
        (vuln_id, ecosystem, package_name, range_type, introduced, fixed, last_affected)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "ALPINE-CVE-TEST-1",
            "Alpine:v3.21",
            "curl",
            "ECOSYSTEM",
            "0",
            "8.17.0-r2",
            None,
        ),
    )
    conn.commit()
    conn.close()


def test_lookup_package_vulns_local_matches_versioned_os_ecosystem(tmp_path, monkeypatch):
    db_path = tmp_path / "osv.db"
    _create_local_osv_db(db_path)
    monkeypatch.setattr(cve_service, "LOCAL_OSV_DB", str(db_path))

    vulns = cve_service._lookup_package_vulns_local("Alpine", "curl", "8.17.0-r1")

    assert len(vulns) == 1
    assert vulns[0]["id"] == "ALPINE-CVE-TEST-1"


def test_lookup_package_vulns_local_filters_fixed_versions(tmp_path, monkeypatch):
    db_path = tmp_path / "osv.db"
    _create_local_osv_db(db_path)
    monkeypatch.setattr(cve_service, "LOCAL_OSV_DB", str(db_path))

    vulns = cve_service._lookup_package_vulns_local("Alpine", "curl", "8.17.0-r2")

    assert vulns == []
