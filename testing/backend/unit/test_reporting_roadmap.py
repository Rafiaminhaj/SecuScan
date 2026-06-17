import pytest
from backend.secuscan.reporting import ReportGenerator

@pytest.fixture
def sample_task():
    return {
        "id": "task-123",
        "tool_name": "Test Scanner",
        "plugin_id": "test_plugin",
        "target": "example.com",
        "status": "completed",
        "created_at": "2026-06-17T12:00:00.000000Z",
        "preset": "Full Scan",
        "command_used": "test-scanner --target example.com",
        "inputs": {"depth": "deep"}
    }

@pytest.fixture
def sample_findings():
    return [
        {
            "id": "finding-1",
            "title": "SQL Injection in Login Form",
            "category": "Injection",
            "severity": "CRITICAL",
            "description": "SQL Injection vulnerability.",
            "remediation": "Use parameterized queries.",
            "target": "example.com/login.php"
        },
        {
            "id": "finding-2",
            "title": "Outdated Software Version Detected",
            "category": "Version Scan",
            "severity": "LOW",
            "description": "The remote server runs an outdated software version.",
            "remediation": "Upgrade the server software.",
            "target": "example.com"
        },
        {
            "id": "finding-3",
            "title": "Missing Security Headers",
            "category": "Headers",
            "severity": "MEDIUM",
            "description": "Vulnerability due to missing security headers.",
            "remediation": "Add security headers to response.",
            "target": "example.com"
        }
    ]

def test_build_remediation_roadmap(sample_findings):
    roadmap = ReportGenerator._build_remediation_roadmap(sample_findings)
    assert len(roadmap) == 3

    # First item: SQL Injection (CRITICAL -> Immediate Priority, Complex Fix)
    assert roadmap[0]["title"] == "SQL Injection in Login Form"
    assert roadmap[0]["priority"] == "Immediate"
    assert roadmap[0]["difficulty"] == "Complex Fix"

    # Second item: Missing Security Headers (MEDIUM -> Scheduled Priority, Quick Fix due to 'header' keyword)
    assert roadmap[1]["title"] == "Missing Security Headers"
    assert roadmap[1]["priority"] == "Scheduled"
    assert roadmap[1]["difficulty"] == "Quick Fix"

    # Third item: Outdated Software Version (LOW -> Backlog Priority, Quick Fix due to 'outdated' / 'version' keyword)
    assert roadmap[2]["title"] == "Outdated Software Version Detected"
    assert roadmap[2]["priority"] == "Backlog"
    assert roadmap[2]["difficulty"] == "Quick Fix"

def test_html_report_contains_roadmap(sample_task, sample_findings):
    result = {
        "findings": sample_findings,
        "structured": {"rows": []},
        "summary": ["Scan completed successfully."],
        "errors": []
    }
    html_report = ReportGenerator.generate_html_report(sample_task, result)
    assert "Remediation Roadmap" in html_report
    assert "SQL Injection in Login Form" in html_report
    assert "Immediate Priority" in html_report
    assert "Complex Fix" in html_report
