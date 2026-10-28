import pytest

from app.models import ScanRequest
from app.scanner import analyze_headers, detect_cms


@pytest.mark.parametrize("domain", ["localhost", "127.0.0.1", "https://example.com", "example.com:443", "bad/domain"])
def test_domain_validation(domain: str) -> None:
    with pytest.raises(ValueError):
        ScanRequest(domain=domain)


def test_header_findings() -> None:
    findings = analyze_headers({"server": "demo"})
    ids = {finding.id for finding in findings}
    assert "missing-strict-transport-security" in ids
    assert "clickjacking" in ids
    assert "server-disclosure" in ids


def test_detects_wordpress() -> None:
    result = detect_cms({}, '<link href="/wp-content/themes/demo/style.css">')
    assert result["detected"] == "wordpress"

