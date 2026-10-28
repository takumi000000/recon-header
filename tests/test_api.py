from fastapi.testclient import TestClient

from app.main import app
from app.models import ScanResponse

client = TestClient(app)


def test_health() -> None:
    assert client.get("/health").json() == {"status": "ok"}


def test_rejects_url_instead_of_domain() -> None:
    response = client.post("/v1/scan", json={"domain": "https://example.com/path"})
    assert response.status_code == 422


def test_scan_endpoint(monkeypatch) -> None:
    async def fake_scan(domain: str) -> ScanResponse:
        return ScanResponse(domain=domain, resolved_ips=["93.184.216.34"], final_url="https://example.com/", status_code=200, headers={}, tls={}, cms={"detected": "unknown"}, findings=[])

    monkeypatch.setattr("app.main.scan", fake_scan)
    response = client.post("/v1/scan", json={"domain": "example.com"})
    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"

