from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.models import ScanRequest, ScanResponse
from app.scanner import scan

app = FastAPI(
    title="Recon Header API",
    description="Passive DNS, HTTP security-header, TLS, and CMS signal analysis for domains you are authorized to assess.",
    version="0.1.0",
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def web_app() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest) -> ScanResponse:
    try:
        return await scan(request.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

