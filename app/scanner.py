import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import httpx

from app.models import Finding, ScanResponse

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512_000
USER_AGENT = "recon-header/0.1 passive-security-check"

SECURITY_HEADERS = {
    "strict-transport-security": ("high", "HSTS is missing"),
    "content-security-policy": ("medium", "Content-Security-Policy is missing"),
    "x-content-type-options": ("low", "X-Content-Type-Options is missing"),
    "referrer-policy": ("low", "Referrer-Policy is missing"),
    "permissions-policy": ("low", "Permissions-Policy is missing"),
}


async def resolve_public(domain: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        rows = await loop.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Domain could not be resolved: {exc}") from exc
    ips = sorted({row[4][0] for row in rows})
    if not ips:
        raise ValueError("Domain did not resolve to an IP address")
    blocked = [ip for ip in ips if not ipaddress.ip_address(ip).is_global]
    if blocked:
        raise ValueError("Domains resolving to private, local, or reserved addresses are not allowed")
    return ips


async def fetch(domain: str) -> tuple[str, int, dict[str, str], str]:
    current = f"https://{domain}/"
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0),
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.1"},
        follow_redirects=False,
        verify=True,
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            parsed = urlparse(current)
            if parsed.scheme not in {"http", "https"} or parsed.port not in {None, 80, 443}:
                raise ValueError("Redirected to an unsupported URL")
            await resolve_public(parsed.hostname or "")
            response = await client.get(current)
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    break
                current = urljoin(current, location)
                continue
            body = response.content[:MAX_BODY_BYTES].decode(response.encoding or "utf-8", errors="replace")
            return str(response.url), response.status_code, dict(response.headers), body
    raise ValueError("Too many redirects")


def _tls_sync(domain: str, ip: str) -> dict[str, object]:
    context = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as sock:
            cert = sock.getpeercert()
            expires = cert.get("notAfter")
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), UTC) if expires else None
            return {
                "version": sock.version(),
                "cipher": sock.cipher()[0] if sock.cipher() else None,
                "expires_at": expiry.isoformat() if expiry else None,
                "days_until_expiry": (expiry - datetime.now(UTC)).days if expiry else None,
                "issuer": dict(item[0] for item in cert.get("issuer", ())),
                "subject_alt_names": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"][:50],
            }


async def inspect_tls(domain: str, ip: str) -> dict[str, object]:
    return await asyncio.to_thread(_tls_sync, domain, ip)


def analyze_headers(headers: dict[str, str]) -> list[Finding]:
    normalized = {key.lower(): value for key, value in headers.items()}
    findings = []
    for header, (severity, title) in SECURITY_HEADERS.items():
        if header not in normalized:
            findings.append(Finding(id=f"missing-{header}", severity=severity, title=title, detail=f"The {header} response header was not observed."))
    if normalized.get("x-frame-options", "").upper() not in {"DENY", "SAMEORIGIN"} and "frame-ancestors" not in normalized.get("content-security-policy", ""):
        findings.append(Finding(id="clickjacking", severity="medium", title="Clickjacking protection was not observed", detail="Set X-Frame-Options or a CSP frame-ancestors directive."))
    if "server" in normalized:
        findings.append(Finding(id="server-disclosure", severity="info", title="Server header is exposed", detail=f"Observed Server header: {normalized['server']}"))
    return findings


def detect_cms(headers: dict[str, str], body: str) -> dict[str, object]:
    sample = body.lower()
    generator = ""
    marker = 'name="generator"'
    if marker in sample:
        start = sample.rfind("<meta", 0, sample.find(marker))
        end = sample.find(">", sample.find(marker))
        generator = body[start : end + 1] if start >= 0 and end >= 0 else ""
    signals: list[str] = []
    cms = "unknown"
    patterns = {
        "wordpress": ["wp-content/", "wp-includes/", "wordpress"],
        "drupal": ["drupal-settings-json", "/sites/default/files/", "drupal"],
        "joomla": ["/media/system/js/", "option=com_", "joomla"],
        "shopify": ["cdn.shopify.com", "shopify.theme"],
        "ghost": ["/ghost/", "ghost-url"],
    }
    for name, markers in patterns.items():
        matched = [value for value in markers if value in sample]
        if matched:
            cms, signals = name, matched
            break
    powered_by = next((value for key, value in headers.items() if key.lower() == "x-powered-by"), None)
    return {"detected": cms, "confidence": "medium" if signals else "unknown", "signals": signals, "generator_meta": generator[:500] or None, "x_powered_by": powered_by}


async def scan(domain: str) -> ScanResponse:
    ips = await resolve_public(domain)
    tls_result, web_result = await asyncio.gather(inspect_tls(domain, ips[0]), fetch(domain), return_exceptions=True)
    findings: list[Finding] = []
    tls: dict[str, object]
    if isinstance(tls_result, BaseException):
        tls = {"error": str(tls_result)}
        findings.append(Finding(id="tls-error", severity="high", title="TLS validation failed", detail=str(tls_result)))
    else:
        tls = tls_result
        if isinstance(tls.get("days_until_expiry"), int) and tls["days_until_expiry"] < 30:
            findings.append(Finding(id="tls-expiry", severity="high", title="TLS certificate expires soon", detail=f"Certificate expires in {tls['days_until_expiry']} days."))
    if isinstance(web_result, BaseException):
        findings.append(Finding(id="http-error", severity="high", title="HTTPS request failed", detail=str(web_result)))
        return ScanResponse(domain=domain, resolved_ips=ips, final_url=None, status_code=None, headers={}, tls=tls, cms={"detected": "unknown"}, findings=findings)
    final_url, status, headers, body = web_result
    findings.extend(analyze_headers(headers))
    return ScanResponse(domain=domain, resolved_ips=ips, final_url=final_url, status_code=status, headers=headers, tls=tls, cms=detect_cms(headers, body), findings=findings)

