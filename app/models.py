import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253, examples=["example.com"])

    @field_validator("domain")
    @classmethod
    def domain_only(cls, value: str) -> str:
        value = value.strip().rstrip(".").lower()
        if "://" in value or "/" in value or ":" in value:
            raise ValueError("Enter a domain only, without a scheme, path, or port")
        try:
            ascii_domain = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid domain") from exc
        try:
            ipaddress.ip_address(ascii_domain)
        except ValueError:
            pass
        else:
            raise ValueError("Enter a domain name, not an IP address")
        labels = ascii_domain.split(".")
        if len(labels) < 2 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        ):
            raise ValueError("Invalid domain")
        return ascii_domain


class Finding(BaseModel):
    id: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    detail: str


class ScanResponse(BaseModel):
    domain: str
    resolved_ips: list[str]
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    tls: dict[str, object]
    cms: dict[str, object]
    findings: list[Finding]

