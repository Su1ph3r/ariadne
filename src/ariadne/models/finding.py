"""Finding models representing vulnerabilities, misconfigurations, and credentials."""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """Base class for all finding types."""

    id: str = ""
    title: str
    description: str = ""
    severity: str = "info"
    affected_asset_id: Optional[str] = None
    source: str = "unknown"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid4())

    @property
    def severity_score(self) -> float:
        """Convert severity to numeric score (0-1)."""
        scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }
        return scores.get(self.severity.lower(), 0.1)


class Vulnerability(Finding):
    """A security vulnerability (CVE, etc.)."""

    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    metasploit_module: Optional[str] = None
    patch_available: bool = False
    patch_url: Optional[str] = None
    template_id: Optional[str] = None
    cwe_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            if self.cve_id:
                self.id = f"vuln:{self.cve_id}:{self.affected_asset_id or 'unknown'}"
            else:
                self.id = f"vuln:{self.title[:30]}:{self.affected_asset_id or 'unknown'}"

    @property
    def severity_score(self) -> float:
        """Use CVSS score if available, otherwise fall back to severity string."""
        if self.cvss_score is not None:
            return min(self.cvss_score / 10.0, 1.0)
        return super().severity_score

    @property
    def is_critical(self) -> bool:
        """Check if this is a critical vulnerability."""
        if self.cvss_score and self.cvss_score >= 9.0:
            return True
        return self.severity.lower() == "critical"


class Misconfiguration(Finding):
    """A security misconfiguration."""

    check_id: Optional[str] = None
    template_id: Optional[str] = None
    rationale: Optional[str] = None
    remediation: Optional[str] = None
    compliance_frameworks: list[str] = Field(default_factory=list)
    expected_value: Optional[str] = None
    actual_value: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"misconfig:{self.check_id or self.title[:30]}:{self.affected_asset_id or 'unknown'}"


class Credential(Finding):
    """A discovered credential (hash, password, token, etc.)."""

    credential_type: str
    username: Optional[str] = None
    domain: Optional[str] = None
    value: str = ""
    hash_type: Optional[str] = None
    is_cracked: bool = False
    cracked_value: Optional[str] = None
    ntlm_hash: Optional[str] = None
    last_changed: Optional[datetime] = None
    origin: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            user_part = f"{self.domain}\\{self.username}" if self.domain else self.username
            self.id = f"cred:{self.credential_type}:{user_part or 'unknown'}"

        if not self.title:
            self.title = f"{self.credential_type} for {self.username or 'unknown'}"

    @property
    def is_hash(self) -> bool:
        """Check if this is a hash rather than plaintext."""
        return self.credential_type in ["ntlm", "lm", "sha1", "sha256", "md5", "kerberos"]

    @property
    def masked_value(self) -> str:
        """Return a masked version of the credential value."""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return self.value[:2] + "*" * (len(self.value) - 4) + self.value[-2:]
