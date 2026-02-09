"""Asset models representing hosts, services, users, and cloud resources."""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """Base class for all asset types."""

    id: str = ""
    source: str = "unknown"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)
    raw_properties: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid4())


class Host(Asset):
    """A network host (server, workstation, etc.)."""

    ip: str = ""
    hostname: Optional[str] = None
    os: Optional[str] = None
    domain: Optional[str] = None
    mac_address: Optional[str] = None
    is_dc: bool = False
    enabled: bool = True
    ports: list[int] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"host:{self.ip or self.hostname}"

    @property
    def fqdn(self) -> str:
        """Return fully qualified domain name if available."""
        if self.hostname and self.domain:
            if not self.hostname.endswith(self.domain):
                return f"{self.hostname}.{self.domain}"
        return self.hostname or self.ip


class Service(Asset):
    """A network service running on a host."""

    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    product: Optional[str] = None
    version: Optional[str] = None
    host_id: Optional[str] = None
    banner: Optional[str] = None
    ssl: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"service:{self.host_id}:{self.port}/{self.protocol}"

    @property
    def display_name(self) -> str:
        """Human-readable service name."""
        if self.product and self.version:
            return f"{self.name} ({self.product} {self.version})"
        elif self.product:
            return f"{self.name} ({self.product})"
        return self.name


class User(Asset):
    """A user account (AD user, local user, cloud identity)."""

    username: str
    domain: Optional[str] = None
    display_name: Optional[str] = None
    email: Optional[str] = None
    enabled: bool = True
    is_admin: bool = False
    password_never_expires: bool = False
    last_logon: Optional[datetime] = None
    groups: list[str] = Field(default_factory=list)
    object_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            if self.domain:
                self.id = f"user:{self.domain}\\{self.username}"
            else:
                self.id = f"user:{self.username}"

    @property
    def principal_name(self) -> str:
        """Return domain\\username format."""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username


class CloudResource(Asset):
    """A cloud resource (AWS, Azure, GCP)."""

    resource_id: str
    resource_type: str
    name: Optional[str] = None
    provider: str = "unknown"
    account_id: Optional[str] = None
    tenant_id: Optional[str] = None
    subscription_id: Optional[str] = None
    region: Optional[str] = None
    app_id: Optional[str] = None
    arn: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"cloud:{self.provider}:{self.resource_type}:{self.resource_id}"

    @property
    def display_name(self) -> str:
        """Human-readable resource identifier."""
        return self.name or self.resource_id


class Container(Asset):
    """A container instance."""

    container_id: str
    image: Optional[str] = None
    registry: Optional[str] = None
    runtime: Optional[str] = None
    namespace: Optional[str] = None
    privileged: bool = False
    host_id: Optional[str] = None
    escape_chain_id: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"container:{self.container_id}"


class MobileApp(Asset):
    """A mobile application."""

    app_id: str
    name: Optional[str] = None
    platform: Optional[str] = None  # ios, android
    version: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"mobile:{self.app_id}"


class ApiEndpoint(Asset):
    """An API endpoint."""

    method: str = "GET"
    path: str = "/"
    base_url: Optional[str] = None
    parameters: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"api:{self.method}:{self.base_url or ''}{self.path}"
