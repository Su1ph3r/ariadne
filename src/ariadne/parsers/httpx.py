"""httpx HTTP probing output parser."""

import json
import re
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class HttpxParser(BaseParser):
    """Parser for httpx HTTP probing and fingerprinting output."""

    name = "httpx"
    description = "Parse httpx HTTP probing, technology detection, and response data"
    file_patterns = ["*httpx*.json", "*httpx*.txt", "httpx_*.json"]
    entity_types = ["Host", "Service", "Misconfiguration"]

    URL_PATTERN = re.compile(
        r"(?P<scheme>https?)://(?P<host>[^:/\s]+)(?::(?P<port>\d+))?(?P<path>/[^\s]*)?"
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    INTERESTING_TECH = [
        "wordpress", "drupal", "joomla", "magento", "sharepoint",
        "jenkins", "gitlab", "grafana", "kibana", "elasticsearch",
        "tomcat", "weblogic", "jboss", "coldfusion", "struts",
        "spring", "laravel", "django", "flask", "express",
        "nginx", "apache", "iis", "lighttpd",
        "php", "asp.net", "java", "python", "ruby", "node.js",
    ]

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an httpx output file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("{") or content.strip().startswith("["):
            yield from self._parse_json(content)
        else:
            yield from self._parse_text(content)

    def _parse_json(self, content: str) -> Generator[Entity, None, None]:
        """Parse httpx JSON output (JSONL format)."""
        seen_hosts: dict[str, Host] = {}

        for line in content.strip().split("\n"):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
                yield from self._parse_json_entry(entry, seen_hosts)
            except json.JSONDecodeError:
                continue

        try:
            data = json.loads(content)
            if isinstance(data, list):
                for entry in data:
                    yield from self._parse_json_entry(entry, seen_hosts)
        except json.JSONDecodeError:
            pass

    def _parse_json_entry(self, entry: dict, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a single httpx JSON entry."""
        url = entry.get("url") or entry.get("input") or ""
        host = entry.get("host") or ""
        port = entry.get("port") or 0
        scheme = entry.get("scheme") or ""
        status_code = entry.get("status_code") or entry.get("status-code") or 0
        title = entry.get("title") or ""
        webserver = entry.get("webserver") or entry.get("server") or ""
        tech = entry.get("tech") or entry.get("technologies") or []
        content_length = entry.get("content_length") or entry.get("content-length") or 0
        content_type = entry.get("content_type") or entry.get("content-type") or ""
        response_time = entry.get("time") or entry.get("response-time") or ""
        tls = entry.get("tls") or entry.get("tls-grab") or {}
        cdn = entry.get("cdn") or entry.get("cdn-name") or ""
        a_records = entry.get("a") or []
        cname = entry.get("cname") or []
        headers = entry.get("header") or entry.get("headers") or {}

        if isinstance(tech, str):
            tech = [tech]
        if isinstance(a_records, str):
            a_records = [a_records]

        if not host and url:
            url_match = self.URL_PATTERN.match(url)
            if url_match:
                host = url_match.group("host")
                if not port:
                    port = int(url_match.group("port") or (443 if url_match.group("scheme") == "https" else 80))
                if not scheme:
                    scheme = url_match.group("scheme")

        if not host:
            return

        ip = ""
        if a_records:
            ip = a_records[0]
        elif self.IPV4_PATTERN.match(host):
            ip = host
            host = ""

        if not port:
            port = 443 if scheme == "https" else 80

        host_key = f"{host or ip}:{port}"
        if host_key not in seen_hosts:
            tags = ["web", "recon"]
            if cdn:
                tags.append(f"cdn:{cdn}")

            host_obj = Host(
                ip=ip,
                hostname=host if host and not self.IPV4_PATTERN.match(host) else None,
                source="httpx",
                tags=tags,
            )
            seen_hosts[host_key] = host_obj
            yield host_obj

            service = Service(
                host_id=host_obj.id,
                port=port,
                protocol="tcp",
                service_name="https" if scheme == "https" else "http",
                product=webserver,
                extra_info=title,
                source="httpx",
                raw_properties={
                    "url": url,
                    "status_code": status_code,
                    "content_type": content_type,
                    "content_length": content_length,
                    "technologies": tech,
                    "response_time": response_time,
                },
            )
            yield service

            for t in tech:
                if t.lower() in self.INTERESTING_TECH:
                    yield Misconfiguration(
                        title=f"Technology Detected: {t}",
                        description=f"Detected {t} on {url or host}",
                        severity="info",
                        affected_asset_id=host_obj.id,
                        source="httpx",
                        check_id=f"tech_{t.lower().replace(' ', '_')}",
                        tags=["technology", t.lower()],
                    )

            if isinstance(headers, dict):
                headers_lower = {k.lower(): v for k, v in headers.items()}
                missing_headers = [h for h in self.SECURITY_HEADERS if h not in headers_lower]

                if missing_headers and status_code and 200 <= status_code < 400:
                    yield Misconfiguration(
                        title=f"Missing Security Headers: {host or ip}",
                        description=f"Missing headers: {', '.join(missing_headers)}",
                        severity="low",
                        affected_asset_id=host_obj.id,
                        source="httpx",
                        check_id="missing_security_headers",
                        tags=["headers", "security"],
                    )

            if status_code in [401, 403]:
                yield Misconfiguration(
                    title=f"Protected Resource: {url or host}",
                    description=f"Resource returned {status_code} - may contain sensitive data",
                    severity="info",
                    affected_asset_id=host_obj.id,
                    source="httpx",
                    check_id=f"protected_{status_code}",
                    tags=["auth"],
                )

            if status_code == 200 and any(x in (title or "").lower() for x in ["admin", "login", "dashboard", "panel"]):
                yield Misconfiguration(
                    title=f"Admin/Login Panel: {url or host}",
                    description=f"Found potential admin panel: {title}",
                    severity="info",
                    affected_asset_id=host_obj.id,
                    source="httpx",
                    check_id="admin_panel",
                    tags=["admin", "login"],
                )

    def _parse_text(self, content: str) -> Generator[Entity, None, None]:
        """Parse httpx text output (URLs only)."""
        seen_hosts: dict[str, Host] = {}

        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            url_match = self.URL_PATTERN.match(line)
            if url_match:
                scheme = url_match.group("scheme")
                host = url_match.group("host")
                port = int(url_match.group("port") or (443 if scheme == "https" else 80))

                host_key = f"{host}:{port}"
                if host_key in seen_hosts:
                    continue

                ip = ""
                hostname = host
                if self.IPV4_PATTERN.match(host):
                    ip = host
                    hostname = ""

                host_obj = Host(
                    ip=ip,
                    hostname=hostname if hostname else None,
                    source="httpx",
                    tags=["web", "recon"],
                )
                seen_hosts[host_key] = host_obj
                yield host_obj

                yield Service(
                    host_id=host_obj.id,
                    port=port,
                    protocol="tcp",
                    service_name="https" if scheme == "https" else "http",
                    source="httpx",
                )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an httpx output file."""
        name_lower = file_path.name.lower()
        if "httpx" in name_lower:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"httpx",
                    b'"url"',
                    b'"host"',
                    b'"status_code"',
                    b'"status-code"',
                    b'"webserver"',
                    b'"tech"',
                    b'"title"',
                    b'"content_length"',
                    b'"tls"',
                ]
                return sum(1 for ind in indicators if ind in header) >= 3
        except Exception:
            return False
