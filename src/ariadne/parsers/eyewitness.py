"""EyeWitness screenshot and web enumeration output parser."""

import json
import re
from pathlib import Path
from typing import Generator
from xml.etree import ElementTree

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class EyeWitnessParser(BaseParser):
    """Parser for EyeWitness web screenshot and enumeration output."""

    name = "eyewitness"
    description = "Parse EyeWitness web screenshots, headers, and service enumeration"
    file_patterns = ["*eyewitness*.xml", "*eyewitness*.json", "report.xml", "ew_report.xml"]
    entity_types = ["Host", "Service", "Misconfiguration"]

    URL_PATTERN = re.compile(
        r"(?P<scheme>https?)://(?P<host>[^:/\s]+)(?::(?P<port>\d+))?(?P<path>/[^\s]*)?"
    )

    IPV4_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    INTERESTING_TITLES = [
        "admin", "login", "dashboard", "panel", "management",
        "console", "portal", "control", "config", "setup",
        "jenkins", "gitlab", "grafana", "kibana", "phpmy",
        "webmail", "outlook", "exchange", "citrix", "vpn",
    ]

    DEFAULT_CREDS_INDICATORS = [
        "default", "password", "admin:admin", "root:root",
        "test", "demo", "guest", "user:user",
    ]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse an EyeWitness output file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".xml":
            yield from self._parse_xml(file_path)
        elif suffix == ".json":
            yield from self._parse_json(file_path)
        else:
            content = file_path.read_text(errors="ignore")
            if content.strip().startswith("<"):
                yield from self._parse_xml(file_path)
            elif content.strip().startswith("{") or content.strip().startswith("["):
                yield from self._parse_json(file_path)

    def _parse_xml(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse EyeWitness XML report."""
        try:
            tree = ElementTree.parse(file_path)
            root = tree.getroot()
        except ElementTree.ParseError:
            return

        seen_hosts: dict[str, Host] = {}

        for server in root.findall(".//server") or root.findall(".//host") or root.findall(".//target"):
            yield from self._parse_xml_server(server, seen_hosts)

        for item in root.findall(".//item") or root.findall(".//result"):
            yield from self._parse_xml_item(item, seen_hosts)

    def _parse_xml_server(self, server, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a single server element from XML."""
        url_elem = server.find("url") or server.find("URL")
        url = url_elem.text if url_elem is not None else ""

        source_elem = server.find("source") or server.find("host")
        source = source_elem.text if source_elem is not None else ""

        title_elem = server.find("title") or server.find("page-title")
        title = title_elem.text if title_elem is not None else ""

        headers_elem = server.find("headers") or server.find("response-headers")
        headers = headers_elem.text if headers_elem is not None else ""

        status_elem = server.find("status") or server.find("response-code")
        status = status_elem.text if status_elem is not None else ""

        screenshot_elem = server.find("screenshot") or server.find("image")
        screenshot = screenshot_elem.text if screenshot_elem is not None else ""

        category_elem = server.find("category")
        category = category_elem.text if category_elem is not None else ""

        target = url or source
        if not target:
            return

        url_match = self.URL_PATTERN.match(target)
        if url_match:
            scheme = url_match.group("scheme")
            host = url_match.group("host")
            port = int(url_match.group("port") or (443 if scheme == "https" else 80))
        else:
            host = target
            port = 80
            scheme = "http"

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            return

        ip = ""
        hostname = host
        if self.IPV4_PATTERN.match(host):
            ip = host
            hostname = ""

        tags = ["web", "screenshot"]
        if category:
            tags.append(category.lower())

        host_obj = Host(
            ip=ip,
            hostname=hostname if hostname else None,
            source="eyewitness",
            tags=tags,
        )
        seen_hosts[host_key] = host_obj
        yield host_obj

        status_code = 0
        if status:
            try:
                status_code = int(re.search(r"\d+", status).group())
            except (AttributeError, ValueError):
                pass

        yield Service(
            host_id=host_obj.id,
            port=port,
            protocol="tcp",
            service_name="https" if scheme == "https" else "http",
            extra_info=title,
            source="eyewitness",
            raw_properties={
                "url": url,
                "status_code": status_code,
                "screenshot": screenshot,
                "category": category,
            },
        )

        if title:
            title_lower = title.lower()
            for indicator in self.INTERESTING_TITLES:
                if indicator in title_lower:
                    yield Misconfiguration(
                        title=f"Interesting Service: {title[:50]}",
                        description=f"Found {indicator}-related service at {url or host}: {title}",
                        severity="info",
                        affected_asset_id=host_obj.id,
                        source="eyewitness",
                        check_id=f"interesting_{indicator}",
                        tags=["interesting", indicator],
                    )
                    break

        if any(ind in (title or "").lower() or ind in (headers or "").lower() for ind in self.DEFAULT_CREDS_INDICATORS):
            yield Misconfiguration(
                title=f"Potential Default Credentials: {host}",
                description=f"Service may have default credentials: {url or host}",
                severity="medium",
                affected_asset_id=host_obj.id,
                source="eyewitness",
                check_id="default_creds",
                tags=["credential", "default"],
            )

        if status_code == 401 or status_code == 403:
            yield Misconfiguration(
                title=f"Protected Resource ({status_code}): {host}",
                description=f"Resource requires authentication at {url or host}",
                severity="info",
                affected_asset_id=host_obj.id,
                source="eyewitness",
                check_id=f"auth_required_{status_code}",
                tags=["auth"],
            )

    def _parse_xml_item(self, item, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a generic item element from XML."""
        for attrib in ["url", "host", "target", "source"]:
            elem = item.find(attrib)
            if elem is not None and elem.text:
                yield from self._parse_url_string(elem.text, seen_hosts)
                break

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse EyeWitness JSON output."""
        content = file_path.read_text(errors="ignore")
        seen_hosts: dict[str, Host] = {}

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        entries = data if isinstance(data, list) else [data]

        for entry in entries:
            if isinstance(entry, dict):
                yield from self._parse_json_entry(entry, seen_hosts)

    def _parse_json_entry(self, entry: dict, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a single JSON entry."""
        url = entry.get("url") or entry.get("URL") or entry.get("target") or ""
        title = entry.get("title") or entry.get("page_title") or ""
        status_code = entry.get("status_code") or entry.get("response_code") or 0
        headers = entry.get("headers") or entry.get("response_headers") or {}
        screenshot = entry.get("screenshot") or entry.get("image") or ""
        category = entry.get("category") or ""
        server = entry.get("server") or entry.get("webserver") or ""

        if not url:
            return

        url_match = self.URL_PATTERN.match(url)
        if not url_match:
            return

        scheme = url_match.group("scheme")
        host = url_match.group("host")
        port = int(url_match.group("port") or (443 if scheme == "https" else 80))

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            return

        ip = ""
        hostname = host
        if self.IPV4_PATTERN.match(host):
            ip = host
            hostname = ""

        tags = ["web", "screenshot"]
        if category:
            tags.append(category.lower())

        host_obj = Host(
            ip=ip,
            hostname=hostname if hostname else None,
            source="eyewitness",
            tags=tags,
        )
        seen_hosts[host_key] = host_obj
        yield host_obj

        yield Service(
            host_id=host_obj.id,
            port=port,
            protocol="tcp",
            service_name="https" if scheme == "https" else "http",
            product=server,
            extra_info=title,
            source="eyewitness",
            raw_properties={
                "url": url,
                "status_code": status_code,
                "screenshot": screenshot,
                "category": category,
            },
        )

        if title:
            title_lower = title.lower()
            for indicator in self.INTERESTING_TITLES:
                if indicator in title_lower:
                    yield Misconfiguration(
                        title=f"Interesting Service: {title[:50]}",
                        description=f"Found {indicator}-related service at {url}: {title}",
                        severity="info",
                        affected_asset_id=host_obj.id,
                        source="eyewitness",
                        check_id=f"interesting_{indicator}",
                        tags=["interesting", indicator],
                    )
                    break

    def _parse_url_string(self, url: str, seen_hosts: dict) -> Generator[Entity, None, None]:
        """Parse a URL string and create entities."""
        url_match = self.URL_PATTERN.match(url)
        if not url_match:
            return

        scheme = url_match.group("scheme")
        host = url_match.group("host")
        port = int(url_match.group("port") or (443 if scheme == "https" else 80))

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            return

        ip = ""
        hostname = host
        if self.IPV4_PATTERN.match(host):
            ip = host
            hostname = ""

        host_obj = Host(
            ip=ip,
            hostname=hostname if hostname else None,
            source="eyewitness",
            tags=["web", "screenshot"],
        )
        seen_hosts[host_key] = host_obj
        yield host_obj

        yield Service(
            host_id=host_obj.id,
            port=port,
            protocol="tcp",
            service_name="https" if scheme == "https" else "http",
            source="eyewitness",
        )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is an EyeWitness output file."""
        name_lower = file_path.name.lower()
        if "eyewitness" in name_lower or name_lower in ["report.xml", "ew_report.xml"]:
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"eyewitness",
                    b"EyeWitness",
                    b"<server>",
                    b"<screenshot>",
                    b"<page-title>",
                    b"<response-headers>",
                    b'"screenshot"',
                    b'"page_title"',
                    b"<category>",
                ]
                return sum(1 for ind in indicators if ind in header) >= 2
        except Exception:
            return False
