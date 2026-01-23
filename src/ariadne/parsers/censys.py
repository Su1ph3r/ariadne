"""Censys search API JSON output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class CensysParser(BaseParser):
    """Parser for Censys search API JSON export files."""

    name = "censys"
    description = "Parse Censys internet scan JSON data"
    file_patterns = ["*censys*.json", "censys_*.json"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Censys JSON file and yield entities."""
        content = file_path.read_text(errors="ignore")

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            for line in content.strip().split("\n"):
                if line.strip():
                    try:
                        entry = json.loads(line)
                        yield from self._parse_entry(entry)
                    except json.JSONDecodeError:
                        continue
            return

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_entry(entry)
        elif isinstance(data, dict):
            if "results" in data:
                for entry in data["results"]:
                    yield from self._parse_entry(entry)
            elif "result" in data:
                yield from self._parse_entry(data["result"])
            else:
                yield from self._parse_entry(data)

    def _parse_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single Censys result entry."""
        ip = entry.get("ip") or entry.get("host") or entry.get("ip_address")
        if not ip:
            return

        dns = entry.get("dns", {})
        names = dns.get("names", []) or dns.get("reverse_dns", {}).get("names", [])
        hostname = names[0] if names else None

        autonomous_system = entry.get("autonomous_system", {})
        location = entry.get("location", {})

        os_info = None
        operating_system = entry.get("operating_system", {})
        if operating_system:
            os_info = operating_system.get("product") or operating_system.get("vendor")

        host = Host(
            ip=str(ip),
            hostname=hostname,
            os=os_info,
            source="censys",
            tags=["internet-facing"],
            raw_properties={
                "asn": autonomous_system.get("asn"),
                "as_name": autonomous_system.get("name"),
                "country": location.get("country"),
                "city": location.get("city"),
                "dns_names": names,
            },
        )
        yield host

        services = entry.get("services", [])
        for svc in services:
            yield from self._parse_service(svc, host.id)

        if not services:
            for proto in ["http", "https", "ssh", "ftp", "smtp", "dns"]:
                if proto in entry:
                    yield from self._parse_protocol_data(entry[proto], proto, host.id)

    def _parse_service(self, svc: dict, host_id: str) -> Generator[Entity, None, None]:
        """Parse a service entry from Censys v2 format."""
        port = svc.get("port")
        if not port:
            return

        transport = svc.get("transport_protocol", "tcp").lower()
        service_name = svc.get("service_name", "unknown").lower()
        extended_service_name = svc.get("extended_service_name", "")

        software = svc.get("software", [])
        product = None
        version = None
        if software:
            first_sw = software[0]
            product = first_sw.get("product") or first_sw.get("vendor")
            version = first_sw.get("version")

        banner = svc.get("banner", "")

        service = Service(
            port=port,
            protocol=transport,
            name=service_name,
            product=product,
            version=version,
            banner=banner[:1000] if banner else None,
            host_id=host_id,
            ssl="tls" in svc or "ssl" in svc or service_name == "https",
            source="censys",
        )
        yield service
        yield Relationship(
            source_id=service.id,
            target_id=host_id,
            relation_type=RelationType.RUNS_ON,
            source="censys",
        )

        tls = svc.get("tls", {}) or svc.get("ssl", {})
        if tls:
            yield from self._parse_tls(tls, service.id)

        http = svc.get("http", {})
        if http:
            yield from self._parse_http(http, service.id)

    def _parse_protocol_data(self, proto_data: dict, proto_name: str, host_id: str) -> Generator[Entity, None, None]:
        """Parse protocol-specific data from Censys v1 format."""
        if not proto_data:
            return

        port_map = {
            "http": 80, "https": 443, "ssh": 22, "ftp": 21,
            "smtp": 25, "dns": 53, "smb": 445,
        }
        port = port_map.get(proto_name, 0)

        if "port" in proto_data:
            port = proto_data["port"]

        service = Service(
            port=port,
            protocol="tcp",
            name=proto_name,
            host_id=host_id,
            ssl=proto_name == "https",
            source="censys",
        )
        yield service
        yield Relationship(
            source_id=service.id,
            target_id=host_id,
            relation_type=RelationType.RUNS_ON,
            source="censys",
        )

    def _parse_tls(self, tls: dict, service_id: str) -> Generator[Entity, None, None]:
        """Parse TLS/SSL information."""
        certificates = tls.get("certificates", {})
        leaf = certificates.get("leaf_data", {})

        if leaf.get("issuer", {}).get("common_name") == leaf.get("subject", {}).get("common_name"):
            yield Misconfiguration(
                title="Self-Signed Certificate",
                description="Service uses a self-signed SSL/TLS certificate",
                severity="low",
                affected_asset_id=service_id,
                source="censys",
                check_id="self_signed_cert",
            )

        validity = leaf.get("validity", {})
        if validity:
            import datetime
            end_str = validity.get("end")
            if end_str:
                try:
                    end_date = datetime.datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                    if end_date < datetime.datetime.now(datetime.timezone.utc):
                        yield Misconfiguration(
                            title="Expired SSL Certificate",
                            description=f"SSL certificate expired on {end_str}",
                            severity="medium",
                            affected_asset_id=service_id,
                            source="censys",
                            check_id="expired_cert",
                        )
                except (ValueError, TypeError):
                    pass

        versions_supported = tls.get("version_selected", "")
        weak_versions = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1"]
        for weak in weak_versions:
            if weak.lower() in versions_supported.lower():
                yield Misconfiguration(
                    title=f"Weak TLS Version: {versions_supported}",
                    description=f"Service negotiated deprecated {versions_supported}",
                    severity="medium",
                    affected_asset_id=service_id,
                    source="censys",
                    check_id="weak_tls_version",
                )
                break

    def _parse_http(self, http: dict, service_id: str) -> Generator[Entity, None, None]:
        """Parse HTTP-specific information."""
        response = http.get("response", {})
        headers = response.get("headers", {})

        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ]

        missing = [h for h in security_headers if h not in [k.lower() for k in headers.keys()]]

        if len(missing) >= 3:
            yield Misconfiguration(
                title="Missing Security Headers",
                description=f"HTTP response missing security headers: {', '.join(missing)}",
                severity="low",
                affected_asset_id=service_id,
                source="censys",
                check_id="missing_security_headers",
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Censys JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"censys",
                    b"autonomous_system",
                    b'"services"',
                    b'"dns"',
                    b"transport_protocol",
                    b"extended_service_name",
                    b'"location"',
                ]
                return sum(1 for ind in indicators if ind in header.lower()) >= 2
        except Exception:
            return False
