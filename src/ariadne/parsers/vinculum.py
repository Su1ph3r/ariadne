"""Vinculum ariadne-export JSON parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Misconfiguration, Vulnerability
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class VinculumParser(BaseParser):
    """Parser for Vinculum ariadne-export JSON files.

    Vinculum is a security finding correlation engine that deduplicates
    and enriches findings from multiple scanners. This parser ingests
    the vinculum-ariadne-export format.
    """

    name = "vinculum"
    description = "Parse Vinculum correlated security findings"
    file_patterns = ["*vinculum*.json", "vinculum_*.json"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration", "Relationship"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Vinculum ariadne-export file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if data.get("format") != "vinculum-ariadne-export":
            return

        # Yield hosts
        for host_data in data.get("hosts", []):
            host = self._parse_host(host_data)
            if host:
                yield host

        # Yield services
        for svc_data in data.get("services", []):
            service = self._parse_service(svc_data)
            if service:
                yield service

                # Service → Host relationship
                host_ip = svc_data.get("host_ip")
                if host_ip:
                    yield Relationship(
                        source_id=service.id,
                        target_id=f"host:{host_ip}",
                        relation_type=RelationType.RUNS_ON,
                        source="vinculum",
                    )

        # Yield vulnerabilities
        for vuln_data in data.get("vulnerabilities", []):
            vuln = self._parse_vulnerability(vuln_data)
            if vuln:
                yield vuln

                asset_id = vuln.affected_asset_id
                if asset_id:
                    yield Relationship(
                        source_id=asset_id,
                        target_id=vuln.id,
                        relation_type=RelationType.HAS_VULNERABILITY,
                        source="vinculum",
                    )

        # Yield misconfigurations
        for misconfig_data in data.get("misconfigurations", []):
            misconfig = self._parse_misconfiguration(misconfig_data)
            if misconfig:
                yield misconfig

                asset_id = misconfig.affected_asset_id
                if asset_id:
                    yield Relationship(
                        source_id=asset_id,
                        target_id=misconfig.id,
                        relation_type=RelationType.HAS_MISCONFIGURATION,
                        source="vinculum",
                    )

    def _parse_host(self, data: dict) -> Host | None:
        """Parse a host entry."""
        ip = data.get("ip")
        if not ip:
            return None

        return Host(
            ip=ip,
            hostname=data.get("hostname"),
            os=data.get("os"),
            source="vinculum",
        )

    def _parse_service(self, data: dict) -> Service | None:
        """Parse a service entry."""
        host_ip = data.get("host_ip")
        port = data.get("port")
        if not host_ip or not port:
            return None

        protocol = data.get("protocol", "tcp")

        return Service(
            port=port,
            protocol=protocol,
            name=data.get("name") or "unknown",
            product=data.get("product"),
            version=data.get("version"),
            host_id=f"host:{host_ip}",
            source="vinculum",
        )

    def _parse_vulnerability(self, data: dict) -> Vulnerability | None:
        """Parse a vulnerability entry."""
        title = data.get("title")
        if not title:
            return None

        host_ip = data.get("host_ip")
        port = data.get("port")
        asset_id = self._build_asset_id(host_ip, port, data.get("protocol"))

        vinculum_meta = data.get("vinculum_metadata", {})

        return Vulnerability(
            cve_id=data.get("cve_id"),
            title=title,
            description=data.get("description", ""),
            severity=data.get("severity", "info"),
            cvss_score=data.get("cvss_score"),
            affected_asset_id=asset_id,
            source="vinculum",
            raw_data=vinculum_meta,
        )

    def _parse_misconfiguration(self, data: dict) -> Misconfiguration | None:
        """Parse a misconfiguration entry."""
        title = data.get("title")
        if not title:
            return None

        host_ip = data.get("host_ip")
        port = data.get("port")
        asset_id = self._build_asset_id(host_ip, port, data.get("protocol"))

        vinculum_meta = data.get("vinculum_metadata", {})

        return Misconfiguration(
            title=title,
            description=data.get("description", ""),
            severity=data.get("severity", "info"),
            check_id=data.get("check_id"),
            remediation=data.get("remediation"),
            affected_asset_id=asset_id,
            source="vinculum",
            raw_data=vinculum_meta,
        )

    def _build_asset_id(self, host_ip: str | None, port: int | None, protocol: str | None) -> str | None:
        """Build an asset ID following Ariadne conventions."""
        if not host_ip:
            return None
        if port:
            return f"service:host:{host_ip}:{port}/{protocol or 'tcp'}"
        return f"host:{host_ip}"

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Vinculum ariadne-export."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)
                return data.get("format") == "vinculum-ariadne-export"
        except Exception:
            return False
