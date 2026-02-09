"""Vinculum ariadne-export JSON parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service, CloudResource, Container, MobileApp, ApiEndpoint
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
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration", "Relationship",
                     "CloudResource", "Container", "MobileApp", "ApiEndpoint"]

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

        # Yield cloud resources (v1.1)
        for cr_data in data.get("cloud_resources", []):
            cloud_resource = self._parse_cloud_resource(cr_data)
            if cloud_resource:
                yield cloud_resource

        # Yield containers (v1.1)
        for container_data in data.get("containers", []):
            container = self._parse_container(container_data)
            if container:
                yield container

        # Yield mobile apps (v1.1)
        for app_data in data.get("mobile_apps", []):
            mobile_app = self._parse_mobile_app(app_data)
            if mobile_app:
                yield mobile_app

        # Yield API endpoints (v1.1)
        for ep_data in data.get("api_endpoints", []):
            api_endpoint = self._parse_api_endpoint(ep_data)
            if api_endpoint:
                yield api_endpoint

        # Yield relationships
        for rel_data in data.get("relationships", []):
            rel = self._parse_relationship(rel_data)
            if rel:
                yield rel

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

    def _parse_cloud_resource(self, data: dict) -> CloudResource | None:
        """Parse a cloud resource entry."""
        resource_id = data.get("resource_id") or data.get("id")
        if not resource_id:
            return None

        return CloudResource(
            resource_id=resource_id,
            resource_type=data.get("type", "unknown"),
            name=data.get("name"),
            provider=data.get("provider", "unknown"),
            region=data.get("region"),
            account_id=data.get("account_id"),
            source="vinculum",
        )

    def _parse_container(self, data: dict) -> Container | None:
        """Parse a container entry."""
        container_id = data.get("id") or data.get("container_id")
        if not container_id:
            return None

        return Container(
            container_id=container_id,
            image=data.get("image"),
            registry=data.get("registry"),
            runtime=data.get("runtime"),
            namespace=data.get("namespace"),
            privileged=data.get("privileged", False),
            escape_chain_id=data.get("escape_chain_id"),
            source="vinculum",
        )

    def _parse_mobile_app(self, data: dict) -> MobileApp | None:
        """Parse a mobile app entry."""
        app_id = data.get("app_id") or data.get("id")
        if not app_id:
            return None

        return MobileApp(
            app_id=app_id,
            name=data.get("name"),
            platform=data.get("platform"),
            version=data.get("version"),
            source="vinculum",
        )

    def _parse_api_endpoint(self, data: dict) -> ApiEndpoint | None:
        """Parse an API endpoint entry."""
        path = data.get("path")
        if not path:
            return None

        return ApiEndpoint(
            method=data.get("method", "GET"),
            path=path,
            base_url=data.get("base_url"),
            parameters=data.get("parameters", []),
            source="vinculum",
        )

    def _parse_relationship(self, data: dict) -> Relationship | None:
        """Parse a relationship entry."""
        source_key = data.get("source_key")
        target_key = data.get("target_key")
        rel_type = data.get("relation_type")

        if not source_key or not target_key or not rel_type:
            return None

        try:
            relation_type = RelationType(rel_type)
        except ValueError:
            return None

        return Relationship(
            source_id=source_key,
            target_id=target_key,
            relation_type=relation_type,
            source="vinculum",
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
