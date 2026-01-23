"""TestSSL.sh JSON output parser for TLS/SSL misconfigurations."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class TestSSLParser(BaseParser):
    """Parser for TestSSL.sh JSON output files."""

    name = "testssl"
    description = "Parse TestSSL.sh TLS/SSL scanner JSON output"
    file_patterns = ["*testssl*.json", "*ssl_scan*.json", "*tls_scan*.json"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    CRITICAL_VULNS = ["heartbleed", "ccs", "ticketbleed", "robot", "secure_renego", "secure_client_renego"]
    HIGH_VULNS = ["crime", "breach", "poodle_ssl", "sweet32", "freak", "drown", "logjam", "beast"]
    MEDIUM_VULNS = ["poodle_tls", "lucky13", "rc4"]

    WEAK_PROTOCOLS = ["ssl2", "ssl3", "tls1", "tls1_1"]
    WEAK_CIPHERS = ["rc4", "des", "3des", "null", "anon", "export"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a TestSSL JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            yield from self._parse_findings_list(data)
        elif isinstance(data, dict):
            if "scanResult" in data:
                for result in data["scanResult"]:
                    yield from self._parse_scan_result(result)
            else:
                yield from self._parse_scan_result(data)

    def _parse_findings_list(self, findings: list) -> Generator[Entity, None, None]:
        """Parse a list of TestSSL findings."""
        hosts_seen: dict[str, Host] = {}
        services_seen: dict[str, Service] = {}
        current_target = None

        for finding in findings:
            target_host = finding.get("targetHost") or finding.get("ip")
            port = finding.get("port", 443)

            if target_host:
                current_target = target_host
                host_key = target_host

                if host_key not in hosts_seen:
                    is_ip = self._is_ip(target_host)
                    host = Host(
                        ip=target_host if is_ip else "",
                        hostname=target_host if not is_ip else None,
                        source="testssl",
                    )
                    hosts_seen[host_key] = host
                    yield host

                    service = Service(
                        port=int(port),
                        protocol="tcp",
                        name="https" if int(port) == 443 else "ssl",
                        ssl=True,
                        host_id=host.id,
                        source="testssl",
                    )
                    services_seen[host_key] = service
                    yield service
                    yield Relationship(
                        source_id=service.id,
                        target_id=host.id,
                        relation_type=RelationType.RUNS_ON,
                        source="testssl",
                    )

            if current_target and current_target in services_seen:
                service = services_seen[current_target]
                yield from self._parse_finding(finding, service.id)

    def _parse_scan_result(self, result: dict) -> Generator[Entity, None, None]:
        """Parse a single scan result object."""
        target_host = result.get("targetHost") or result.get("ip") or result.get("host")
        port = result.get("port", 443)

        if not target_host:
            return

        is_ip = self._is_ip(target_host)
        host = Host(
            ip=target_host if is_ip else "",
            hostname=target_host if not is_ip else None,
            source="testssl",
        )
        yield host

        service = Service(
            port=int(port),
            protocol="tcp",
            name="https" if int(port) == 443 else "ssl",
            ssl=True,
            host_id=host.id,
            source="testssl",
        )
        yield service
        yield Relationship(
            source_id=service.id,
            target_id=host.id,
            relation_type=RelationType.RUNS_ON,
            source="testssl",
        )

        for finding in result.get("findings", []):
            yield from self._parse_finding(finding, service.id)

        for vuln_name in result.get("vulnerabilities", {}):
            vuln_data = result["vulnerabilities"][vuln_name]
            yield from self._parse_vulnerability_entry(vuln_name, vuln_data, service.id)

        for protocol in result.get("protocols", {}):
            proto_data = result["protocols"][protocol]
            if isinstance(proto_data, dict) and proto_data.get("finding") == "offered":
                if protocol.lower() in self.WEAK_PROTOCOLS:
                    yield Misconfiguration(
                        title=f"Weak protocol enabled: {protocol.upper()}",
                        description=f"The server supports {protocol.upper()}, which is considered insecure",
                        severity="high" if protocol.lower() in ["ssl2", "ssl3"] else "medium",
                        affected_asset_id=service.id,
                        source="testssl",
                        check_id=f"weak_protocol_{protocol}",
                    )

    def _parse_finding(self, finding: dict, service_id: str) -> Generator[Entity, None, None]:
        """Parse an individual finding."""
        finding_id = finding.get("id", "")
        severity = finding.get("severity", "INFO").upper()
        finding_text = finding.get("finding", "")

        if severity in ["OK", "INFO"] and "not" in finding_text.lower():
            return

        id_lower = finding_id.lower()

        if id_lower in self.CRITICAL_VULNS:
            if "not vulnerable" not in finding_text.lower() and "no" not in finding_text.lower():
                yield Vulnerability(
                    title=f"SSL/TLS Vulnerability: {finding_id}",
                    description=finding_text,
                    severity="critical",
                    affected_asset_id=service_id,
                    source="testssl",
                    template_id=finding_id,
                )
            return

        if id_lower in self.HIGH_VULNS:
            if "not vulnerable" not in finding_text.lower() and "no" not in finding_text.lower():
                yield Vulnerability(
                    title=f"SSL/TLS Vulnerability: {finding_id}",
                    description=finding_text,
                    severity="high",
                    affected_asset_id=service_id,
                    source="testssl",
                    template_id=finding_id,
                )
            return

        if id_lower in self.WEAK_PROTOCOLS:
            if "offered" in finding_text.lower() or "yes" in finding_text.lower():
                yield Misconfiguration(
                    title=f"Weak protocol enabled: {finding_id.upper()}",
                    description=finding_text,
                    severity="high" if id_lower in ["ssl2", "ssl3"] else "medium",
                    affected_asset_id=service_id,
                    source="testssl",
                    check_id=f"weak_protocol_{finding_id}",
                )
            return

        if any(weak in id_lower for weak in self.WEAK_CIPHERS):
            if "offered" in finding_text.lower():
                yield Misconfiguration(
                    title=f"Weak cipher suite: {finding_id}",
                    description=finding_text,
                    severity="medium",
                    affected_asset_id=service_id,
                    source="testssl",
                    check_id=f"weak_cipher_{finding_id}",
                )
            return

        if "cert" in id_lower:
            if any(issue in finding_text.lower() for issue in ["expired", "self-signed", "untrusted", "mismatch", "weak"]):
                yield Misconfiguration(
                    title=f"Certificate issue: {finding_id}",
                    description=finding_text,
                    severity="medium" if "expired" in finding_text.lower() else "low",
                    affected_asset_id=service_id,
                    source="testssl",
                    check_id=finding_id,
                )
            return

        if severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium"}
            yield Misconfiguration(
                title=f"TLS Configuration Issue: {finding_id}",
                description=finding_text,
                severity=severity_map.get(severity, "low"),
                affected_asset_id=service_id,
                source="testssl",
                check_id=finding_id,
            )

    def _parse_vulnerability_entry(self, vuln_name: str, vuln_data: dict, service_id: str) -> Generator[Entity, None, None]:
        """Parse a vulnerability entry from structured data."""
        if isinstance(vuln_data, dict):
            vulnerable = vuln_data.get("vulnerable", False)
            finding = vuln_data.get("finding", "")
        else:
            vulnerable = str(vuln_data).lower() in ["true", "yes", "vulnerable"]
            finding = str(vuln_data)

        if not vulnerable:
            return

        vuln_lower = vuln_name.lower()
        if vuln_lower in self.CRITICAL_VULNS:
            severity = "critical"
        elif vuln_lower in self.HIGH_VULNS:
            severity = "high"
        elif vuln_lower in self.MEDIUM_VULNS:
            severity = "medium"
        else:
            severity = "low"

        yield Vulnerability(
            title=f"SSL/TLS Vulnerability: {vuln_name}",
            description=finding or f"The server is vulnerable to {vuln_name}",
            severity=severity,
            affected_asset_id=service_id,
            source="testssl",
            template_id=vuln_name,
        )

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a TestSSL JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(3000)
                indicators = [
                    b"testssl",
                    b"scanResult",
                    b"targetHost",
                    b"heartbleed",
                    b"poodle",
                    b"beast",
                    b"freak",
                    b"logjam",
                    b'"ssl2"',
                    b'"ssl3"',
                    b'"tls1"',
                    b"cipherTests",
                    b"serverDefaults",
                ]
                return any(ind in header.lower() for ind in indicators)
        except Exception:
            return False
