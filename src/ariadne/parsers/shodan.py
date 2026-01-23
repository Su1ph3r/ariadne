"""Shodan API JSON output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class ShodanParser(BaseParser):
    """Parser for Shodan API JSON export files."""

    name = "shodan"
    description = "Parse Shodan internet-wide scan JSON data"
    file_patterns = ["*shodan*.json", "shodan_*.json"]
    entity_types = ["Host", "Service", "Vulnerability", "Misconfiguration"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Shodan JSON file and yield entities."""
        content = file_path.read_text(errors="ignore")

        if content.strip().startswith("["):
            data = json.loads(content)
            for entry in data:
                yield from self._parse_entry(entry)
        elif content.strip().startswith("{"):
            for line in content.strip().split("\n"):
                line = line.strip()
                if line and line.startswith("{"):
                    try:
                        entry = json.loads(line)
                        yield from self._parse_entry(entry)
                    except json.JSONDecodeError:
                        continue
        else:
            for line in content.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        yield from self._parse_entry(entry)
                    except json.JSONDecodeError:
                        continue

    def _parse_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single Shodan result entry."""
        ip = entry.get("ip_str") or entry.get("ip")
        if not ip:
            return

        hostnames = entry.get("hostnames", [])
        hostname = hostnames[0] if hostnames else None
        os_info = entry.get("os")
        org = entry.get("org")
        asn = entry.get("asn")
        isp = entry.get("isp")

        host = Host(
            ip=str(ip),
            hostname=hostname,
            os=os_info,
            source="shodan",
            tags=["internet-facing"],
            raw_properties={
                "org": org,
                "asn": asn,
                "isp": isp,
                "country": entry.get("country_code"),
                "city": entry.get("city"),
                "hostnames": hostnames,
            },
        )
        yield host

        port = entry.get("port")
        transport = entry.get("transport", "tcp")

        if port:
            product = entry.get("product")
            version = entry.get("version")
            banner = entry.get("data", "")

            service_name = self._get_service_name(entry)

            service = Service(
                port=port,
                protocol=transport,
                name=service_name,
                product=product,
                version=version,
                banner=banner[:1000] if banner else None,
                host_id=host.id,
                ssl=entry.get("ssl") is not None,
                source="shodan",
            )
            yield service
            yield Relationship(
                source_id=service.id,
                target_id=host.id,
                relation_type=RelationType.RUNS_ON,
                source="shodan",
            )

            yield from self._parse_vulns(entry, service.id)
            yield from self._parse_misconfigs(entry, service.id, banner)

    def _get_service_name(self, entry: dict) -> str:
        """Determine service name from Shodan data."""
        if "http" in entry:
            return "http"
        if "ssh" in entry:
            return "ssh"
        if "ssl" in entry:
            return "https"
        if "ftp" in entry:
            return "ftp"
        if "smb" in entry:
            return "smb"

        module = entry.get("_shodan", {}).get("module", "")
        if module:
            return module.split("-")[0]

        port = entry.get("port", 0)
        port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 6379: "redis", 27017: "mongodb",
        }
        return port_services.get(port, "unknown")

    def _parse_vulns(self, entry: dict, service_id: str) -> Generator[Entity, None, None]:
        """Parse vulnerability information from Shodan."""
        vulns = entry.get("vulns", {})
        if isinstance(vulns, list):
            vulns = {v: {} for v in vulns}

        for cve_id, vuln_info in vulns.items():
            if isinstance(vuln_info, dict):
                cvss = vuln_info.get("cvss")
                verified = vuln_info.get("verified", False)
            else:
                cvss = None
                verified = False

            yield Vulnerability(
                title=cve_id,
                cve_id=cve_id,
                cvss_score=cvss,
                severity=self._cvss_to_severity(cvss),
                affected_asset_id=service_id,
                source="shodan",
                tags=["internet-facing"] + (["verified"] if verified else []),
                raw_data=vuln_info if isinstance(vuln_info, dict) else {},
            )

    def _parse_misconfigs(self, entry: dict, service_id: str, banner: str) -> Generator[Entity, None, None]:
        """Parse misconfigurations from Shodan data."""
        opts = entry.get("opts", {})

        if opts.get("heartbleed"):
            yield Misconfiguration(
                title="Heartbleed Vulnerable",
                description="Service is vulnerable to Heartbleed (CVE-2014-0160)",
                severity="critical",
                affected_asset_id=service_id,
                source="shodan",
                check_id="heartbleed",
            )

        ssl_info = entry.get("ssl", {})
        if ssl_info:
            cert = ssl_info.get("cert", {})
            if cert.get("expired"):
                yield Misconfiguration(
                    title="Expired SSL Certificate",
                    description="The SSL certificate has expired",
                    severity="medium",
                    affected_asset_id=service_id,
                    source="shodan",
                    check_id="ssl_expired",
                )

            versions = ssl_info.get("versions", [])
            for weak_version in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "-SSLv2", "-SSLv3"]:
                clean_version = weak_version.lstrip("-")
                if clean_version in versions or weak_version in versions:
                    yield Misconfiguration(
                        title=f"Weak SSL/TLS Version: {clean_version}",
                        description=f"Service supports deprecated {clean_version}",
                        severity="medium",
                        affected_asset_id=service_id,
                        source="shodan",
                        check_id=f"weak_ssl_{clean_version.lower()}",
                    )

        if banner:
            banner_lower = banner.lower()
            if "anonymous" in banner_lower and entry.get("port") == 21:
                yield Misconfiguration(
                    title="Anonymous FTP Access",
                    description="FTP server allows anonymous access",
                    severity="medium",
                    affected_asset_id=service_id,
                    source="shodan",
                    check_id="anonymous_ftp",
                )

            if "authentication disabled" in banner_lower:
                yield Misconfiguration(
                    title="Authentication Disabled",
                    description="Service has authentication disabled",
                    severity="high",
                    affected_asset_id=service_id,
                    source="shodan",
                    check_id="no_auth",
                )

    def _cvss_to_severity(self, cvss: float | None) -> str:
        """Convert CVSS score to severity string."""
        if cvss is None:
            return "medium"
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss > 0:
            return "low"
        return "info"

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Shodan JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"ip_str",
                    b"_shodan",
                    b'"port"',
                    b'"hostnames"',
                    b'"vulns"',
                    b"shodan",
                    b'"asn"',
                    b'"isp"',
                ]
                return sum(1 for ind in indicators if ind in header) >= 3
        except Exception:
            return False
