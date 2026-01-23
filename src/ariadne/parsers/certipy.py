"""Certipy JSON output parser for AD Certificate Services vulnerabilities."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.finding import Vulnerability, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class CertipyParser(BaseParser):
    """Parser for Certipy JSON output files (AD CS enumeration and vulnerabilities)."""

    name = "certipy"
    description = "Parse Certipy AD Certificate Services JSON output"
    file_patterns = ["*certipy*.json", "*adcs*.json", "*bloodhound_certipy*.json"]
    entity_types = ["Host", "User", "Vulnerability", "Misconfiguration"]

    ESC_DESCRIPTIONS = {
        "ESC1": "Template allows enrollee to specify SAN, enabling impersonation of any user",
        "ESC2": "Template can be used for any purpose, allowing code signing or client auth",
        "ESC3": "Certificate request agent template enabling enrollment on behalf of others",
        "ESC4": "Vulnerable certificate template ACLs allowing modification",
        "ESC5": "Vulnerable PKI object ACLs (CA or certificate authority)",
        "ESC6": "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on CA",
        "ESC7": "Vulnerable CA ACLs allowing certificate issuance manipulation",
        "ESC8": "NTLM relay to HTTP enrollment endpoints",
        "ESC9": "No security extension in certificate template",
        "ESC10": "Weak certificate mappings enabling impersonation",
        "ESC11": "NTLM relay to RPC/DCOM enrollment interfaces",
    }

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Certipy JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if "Certificate Authorities" in data:
            yield from self._parse_cas(data["Certificate Authorities"])

        if "Certificate Templates" in data:
            yield from self._parse_templates(data["Certificate Templates"])

        if "Enrollment Services" in data:
            yield from self._parse_enrollment_services(data["Enrollment Services"])

        if "Vulnerabilities" in data or "vulnerabilities" in data:
            vulns = data.get("Vulnerabilities") or data.get("vulnerabilities", [])
            yield from self._parse_vulnerabilities(vulns)

    def _parse_cas(self, cas: dict) -> Generator[Entity, None, None]:
        """Parse Certificate Authority information."""
        for ca_name, ca_info in cas.items():
            dns_name = ca_info.get("DNS Name") or ca_info.get("dNSHostName")
            if dns_name:
                host = Host(
                    ip="",
                    hostname=dns_name,
                    source="certipy",
                    tags=["certificate-authority", "adcs"],
                    raw_properties={"ca_name": ca_name},
                )
                yield host

                if ca_info.get("User Specified SAN") == "Enabled":
                    yield Misconfiguration(
                        title=f"EDITF_ATTRIBUTESUBJECTALTNAME2 enabled on {ca_name}",
                        description=f"CA {ca_name} has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)",
                        severity="high",
                        affected_asset_id=host.id,
                        check_id="ESC6",
                        source="certipy",
                    )

                if ca_info.get("Web Enrollment") == "Enabled":
                    yield Misconfiguration(
                        title=f"Web Enrollment enabled on {ca_name}",
                        description=f"CA {ca_name} has web enrollment enabled, potentially vulnerable to ESC8 relay attacks",
                        severity="medium",
                        affected_asset_id=host.id,
                        check_id="ESC8",
                        source="certipy",
                    )

    def _parse_templates(self, templates: dict) -> Generator[Entity, None, None]:
        """Parse Certificate Template information."""
        for template_name, template_info in templates.items():
            vulnerabilities = template_info.get("Vulnerabilities") or template_info.get("vulnerabilities", [])

            for vuln_type in vulnerabilities:
                esc_code = vuln_type.upper() if vuln_type.upper().startswith("ESC") else f"ESC{vuln_type}"
                description = self.ESC_DESCRIPTIONS.get(esc_code, f"AD CS vulnerability: {esc_code}")

                yield Vulnerability(
                    title=f"{esc_code}: {template_name}",
                    description=f"{description}\nTemplate: {template_name}",
                    severity="critical" if esc_code in ["ESC1", "ESC3", "ESC6", "ESC8"] else "high",
                    source="certipy",
                    tags=[esc_code.lower(), "adcs", "certificate-template"],
                    raw_data={
                        "template_name": template_name,
                        "esc_type": esc_code,
                        "template_info": template_info,
                    },
                )

            enrollment_rights = template_info.get("Enrollment Rights") or template_info.get("enrollment_rights", [])
            for principal in enrollment_rights:
                if isinstance(principal, str) and principal.lower() in ["domain users", "authenticated users", "everyone"]:
                    yield Misconfiguration(
                        title=f"Broad enrollment rights on {template_name}",
                        description=f"Template {template_name} grants enrollment rights to {principal}",
                        severity="medium",
                        source="certipy",
                        check_id="weak_enrollment_rights",
                    )

    def _parse_enrollment_services(self, services: dict) -> Generator[Entity, None, None]:
        """Parse Enrollment Service information."""
        for service_name, service_info in services.items():
            dns_name = service_info.get("DNS Name") or service_info.get("dNSHostName")
            if dns_name:
                host = Host(
                    ip="",
                    hostname=dns_name,
                    source="certipy",
                    tags=["enrollment-service", "adcs"],
                )
                yield host

    def _parse_vulnerabilities(self, vulns: list | dict) -> Generator[Entity, None, None]:
        """Parse explicit vulnerability findings."""
        if isinstance(vulns, dict):
            vulns = [vulns]

        for vuln in vulns:
            vuln_type = vuln.get("Vulnerability") or vuln.get("type", "Unknown")
            template = vuln.get("Template") or vuln.get("template", "")
            ca = vuln.get("CA") or vuln.get("ca", "")

            esc_code = vuln_type.upper() if vuln_type.upper().startswith("ESC") else vuln_type
            description = self.ESC_DESCRIPTIONS.get(esc_code, f"AD CS vulnerability: {esc_code}")

            yield Vulnerability(
                title=f"{esc_code}: {template}" if template else esc_code,
                description=f"{description}\nCA: {ca}\nTemplate: {template}",
                severity="critical" if esc_code in ["ESC1", "ESC3", "ESC6", "ESC8"] else "high",
                source="certipy",
                tags=[esc_code.lower(), "adcs"],
                raw_data=vuln,
            )

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Certipy JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [
                    b"Certificate Authorities",
                    b"Certificate Templates",
                    b"Enrollment Services",
                    b"certipy",
                    b"ESC1", b"ESC2", b"ESC3", b"ESC4", b"ESC5",
                    b"ESC6", b"ESC7", b"ESC8", b"ESC9", b"ESC10",
                ]
                return any(ind in header for ind in indicators)
        except Exception:
            return False
