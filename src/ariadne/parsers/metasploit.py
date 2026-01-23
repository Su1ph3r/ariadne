"""Metasploit workspace export parser (XML and JSON)."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Vulnerability, Credential
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class MetasploitParser(BaseParser):
    """Parser for Metasploit workspace export files (XML/JSON)."""

    name = "metasploit"
    description = "Parse Metasploit Framework workspace exports"
    file_patterns = ["*metasploit*.xml", "*metasploit*.json", "*msf*.xml", "*msf*.json", "*.msf"]
    entity_types = ["Host", "Service", "User", "Vulnerability", "Credential"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a Metasploit export file and yield entities."""
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            yield from self._parse_json(file_path)
        elif suffix in [".xml", ".msf"]:
            yield from self._parse_xml(file_path)
        else:
            content = file_path.read_text(errors="ignore")[:100]
            if content.strip().startswith("<"):
                yield from self._parse_xml(file_path)
            else:
                yield from self._parse_json(file_path)

    def _parse_xml(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Metasploit XML export."""
        tree = ET.parse(file_path)
        root = tree.getroot()

        host_map: dict[str, Host] = {}

        for host_elem in root.findall(".//host"):
            host = self._parse_host_xml(host_elem)
            if host:
                host_map[host.ip] = host
                yield host

                for service_elem in host_elem.findall(".//service"):
                    service = self._parse_service_xml(service_elem, host.id)
                    if service:
                        yield service
                        yield Relationship(
                            source_id=service.id,
                            target_id=host.id,
                            relation_type=RelationType.RUNS_ON,
                            source="metasploit",
                        )

        for vuln_elem in root.findall(".//vuln"):
            yield from self._parse_vuln_xml(vuln_elem, host_map)

        for cred_elem in root.findall(".//cred"):
            yield from self._parse_cred_xml(cred_elem, host_map)

        for loot_elem in root.findall(".//loot"):
            yield from self._parse_loot_xml(loot_elem, host_map)

    def _parse_host_xml(self, host_elem: ET.Element) -> Host | None:
        """Parse a host element from XML."""
        address = self._get_text(host_elem, "address")
        if not address:
            return None

        return Host(
            ip=address,
            hostname=self._get_text(host_elem, "name") or self._get_text(host_elem, "hostname"),
            os=self._get_text(host_elem, "os_name") or self._get_text(host_elem, "os_flavor"),
            source="metasploit",
            raw_properties={
                "os_sp": self._get_text(host_elem, "os_sp"),
                "os_lang": self._get_text(host_elem, "os_lang"),
                "arch": self._get_text(host_elem, "arch"),
                "mac": self._get_text(host_elem, "mac"),
                "state": self._get_text(host_elem, "state"),
                "purpose": self._get_text(host_elem, "purpose"),
            },
        )

    def _parse_service_xml(self, service_elem: ET.Element, host_id: str) -> Service | None:
        """Parse a service element from XML."""
        port_str = self._get_text(service_elem, "port")
        if not port_str:
            return None

        try:
            port = int(port_str)
        except ValueError:
            return None

        return Service(
            port=port,
            protocol=self._get_text(service_elem, "proto", "tcp"),
            name=self._get_text(service_elem, "name", "unknown"),
            product=self._get_text(service_elem, "info"),
            host_id=host_id,
            source="metasploit",
            raw_properties={
                "state": self._get_text(service_elem, "state"),
            },
        )

    def _parse_vuln_xml(self, vuln_elem: ET.Element, host_map: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse a vulnerability element from XML."""
        name = self._get_text(vuln_elem, "name")
        if not name:
            return

        host_addr = self._get_text(vuln_elem, "host")
        host = host_map.get(host_addr) if host_addr else None
        affected_id = host.id if host else None

        refs = []
        for ref_elem in vuln_elem.findall(".//ref"):
            if ref_elem.text:
                refs.append(ref_elem.text)

        cve_id = None
        for ref in refs:
            if ref.upper().startswith("CVE-"):
                cve_id = ref.upper()
                break

        exploited = self._get_text(vuln_elem, "exploited_at") is not None

        yield Vulnerability(
            title=name,
            description=self._get_text(vuln_elem, "info", ""),
            cve_id=cve_id,
            affected_asset_id=affected_id,
            exploit_available=exploited,
            severity="high" if exploited else "medium",
            source="metasploit",
            references=refs,
            tags=["exploited"] if exploited else [],
            raw_data={
                "vuln_id": self._get_text(vuln_elem, "id"),
                "module": self._get_text(vuln_elem, "module"),
            },
        )

    def _parse_cred_xml(self, cred_elem: ET.Element, host_map: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse a credential element from XML."""
        username = self._get_text(cred_elem, "user") or self._get_text(cred_elem, "public")
        cred_type = self._get_text(cred_elem, "ptype") or self._get_text(cred_elem, "type", "password")
        value = self._get_text(cred_elem, "pass") or self._get_text(cred_elem, "private", "")

        if not username and not value:
            return

        host_addr = self._get_text(cred_elem, "host") or self._get_text(cred_elem, "address")
        host = host_map.get(host_addr) if host_addr else None

        if cred_type in ["smb_hash", "ntlm_hash"]:
            cred_type = "ntlm"
        elif cred_type in ["ssh_key", "ssh_pubkey"]:
            cred_type = "ssh_key"
        elif "hash" in cred_type.lower():
            cred_type = "hash"
        else:
            cred_type = "password"

        if username:
            user = User(
                username=username,
                source="metasploit",
            )
            yield user

        yield Credential(
            title=f"Credential for {username or 'unknown'}",
            credential_type=cred_type,
            username=username,
            value=value,
            severity="critical" if cred_type == "password" else "high",
            affected_asset_id=host.id if host else None,
            source="metasploit",
            raw_data={
                "origin": self._get_text(cred_elem, "origin"),
                "service": self._get_text(cred_elem, "sname"),
            },
        )

    def _parse_loot_xml(self, loot_elem: ET.Element, host_map: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse loot (captured data) from XML."""
        loot_type = self._get_text(loot_elem, "ltype") or self._get_text(loot_elem, "type")
        name = self._get_text(loot_elem, "name", "")
        data = self._get_text(loot_elem, "data", "")

        if not loot_type:
            return

        host_addr = self._get_text(loot_elem, "host")
        host = host_map.get(host_addr) if host_addr else None

        if "hash" in loot_type.lower() or "password" in loot_type.lower():
            yield Credential(
                title=f"Loot: {name or loot_type}",
                credential_type="loot",
                value=data[:500] if data else "",
                severity="high",
                affected_asset_id=host.id if host else None,
                source="metasploit",
                raw_data={"loot_type": loot_type},
            )

    def _parse_json(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse Metasploit JSON export."""
        with open(file_path) as f:
            data = json.load(f)

        host_map: dict[str, Host] = {}

        hosts = data.get("hosts", [])
        for host_data in hosts:
            host = self._parse_host_json(host_data)
            if host:
                host_map[host.ip] = host
                yield host

                for svc_data in host_data.get("services", []):
                    service = self._parse_service_json(svc_data, host.id)
                    if service:
                        yield service
                        yield Relationship(
                            source_id=service.id,
                            target_id=host.id,
                            relation_type=RelationType.RUNS_ON,
                            source="metasploit",
                        )

        for vuln_data in data.get("vulns", []):
            yield from self._parse_vuln_json(vuln_data, host_map)

        for cred_data in data.get("creds", []):
            yield from self._parse_cred_json(cred_data, host_map)

    def _parse_host_json(self, host_data: dict) -> Host | None:
        """Parse a host from JSON."""
        address = host_data.get("address") or host_data.get("ip")
        if not address:
            return None

        return Host(
            ip=address,
            hostname=host_data.get("name") or host_data.get("hostname"),
            os=host_data.get("os_name"),
            source="metasploit",
        )

    def _parse_service_json(self, svc_data: dict, host_id: str) -> Service | None:
        """Parse a service from JSON."""
        port = svc_data.get("port")
        if not port:
            return None

        return Service(
            port=int(port),
            protocol=svc_data.get("proto", "tcp"),
            name=svc_data.get("name", "unknown"),
            product=svc_data.get("info"),
            host_id=host_id,
            source="metasploit",
        )

    def _parse_vuln_json(self, vuln_data: dict, host_map: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse vulnerability from JSON."""
        name = vuln_data.get("name")
        if not name:
            return

        host_addr = vuln_data.get("host")
        host = host_map.get(host_addr) if host_addr else None

        refs = vuln_data.get("refs", [])
        cve_id = next((r for r in refs if r.upper().startswith("CVE-")), None)

        yield Vulnerability(
            title=name,
            description=vuln_data.get("info", ""),
            cve_id=cve_id,
            affected_asset_id=host.id if host else None,
            source="metasploit",
            references=refs,
        )

    def _parse_cred_json(self, cred_data: dict, host_map: dict[str, Host]) -> Generator[Entity, None, None]:
        """Parse credential from JSON."""
        username = cred_data.get("user") or cred_data.get("public")
        value = cred_data.get("pass") or cred_data.get("private", "")

        if not username and not value:
            return

        host_addr = cred_data.get("host")
        host = host_map.get(host_addr) if host_addr else None

        cred_type = cred_data.get("ptype", "password")

        yield Credential(
            title=f"Credential for {username or 'unknown'}",
            credential_type=cred_type,
            username=username,
            value=value,
            severity="critical" if cred_type == "password" else "high",
            affected_asset_id=host.id if host else None,
            source="metasploit",
        )

    def _get_text(self, elem: ET.Element, tag: str, default: str = "") -> str:
        """Get text content of a child element."""
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return default

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a Metasploit export file."""
        suffix = file_path.suffix.lower()
        if suffix not in [".xml", ".json", ".msf"]:
            return False

        # Check if filename contains "metasploit" or "msf"
        filename_lower = file_path.name.lower()
        if "metasploit" in filename_lower or suffix == ".msf":
            return True

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                header_lower = header.lower()
                # Check for metasploit-specific indicators only
                # Avoid generic XML elements like <host>, <service> that match nmap
                metasploit_indicators = [
                    b"metasploit",
                    b"<metasploitv",
                    b"<vuln>",
                    b"<cred>",
                    b'"vulns"',
                    b'"creds"',
                    b"workspace",
                ]
                return any(ind in header_lower for ind in metasploit_indicators)
        except Exception:
            return False
