"""CrackMapExec JSON output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, Service, User
from ariadne.models.finding import Credential, Misconfiguration
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class CrackMapExecParser(BaseParser):
    """Parser for CrackMapExec JSON output files."""

    name = "crackmapexec"
    description = "Parse CrackMapExec/NetExec JSON output (SMB, WinRM, LDAP)"
    file_patterns = ["*cme*.json", "*nxc*.json", "*crackmapexec*.json", "*netexec*.json"]
    entity_types = ["Host", "Service", "User", "Credential", "Misconfiguration"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a CrackMapExec JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if isinstance(data, list):
            for entry in data:
                yield from self._parse_entry(entry)
        elif isinstance(data, dict):
            yield from self._parse_entry(data)

    def _parse_entry(self, entry: dict) -> Generator[Entity, None, None]:
        """Parse a single CME output entry."""
        host_ip = entry.get("host") or entry.get("ip") or entry.get("target")
        if not host_ip:
            return

        hostname = entry.get("hostname") or entry.get("name")
        domain = entry.get("domain")
        os_info = entry.get("os") or entry.get("os_info")

        host = Host(
            ip=host_ip,
            hostname=hostname,
            domain=domain,
            os=os_info,
            source="crackmapexec",
        )
        yield host

        protocol = entry.get("protocol", "smb").lower()
        port = self._get_port_for_protocol(protocol)

        service = Service(
            port=port,
            protocol="tcp",
            name=protocol,
            host_id=host.id,
            source="crackmapexec",
        )
        yield service
        yield Relationship(
            source_id=service.id,
            target_id=host.id,
            relation_type=RelationType.RUNS_ON,
            source="crackmapexec",
        )

        if entry.get("signing") is False or entry.get("smb_signing") is False:
            yield Misconfiguration(
                title="SMB Signing Not Required",
                description=f"SMB signing is not required on {host_ip}, enabling relay attacks.",
                severity="medium",
                affected_asset_id=service.id,
                source="crackmapexec",
            )

        if entry.get("smbv1"):
            yield Misconfiguration(
                title="SMBv1 Enabled",
                description=f"SMBv1 is enabled on {host_ip}, which is vulnerable to attacks like EternalBlue.",
                severity="high",
                affected_asset_id=service.id,
                source="crackmapexec",
            )

        for share_info in entry.get("shares", []):
            share_name = share_info.get("name", "")
            if share_info.get("read") or share_info.get("write"):
                yield Misconfiguration(
                    title=f"Accessible Share: {share_name}",
                    description=f"Share {share_name} on {host_ip} is accessible (read: {share_info.get('read')}, write: {share_info.get('write')})",
                    severity="low" if share_name in ["IPC$", "print$"] else "medium",
                    affected_asset_id=host.id,
                    source="crackmapexec",
                )

        for session in entry.get("sessions", []):
            username = session.get("user") or session.get("username")
            session_domain = session.get("domain", domain)
            if username:
                user = User(
                    username=username,
                    domain=session_domain,
                    source="crackmapexec",
                )
                yield user
                yield Relationship(
                    source_id=user.id,
                    target_id=host.id,
                    relation_type=RelationType.HAS_SESSION,
                    source="crackmapexec",
                )

        if entry.get("admin") or entry.get("pwned"):
            username = entry.get("username") or entry.get("user")
            if username:
                user = User(
                    username=username,
                    domain=domain,
                    is_admin=True,
                    source="crackmapexec",
                )
                yield user
                yield Relationship(
                    source_id=user.id,
                    target_id=host.id,
                    relation_type=RelationType.ADMIN_TO,
                    source="crackmapexec",
                )

        for cred in entry.get("credentials", []):
            yield from self._parse_credential(cred, domain, host.id)

        if entry.get("hash") or entry.get("password"):
            yield from self._parse_credential(entry, domain, host.id)

    def _parse_credential(self, cred: dict, default_domain: str | None, host_id: str) -> Generator[Entity, None, None]:
        """Parse credential information."""
        username = cred.get("username") or cred.get("user")
        if not username:
            return

        domain = cred.get("domain", default_domain)
        password = cred.get("password")
        ntlm_hash = cred.get("hash") or cred.get("ntlm")

        if password and password not in ["", "*", "(null)"]:
            yield Credential(
                title=f"Password for {domain}\\{username}" if domain else f"Password for {username}",
                credential_type="password",
                username=username,
                domain=domain,
                value=password,
                severity="critical",
                affected_asset_id=host_id,
                source="crackmapexec",
            )
        elif ntlm_hash:
            yield Credential(
                title=f"NTLM hash for {domain}\\{username}" if domain else f"NTLM hash for {username}",
                credential_type="ntlm",
                username=username,
                domain=domain,
                value=ntlm_hash,
                ntlm_hash=ntlm_hash,
                severity="high",
                affected_asset_id=host_id,
                source="crackmapexec",
            )

    def _get_port_for_protocol(self, protocol: str) -> int:
        """Get default port for CME protocol."""
        ports = {
            "smb": 445,
            "winrm": 5985,
            "ldap": 389,
            "ldaps": 636,
            "mssql": 1433,
            "ssh": 22,
            "rdp": 3389,
            "wmi": 135,
            "ftp": 21,
        }
        return ports.get(protocol, 445)

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a CrackMapExec JSON file."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path, "rb") as f:
                header = f.read(2000)
                indicators = [b"crackmapexec", b"netexec", b"cme", b"nxc", b'"protocol"', b'"signing"', b'"pwned"']
                return any(ind in header.lower() for ind in indicators)
        except Exception:
            return False
