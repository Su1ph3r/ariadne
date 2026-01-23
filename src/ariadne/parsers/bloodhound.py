"""BloodHound JSON output parser."""

import json
from pathlib import Path
from typing import Generator

from ariadne.models.asset import Host, User
from ariadne.models.relationship import Relationship, RelationType
from ariadne.parsers.base import BaseParser, Entity
from ariadne.parsers.registry import register_parser


@register_parser
class BloodHoundParser(BaseParser):
    """Parser for BloodHound JSON export files."""

    name = "bloodhound"
    description = "Parse BloodHound Active Directory enumeration data"
    file_patterns = ["*.json", "*_users.json", "*_computers.json", "*_groups.json", "*_domains.json"]
    entity_types = ["Host", "User", "Relationship"]

    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a BloodHound JSON file and yield entities."""
        with open(file_path) as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return

        meta = data.get("meta", {})
        data_type = meta.get("type", "").lower()

        if "data" not in data:
            return

        items = data["data"]

        if data_type == "computers":
            yield from self._parse_computers(items)
        elif data_type == "users":
            yield from self._parse_users(items)
        elif data_type == "groups":
            yield from self._parse_groups(items)
        elif data_type == "domains":
            yield from self._parse_domains(items)
        else:
            if items and isinstance(items, list) and len(items) > 0:
                sample = items[0]
                if "Properties" in sample:
                    props = sample.get("Properties", {})
                    if "samaccountname" in props and "enabled" in props:
                        yield from self._parse_users(items)
                    elif "operatingsystem" in props:
                        yield from self._parse_computers(items)

    def _parse_computers(self, items: list) -> Generator[Entity, None, None]:
        """Parse computer objects."""
        for item in items:
            props = item.get("Properties", {})
            aces = item.get("Aces", [])

            name = props.get("name", "")
            hostname = name.split("@")[0] if "@" in name else name

            host = Host(
                hostname=hostname.lower(),
                os=props.get("operatingsystem"),
                domain=props.get("domain"),
                is_dc=props.get("isdc", False),
                enabled=props.get("enabled", True),
                source="bloodhound",
                raw_properties=props,
            )
            yield host

            for ace in aces:
                yield from self._parse_ace(ace, host.id)

    def _parse_users(self, items: list) -> Generator[Entity, None, None]:
        """Parse user objects."""
        for item in items:
            props = item.get("Properties", {})
            aces = item.get("Aces", [])

            name = props.get("name", "")
            samaccountname = props.get("samaccountname", "")
            domain = props.get("domain", "")

            user = User(
                username=samaccountname or name,
                domain=domain,
                display_name=props.get("displayname"),
                enabled=props.get("enabled", True),
                is_admin=props.get("admincount", False),
                password_never_expires=props.get("pwdneverexpires", False),
                last_logon=props.get("lastlogon"),
                source="bloodhound",
                raw_properties=props,
            )
            yield user

            for ace in aces:
                yield from self._parse_ace(ace, user.id)

            for membership in item.get("MemberOf", []):
                yield Relationship(
                    source_id=user.id,
                    target_id=self._object_id(membership),
                    relation_type=RelationType.MEMBER_OF,
                    properties={"group": membership.get("ObjectIdentifier")},
                )

    def _parse_groups(self, items: list) -> Generator[Entity, None, None]:
        """Parse group objects for membership relationships."""
        for item in items:
            props = item.get("Properties", {})
            group_id = self._object_id(item)

            for member in item.get("Members", []):
                yield Relationship(
                    source_id=self._object_id(member),
                    target_id=group_id,
                    relation_type=RelationType.MEMBER_OF,
                    properties={
                        "group_name": props.get("name"),
                    },
                )

    def _parse_domains(self, items: list) -> Generator[Entity, None, None]:
        """Parse domain objects for trust relationships."""
        for item in items:
            props = item.get("Properties", {})
            domain_id = self._object_id(item)

            for trust in item.get("Trusts", []):
                yield Relationship(
                    source_id=domain_id,
                    target_id=trust.get("TargetDomainSid", trust.get("TargetDomainName", "")),
                    relation_type=RelationType.TRUSTS,
                    properties={
                        "trust_type": trust.get("TrustType"),
                        "trust_direction": trust.get("TrustDirection"),
                        "is_transitive": trust.get("IsTransitive"),
                    },
                )

    def _parse_ace(self, ace: dict, source_id: str) -> Generator[Relationship, None, None]:
        """Parse an ACE into a relationship."""
        right_name = ace.get("RightName", "")
        principal_sid = ace.get("PrincipalSID", "")
        principal_type = ace.get("PrincipalType", "")

        if not principal_sid:
            return

        relation_map = {
            "GenericAll": RelationType.HAS_GENERIC_ALL,
            "GenericWrite": RelationType.HAS_GENERIC_WRITE,
            "WriteOwner": RelationType.HAS_WRITE_OWNER,
            "WriteDacl": RelationType.HAS_WRITE_DACL,
            "AddMember": RelationType.CAN_ADD_MEMBER,
            "ForceChangePassword": RelationType.CAN_FORCE_CHANGE_PASSWORD,
            "ReadLAPSPassword": RelationType.CAN_READ_LAPS,
            "ReadGMSAPassword": RelationType.CAN_READ_GMSA,
            "AllExtendedRights": RelationType.HAS_ALL_EXTENDED_RIGHTS,
            "Owns": RelationType.OWNS,
        }

        relation_type = relation_map.get(right_name)
        if relation_type:
            yield Relationship(
                source_id=principal_sid,
                target_id=source_id,
                relation_type=relation_type,
                properties={
                    "principal_type": principal_type,
                    "is_inherited": ace.get("IsInherited", False),
                },
            )

    def _object_id(self, obj: dict) -> str:
        """Extract object identifier from BloodHound object."""
        return obj.get("ObjectIdentifier", obj.get("Properties", {}).get("objectid", ""))

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this file is a BloodHound export."""
        if file_path.suffix.lower() != ".json":
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if "meta" in data and "data" in data:
                        meta_type = data["meta"].get("type", "")
                        return meta_type in ["computers", "users", "groups", "domains", "gpos", "ous"]
                    if "data" in data and isinstance(data["data"], list):
                        if len(data["data"]) > 0:
                            sample = data["data"][0]
                            return "Properties" in sample or "ObjectIdentifier" in sample
        except Exception:
            return False

        return False
