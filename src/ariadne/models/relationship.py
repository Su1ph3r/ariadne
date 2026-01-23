"""Relationship model for graph edges between entities."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class RelationType(str, Enum):
    """Types of relationships between entities."""

    CAN_REACH = "can_reach"
    HAS_ACCESS = "has_access"
    RUNS_ON = "runs_on"
    MEMBER_OF = "member_of"
    ADMIN_TO = "admin_to"
    CAN_RDP = "can_rdp"
    CAN_PSREMOTE = "can_psremote"
    CAN_SSH = "can_ssh"

    CAN_EXPLOIT = "can_exploit"
    HAS_VULNERABILITY = "has_vulnerability"
    HAS_MISCONFIGURATION = "has_misconfiguration"

    HAS_SESSION = "has_session"
    LOGGED_IN_TO = "logged_in_to"

    HAS_GENERIC_ALL = "has_generic_all"
    HAS_GENERIC_WRITE = "has_generic_write"
    HAS_WRITE_OWNER = "has_write_owner"
    HAS_WRITE_DACL = "has_write_dacl"
    HAS_ALL_EXTENDED_RIGHTS = "has_all_extended_rights"
    CAN_ADD_MEMBER = "can_add_member"
    CAN_FORCE_CHANGE_PASSWORD = "can_force_change_password"
    CAN_READ_LAPS = "can_read_laps"
    CAN_READ_GMSA = "can_read_gmsa"
    OWNS = "owns"
    TRUSTS = "trusts"

    HAS_ROLE = "has_role"
    CAN_ASSUME = "can_assume"
    HAS_PERMISSION = "has_permission"
    CONTAINS = "contains"

    RESOLVES_TO = "resolves_to"
    RELATED_TO = "related_to"


ATTACK_RELATIONSHIPS = {
    RelationType.CAN_REACH,
    RelationType.HAS_ACCESS,
    RelationType.ADMIN_TO,
    RelationType.CAN_RDP,
    RelationType.CAN_PSREMOTE,
    RelationType.CAN_SSH,
    RelationType.CAN_EXPLOIT,
    RelationType.HAS_SESSION,
    RelationType.HAS_GENERIC_ALL,
    RelationType.HAS_GENERIC_WRITE,
    RelationType.HAS_WRITE_OWNER,
    RelationType.HAS_WRITE_DACL,
    RelationType.CAN_ADD_MEMBER,
    RelationType.CAN_FORCE_CHANGE_PASSWORD,
    RelationType.CAN_READ_LAPS,
    RelationType.CAN_READ_GMSA,
    RelationType.OWNS,
    RelationType.CAN_ASSUME,
}


class Relationship(BaseModel):
    """A directed relationship between two entities."""

    id: str = ""
    source_id: str
    target_id: str
    relation_type: RelationType
    bidirectional: bool = False
    weight: float = 1.0
    confidence: float = 1.0
    properties: dict[str, Any] = Field(default_factory=dict)
    source: str = "unknown"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"extra": "allow"}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = f"rel:{self.source_id}-{self.relation_type.value}->{self.target_id}"

    @property
    def is_attack_edge(self) -> bool:
        """Check if this relationship represents a potential attack path."""
        return self.relation_type in ATTACK_RELATIONSHIPS

    @property
    def display_name(self) -> str:
        """Human-readable relationship name."""
        return self.relation_type.value.replace("_", " ").title()

    def reverse(self) -> "Relationship":
        """Create a reversed version of this relationship."""
        return Relationship(
            source_id=self.target_id,
            target_id=self.source_id,
            relation_type=self.relation_type,
            bidirectional=self.bidirectional,
            weight=self.weight,
            confidence=self.confidence,
            properties=self.properties.copy(),
            source=self.source,
        )
