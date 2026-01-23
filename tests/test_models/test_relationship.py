"""Tests for Relationship model and RelationType enum."""

import pytest
from datetime import datetime

from ariadne.models.relationship import (
    Relationship,
    RelationType,
    ATTACK_RELATIONSHIPS,
)


class TestRelationType:
    """Test RelationType enum."""

    def test_relation_type_values(self):
        """Test RelationType has expected values."""
        assert RelationType.CAN_REACH.value == "can_reach"
        assert RelationType.HAS_ACCESS.value == "has_access"
        assert RelationType.ADMIN_TO.value == "admin_to"
        assert RelationType.CAN_RDP.value == "can_rdp"
        assert RelationType.CAN_SSH.value == "can_ssh"
        assert RelationType.CAN_PSREMOTE.value == "can_psremote"
        assert RelationType.MEMBER_OF.value == "member_of"

    def test_relation_type_ad_permissions(self):
        """Test RelationType has AD permission types."""
        assert RelationType.HAS_GENERIC_ALL.value == "has_generic_all"
        assert RelationType.HAS_GENERIC_WRITE.value == "has_generic_write"
        assert RelationType.HAS_WRITE_OWNER.value == "has_write_owner"
        assert RelationType.HAS_WRITE_DACL.value == "has_write_dacl"
        assert RelationType.CAN_ADD_MEMBER.value == "can_add_member"
        assert RelationType.CAN_FORCE_CHANGE_PASSWORD.value == "can_force_change_password"
        assert RelationType.CAN_READ_LAPS.value == "can_read_laps"
        assert RelationType.CAN_READ_GMSA.value == "can_read_gmsa"

    def test_relation_type_vulnerability_types(self):
        """Test RelationType has vulnerability relationship types."""
        assert RelationType.CAN_EXPLOIT.value == "can_exploit"
        assert RelationType.HAS_VULNERABILITY.value == "has_vulnerability"
        assert RelationType.HAS_MISCONFIGURATION.value == "has_misconfiguration"

    def test_relation_type_session_types(self):
        """Test RelationType has session types."""
        assert RelationType.HAS_SESSION.value == "has_session"
        assert RelationType.LOGGED_IN_TO.value == "logged_in_to"

    def test_relation_type_cloud_types(self):
        """Test RelationType has cloud relationship types."""
        assert RelationType.HAS_ROLE.value == "has_role"
        assert RelationType.CAN_ASSUME.value == "can_assume"
        assert RelationType.HAS_PERMISSION.value == "has_permission"
        assert RelationType.CONTAINS.value == "contains"

    def test_relation_type_is_string_enum(self):
        """Test RelationType is a string enum."""
        assert isinstance(RelationType.ADMIN_TO, str)
        assert RelationType.ADMIN_TO == "admin_to"


class TestAttackRelationships:
    """Test ATTACK_RELATIONSHIPS constant."""

    def test_attack_relationships_contains_admin_to(self):
        """Test ATTACK_RELATIONSHIPS contains AdminTo."""
        assert RelationType.ADMIN_TO in ATTACK_RELATIONSHIPS

    def test_attack_relationships_contains_can_rdp(self):
        """Test ATTACK_RELATIONSHIPS contains CanRDP."""
        assert RelationType.CAN_RDP in ATTACK_RELATIONSHIPS

    def test_attack_relationships_contains_can_ssh(self):
        """Test ATTACK_RELATIONSHIPS contains CanSSH."""
        assert RelationType.CAN_SSH in ATTACK_RELATIONSHIPS

    def test_attack_relationships_contains_generic_all(self):
        """Test ATTACK_RELATIONSHIPS contains GenericAll."""
        assert RelationType.HAS_GENERIC_ALL in ATTACK_RELATIONSHIPS

    def test_attack_relationships_contains_can_exploit(self):
        """Test ATTACK_RELATIONSHIPS contains CanExploit."""
        assert RelationType.CAN_EXPLOIT in ATTACK_RELATIONSHIPS

    def test_attack_relationships_not_contains_member_of(self):
        """Test ATTACK_RELATIONSHIPS does not contain MemberOf."""
        assert RelationType.MEMBER_OF not in ATTACK_RELATIONSHIPS

    def test_attack_relationships_not_contains_related_to(self):
        """Test ATTACK_RELATIONSHIPS does not contain RelatedTo."""
        assert RelationType.RELATED_TO not in ATTACK_RELATIONSHIPS

    def test_attack_relationships_not_contains_has_vulnerability(self):
        """Test ATTACK_RELATIONSHIPS does not contain HasVulnerability."""
        assert RelationType.HAS_VULNERABILITY not in ATTACK_RELATIONSHIPS


class TestRelationship:
    """Test Relationship model."""

    def test_relationship_id_generation(self):
        """Test Relationship ID is auto-generated."""
        rel = Relationship(
            source_id="user:CORP\\admin",
            target_id="host:192.168.1.1",
            relation_type=RelationType.ADMIN_TO,
        )
        assert "rel:" in rel.id
        assert "admin_to" in rel.id
        assert "->" in rel.id

    def test_relationship_required_fields(self):
        """Test Relationship required fields."""
        rel = Relationship(
            source_id="user:test",
            target_id="host:test",
            relation_type=RelationType.CAN_REACH,
        )
        assert rel.source_id == "user:test"
        assert rel.target_id == "host:test"
        assert rel.relation_type == RelationType.CAN_REACH

    def test_relationship_defaults(self):
        """Test Relationship default values."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.RELATED_TO,
        )
        assert rel.bidirectional is False
        assert rel.weight == 1.0
        assert rel.confidence == 1.0
        assert rel.properties == {}
        assert rel.source == "unknown"
        assert isinstance(rel.discovered_at, datetime)

    def test_relationship_with_all_fields(self):
        """Test Relationship with all fields populated."""
        rel = Relationship(
            source_id="user:CORP\\admin",
            target_id="host:192.168.1.100",
            relation_type=RelationType.ADMIN_TO,
            bidirectional=False,
            weight=1.0,
            confidence=0.95,
            properties={"method": "local_admin"},
            source="bloodhound",
        )
        assert rel.confidence == 0.95
        assert rel.properties["method"] == "local_admin"
        assert rel.source == "bloodhound"

    def test_relationship_is_attack_edge_admin_to(self):
        """Test Relationship is_attack_edge for AdminTo."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.ADMIN_TO,
        )
        assert rel.is_attack_edge is True

    def test_relationship_is_attack_edge_can_rdp(self):
        """Test Relationship is_attack_edge for CanRDP."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.CAN_RDP,
        )
        assert rel.is_attack_edge is True

    def test_relationship_is_attack_edge_generic_all(self):
        """Test Relationship is_attack_edge for GenericAll."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.HAS_GENERIC_ALL,
        )
        assert rel.is_attack_edge is True

    def test_relationship_is_not_attack_edge_member_of(self):
        """Test Relationship is_attack_edge returns False for MemberOf."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.MEMBER_OF,
        )
        assert rel.is_attack_edge is False

    def test_relationship_is_not_attack_edge_related_to(self):
        """Test Relationship is_attack_edge returns False for RelatedTo."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.RELATED_TO,
        )
        assert rel.is_attack_edge is False

    def test_relationship_display_name(self):
        """Test Relationship display_name property."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.ADMIN_TO,
        )
        assert rel.display_name == "Admin To"

    def test_relationship_display_name_generic_all(self):
        """Test Relationship display_name for GenericAll."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.HAS_GENERIC_ALL,
        )
        assert rel.display_name == "Has Generic All"

    def test_relationship_reverse(self):
        """Test Relationship reverse() method."""
        original = Relationship(
            source_id="user:admin",
            target_id="host:server",
            relation_type=RelationType.ADMIN_TO,
            weight=0.9,
            confidence=0.8,
            properties={"test": "value"},
            source="bloodhound",
        )
        reversed_rel = original.reverse()

        assert reversed_rel.source_id == original.target_id
        assert reversed_rel.target_id == original.source_id
        assert reversed_rel.relation_type == original.relation_type
        assert reversed_rel.weight == original.weight
        assert reversed_rel.confidence == original.confidence
        assert reversed_rel.properties == original.properties
        assert reversed_rel.source == original.source

    def test_relationship_reverse_preserves_bidirectional(self):
        """Test Relationship reverse() preserves bidirectional flag."""
        original = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.CAN_REACH,
            bidirectional=True,
        )
        reversed_rel = original.reverse()
        assert reversed_rel.bidirectional is True

    def test_relationship_reverse_creates_new_id(self):
        """Test Relationship reverse() creates new ID."""
        original = Relationship(
            source_id="user:admin",
            target_id="host:server",
            relation_type=RelationType.ADMIN_TO,
        )
        reversed_rel = original.reverse()

        assert reversed_rel.id != original.id

    def test_relationship_reverse_does_not_modify_original(self):
        """Test Relationship reverse() does not modify original."""
        original = Relationship(
            source_id="user:admin",
            target_id="host:server",
            relation_type=RelationType.ADMIN_TO,
        )
        original_source = original.source_id
        original_target = original.target_id

        _ = original.reverse()

        assert original.source_id == original_source
        assert original.target_id == original_target

    def test_relationship_allows_extra_fields(self):
        """Test Relationship allows extra fields."""
        rel = Relationship(
            source_id="a",
            target_id="b",
            relation_type=RelationType.RELATED_TO,
            custom_field="test",
        )
        assert rel.custom_field == "test"
