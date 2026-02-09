"""Tests for the PlaybookGenerator engine."""

import json
from unittest.mock import MagicMock

import pytest

from ariadne.config import AriadneConfig
from ariadne.engine.playbook import PlaybookGenerator
from ariadne.engine.playbook_templates import (
    PLAYBOOK_TEMPLATES,
    SafeFormatDict,
    lookup_template,
)
from ariadne.graph.store import GraphStore
from ariadne.models.asset import Host, User
from ariadne.models.attack_path import AttackPath, AttackStep, AttackTechnique
from ariadne.models.finding import Credential
from ariadne.models.playbook import Playbook, PlaybookCommand, PlaybookStep
from ariadne.models.relationship import (
    ATTACK_RELATIONSHIPS,
    Relationship,
    RelationType,
)


# ============================================================================
# SafeFormatDict
# ============================================================================


class TestSafeFormatDict:
    def test_present_keys_filled(self):
        fmt = SafeFormatDict({"name": "alice"})
        assert "hello alice".format_map(fmt) == "hello alice"

    def test_missing_keys_left_as_placeholder(self):
        fmt = SafeFormatDict({"name": "alice"})
        assert "{missing}".format_map(fmt) == "{missing}"

    def test_mixed_keys(self):
        fmt = SafeFormatDict({"user": "bob"})
        result = "ssh {user}@{target_ip}".format_map(fmt)
        assert result == "ssh bob@{target_ip}"


# ============================================================================
# Template Lookup
# ============================================================================


class TestTemplateLookup:
    def test_exact_match_with_technique(self):
        template = lookup_template(RelationType.HAS_GENERIC_ALL, "T1558.003")
        assert template is not None
        assert any("kerberoast" in str(c["command"]).lower() for c in template.commands)

    def test_fallback_to_generic(self):
        template = lookup_template(RelationType.HAS_GENERIC_ALL, "T9999.999")
        assert template is not None
        # Should fall back to (HAS_GENERIC_ALL, None)
        assert any("secretsdump" in str(c["command"]).lower() for c in template.commands)

    def test_generic_lookup(self):
        template = lookup_template(RelationType.CAN_SSH)
        assert template is not None
        assert any("ssh" in str(c["command"]).lower() for c in template.commands)

    def test_unknown_returns_none(self):
        # RESOLVES_TO has no template
        template = lookup_template(RelationType.RESOLVES_TO)
        assert template is None

    def test_all_attack_relationships_covered(self):
        """Verify that all ATTACK_RELATIONSHIPS have at least a generic template."""
        missing = []
        for rel_type in ATTACK_RELATIONSHIPS:
            if lookup_template(rel_type) is None:
                missing.append(rel_type)
        assert not missing, f"Missing templates for: {missing}"

    @pytest.mark.parametrize(
        "rel_type",
        [
            RelationType.ADMIN_TO,
            RelationType.CAN_RDP,
            RelationType.CAN_PSREMOTE,
            RelationType.CAN_SSH,
            RelationType.HAS_GENERIC_ALL,
            RelationType.HAS_GENERIC_WRITE,
            RelationType.HAS_WRITE_DACL,
            RelationType.HAS_WRITE_OWNER,
            RelationType.CAN_FORCE_CHANGE_PASSWORD,
            RelationType.CAN_READ_LAPS,
            RelationType.CAN_READ_GMSA,
            RelationType.HAS_SESSION,
            RelationType.CAN_EXPLOIT,
            RelationType.CAN_ASSUME,
            RelationType.HAS_PERMISSION,
        ],
    )
    def test_known_types_have_templates(self, rel_type):
        assert lookup_template(rel_type) is not None


# ============================================================================
# PlaybookGenerator
# ============================================================================


@pytest.fixture
def store_with_entities():
    """Create a GraphStore populated with test entities."""
    store = GraphStore()
    entities = [
        Host(
            ip="192.168.1.100",
            hostname="dc01.corp.local",
            os="Windows Server 2019",
            domain="CORP",
            is_dc=True,
            ports=[88, 389, 445],
            source="nmap",
        ),
        Host(
            ip="192.168.1.50",
            hostname="ws01.corp.local",
            os="Windows 10",
            domain="CORP",
            ports=[445, 3389],
            source="nmap",
        ),
        Host(
            ip="192.168.1.10",
            hostname="web01.corp.local",
            os="Ubuntu 22.04",
            ports=[22, 80, 443],
            source="nmap",
        ),
        User(
            username="jsmith",
            domain="CORP",
            display_name="John Smith",
            enabled=True,
            is_admin=False,
            source="bloodhound",
        ),
        User(
            username="svc_sql",
            domain="CORP",
            display_name="SQL Service Account",
            enabled=True,
            is_admin=False,
            source="bloodhound",
        ),
        Credential(
            title="NTLM Hash for jsmith",
            credential_type="ntlm",
            username="jsmith",
            domain="CORP",
            value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            severity="high",
            source="impacket",
        ),
        Relationship(
            source_id="user:CORP\\jsmith",
            target_id="user:CORP\\svc_sql",
            relation_type=RelationType.HAS_GENERIC_ALL,
            source="bloodhound",
        ),
        Relationship(
            source_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
            relation_type=RelationType.CAN_RDP,
            source="bloodhound",
        ),
        Relationship(
            source_id="user:CORP\\svc_sql",
            target_id="host:192.168.1.100",
            relation_type=RelationType.ADMIN_TO,
            source="bloodhound",
        ),
    ]
    store.build_from_entities(entities)
    return store


@pytest.fixture
def generator(store_with_entities):
    """Create a PlaybookGenerator with populated store."""
    config = AriadneConfig()
    config.playbook.enabled = True
    return PlaybookGenerator(config, store_with_entities)


@pytest.fixture
def generator_with_llm(store_with_entities):
    """Create a PlaybookGenerator with mock LLM."""
    config = AriadneConfig()
    config.playbook.enabled = True
    config.playbook.llm_enhance = True

    mock_llm = MagicMock()
    mock_llm.complete_json.return_value = {
        "commands": [
            {
                "tool": "custom-tool",
                "command": "custom-command --target {target}",
                "description": "LLM-generated command",
                "requires_root": False,
                "requires_implant": False,
            }
        ],
        "fallback_commands": [],
        "prerequisites": ["LLM prereq"],
        "opsec_notes": ["LLM OPSEC note"],
        "expected_output": "LLM expected output",
        "detection_signatures": ["LLM detection sig"],
    }

    return PlaybookGenerator(config, store_with_entities, llm=mock_llm)


class TestRelationTypeResolution:
    def test_resolve_can_rdp(self, generator):
        result = generator._resolve_relation_type("Can Rdp")
        assert result == RelationType.CAN_RDP

    def test_resolve_has_generic_all(self, generator):
        result = generator._resolve_relation_type("Has Generic All")
        assert result == RelationType.HAS_GENERIC_ALL

    def test_resolve_admin_to(self, generator):
        result = generator._resolve_relation_type("Admin To")
        assert result == RelationType.ADMIN_TO

    def test_resolve_can_ssh(self, generator):
        result = generator._resolve_relation_type("Can Ssh")
        assert result == RelationType.CAN_SSH

    def test_resolve_unknown_returns_none(self, generator):
        result = generator._resolve_relation_type("Some Random Action")
        assert result is None


class TestEntityContextResolution:
    def test_host_target_context(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="host:192.168.1.100",
            action="Admin To",
            description="Admin to DC",
        )
        ctx = generator._resolve_entity_context(step)
        assert ctx["target_ip"] == "192.168.1.100"
        assert ctx["target_hostname"] == "dc01.corp.local"
        assert ctx["username"] == "jsmith"

    def test_user_target_context(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="user:CORP\\svc_sql",
            action="Has Generic All",
            description="GenericAll on svc_sql",
        )
        ctx = generator._resolve_entity_context(step)
        assert ctx["target_username"] == "svc_sql"
        assert ctx["username"] == "jsmith"
        assert ctx["domain"] == "CORP"

    def test_credential_context(self, generator, store_with_entities):
        # Get the credential ID
        cred_id = None
        for fid, finding in store_with_entities.builder._findings.items():
            if isinstance(finding, Credential) and finding.username == "jsmith":
                cred_id = fid
                break

        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="host:192.168.1.100",
            action="Admin To",
            description="Admin to DC",
            finding_ids=[cred_id] if cred_id else [],
        )
        ctx = generator._resolve_entity_context(step)
        if cred_id:
            assert ctx.get("credential_value")
            assert ctx.get("hash")

    def test_missing_entity_graceful(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:NONEXISTENT",
            target_asset_id="host:NONEXISTENT",
            action="Can Ssh",
            description="SSH to unknown",
        )
        ctx = generator._resolve_entity_context(step)
        # Should not raise, context may be mostly empty
        assert isinstance(ctx, dict)


class TestStepGeneration:
    def test_known_type_generates_template_step(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="host:192.168.1.50",
            action="Can Rdp",
            description="RDP to workstation",
        )
        pb_step = generator._generate_step(step)
        assert pb_step.source == "template"
        assert len(pb_step.commands) > 0
        assert any("xfreerdp" in cmd.tool.lower() for cmd in pb_step.commands)

    def test_placeholder_filling(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="host:192.168.1.100",
            action="Admin To",
            description="Admin to DC",
        )
        pb_step = generator._generate_step(step)
        # Check that target_ip was filled in the command
        assert any("192.168.1.100" in cmd.command for cmd in pb_step.commands)

    def test_unknown_type_generates_manual_step(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="host:a",
            target_asset_id="host:b",
            action="Unknown Action Type",
            description="Something unknown",
        )
        pb_step = generator._generate_step(step)
        assert pb_step.source == "manual"
        assert len(pb_step.commands) == 1
        assert pb_step.commands[0].tool == "manual"

    def test_llm_fallback_for_unknown_type(self, generator_with_llm):
        step = AttackStep(
            order=0,
            source_asset_id="host:a",
            target_asset_id="host:b",
            action="Unknown Action Type",
            description="Something unknown",
        )
        pb_step = generator_with_llm._generate_step(step)
        assert pb_step.source == "llm"
        assert len(pb_step.commands) > 0

    def test_technique_specific_template(self, generator):
        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="user:CORP\\svc_sql",
            action="Has Generic All",
            description="GenericAll with Kerberoast",
            technique=AttackTechnique(
                technique_id="T1558.003",
                name="Kerberoasting",
                tactic="Credential Access",
            ),
        )
        pb_step = generator._generate_step(step)
        assert pb_step.source == "template"
        # Should use the Kerberoasting-specific template
        assert any(
            "kerberoast" in cmd.command.lower() or "getuserspns" in cmd.command.lower()
            for cmd in pb_step.commands
        )


class TestPlaybookGeneration:
    def test_single_step_playbook(self, generator):
        path = AttackPath(
            name="Test Path",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="host:192.168.1.50",
                    action="Can Rdp",
                    description="RDP to workstation",
                )
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
        )
        playbooks = generator.generate([path])
        assert len(playbooks) == 1
        assert playbooks[0].attack_path_id == path.id
        assert len(playbooks[0].steps) == 1
        assert playbooks[0].complexity == "low"

    def test_multi_step_playbook(self, generator):
        path = AttackPath(
            name="Multi-step",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="user:CORP\\svc_sql",
                    action="Has Generic All",
                    description="GenericAll on svc_sql",
                ),
                AttackStep(
                    order=1,
                    source_asset_id="user:CORP\\svc_sql",
                    target_asset_id="host:192.168.1.100",
                    action="Admin To",
                    description="Admin to DC",
                ),
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.100",
        )
        playbooks = generator.generate([path])
        assert len(playbooks) == 1
        pb = playbooks[0]
        assert len(pb.steps) == 2
        assert pb.complexity == "low"
        assert len(pb.global_prerequisites) > 0

    def test_multiple_paths(self, generator):
        paths = [
            AttackPath(
                name=f"Path {i}",
                steps=[
                    AttackStep(
                        order=0,
                        source_asset_id="user:CORP\\jsmith",
                        target_asset_id="host:192.168.1.50",
                        action="Can Rdp",
                        description="RDP",
                    )
                ],
                entry_point_id="user:CORP\\jsmith",
                target_id="host:192.168.1.50",
            )
            for i in range(3)
        ]
        playbooks = generator.generate(paths)
        assert len(playbooks) == 3

    def test_estimated_time_format(self, generator):
        path = AttackPath(
            name="Test",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="a",
                    target_asset_id="b",
                    action="Can Rdp",
                    description="RDP",
                )
            ],
            entry_point_id="a",
            target_id="b",
        )
        playbooks = generator.generate([path])
        assert "minutes" in playbooks[0].estimated_time

    def test_detection_signatures_included(self, generator):
        path = AttackPath(
            name="Test",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="host:192.168.1.50",
                    action="Can Rdp",
                    description="RDP",
                )
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
        )
        playbooks = generator.generate([path])
        assert len(playbooks[0].steps[0].detection_signatures) > 0

    def test_detection_signatures_excluded_when_disabled(self, store_with_entities):
        config = AriadneConfig()
        config.playbook.enabled = True
        config.playbook.include_detection_sigs = False
        gen = PlaybookGenerator(config, store_with_entities)

        path = AttackPath(
            name="Test",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="host:192.168.1.50",
                    action="Can Rdp",
                    description="RDP",
                )
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
        )
        playbooks = gen.generate([path])
        assert len(playbooks[0].steps[0].detection_signatures) == 0

    def test_playbook_without_llm(self, generator):
        """Playbook generates successfully without LLM client."""
        path = AttackPath(
            name="No LLM",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="host:192.168.1.50",
                    action="Can Rdp",
                    description="RDP",
                )
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
        )
        playbooks = generator.generate([path])
        assert len(playbooks) == 1
        assert not playbooks[0].llm_enhanced

    def test_playbook_with_llm_enhancement(self, store_with_entities):
        """Playbook enhancement via LLM sets llm_enhanced flag."""
        config = AriadneConfig()
        config.playbook.enabled = True
        config.playbook.llm_enhance = True

        mock_llm = MagicMock()
        mock_llm.complete_json.return_value = {
            "global_opsec_notes": ["LLM global note"],
            "steps": [
                {
                    "additional_opsec_notes": ["LLM step note"],
                    "additional_detection_signatures": ["LLM sig"],
                }
            ],
        }

        gen = PlaybookGenerator(config, store_with_entities, llm=mock_llm)

        path = AttackPath(
            name="LLM Enhanced",
            steps=[
                AttackStep(
                    order=0,
                    source_asset_id="user:CORP\\jsmith",
                    target_asset_id="host:192.168.1.50",
                    action="Can Rdp",
                    description="RDP",
                )
            ],
            entry_point_id="user:CORP\\jsmith",
            target_id="host:192.168.1.50",
        )
        playbooks = gen.generate([path])
        assert playbooks[0].llm_enhanced
        assert "LLM global note" in playbooks[0].global_opsec_notes
        assert "LLM step note" in playbooks[0].steps[0].opsec_notes


class TestMaxFallbacks:
    def test_respects_max_fallbacks_config(self, store_with_entities):
        config = AriadneConfig()
        config.playbook.enabled = True
        config.playbook.max_fallbacks = 1
        gen = PlaybookGenerator(config, store_with_entities)

        step = AttackStep(
            order=0,
            source_asset_id="user:CORP\\jsmith",
            target_asset_id="host:192.168.1.100",
            action="Admin To",
            description="Admin to DC",
        )
        pb_step = gen._generate_step(step)
        # ADMIN_TO template has 2 fallbacks, but max_fallbacks=1
        assert len(pb_step.fallback_commands) <= 1
