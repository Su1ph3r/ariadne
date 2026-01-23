"""Tests for MITRE ATT&CK technique mapping."""

import pytest

from ariadne.engine.techniques import (
    TechniqueMapper,
    TECHNIQUE_DATABASE,
    RELATIONSHIP_TECHNIQUE_MAP,
)
from ariadne.models.attack_path import AttackTechnique
from ariadne.models.relationship import RelationType


class TestTechniqueMapper:
    """Test TechniqueMapper functionality."""

    @pytest.fixture
    def mapper(self) -> TechniqueMapper:
        """Create mapper instance."""
        return TechniqueMapper()

    # =========================================================================
    # Initialization Tests
    # =========================================================================

    def test_initialization(self, mapper: TechniqueMapper):
        """Test mapper initializes with technique data."""
        assert mapper.techniques == TECHNIQUE_DATABASE
        assert mapper.relationship_map == RELATIONSHIP_TECHNIQUE_MAP

    # =========================================================================
    # Get Technique Tests
    # =========================================================================

    def test_get_technique_valid(self, mapper: TechniqueMapper):
        """Test getting valid technique by ID."""
        technique = mapper.get_technique("T1190")

        assert technique is not None
        assert isinstance(technique, AttackTechnique)
        assert technique.technique_id == "T1190"
        assert technique.name == "Exploit Public-Facing Application"
        assert technique.tactic == "initial-access"

    def test_get_technique_with_subtechnique(self, mapper: TechniqueMapper):
        """Test getting subtechnique by ID."""
        technique = mapper.get_technique("T1021.001")

        assert technique is not None
        assert technique.technique_id == "T1021.001"
        assert technique.name == "Remote Desktop Protocol"
        assert technique.tactic == "lateral-movement"

    def test_get_technique_invalid(self, mapper: TechniqueMapper):
        """Test getting invalid technique returns None."""
        technique = mapper.get_technique("T9999")
        assert technique is None

    def test_get_technique_includes_description(self, mapper: TechniqueMapper):
        """Test that technique includes description."""
        technique = mapper.get_technique("T1558.003")

        assert technique is not None
        assert technique.description is not None
        assert "Kerberos" in technique.description

    # =========================================================================
    # Map Relationship Tests
    # =========================================================================

    def test_map_relationship_rdp(self, mapper: TechniqueMapper):
        """Test mapping RDP relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.CAN_RDP)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.001" in technique_ids

    def test_map_relationship_ssh(self, mapper: TechniqueMapper):
        """Test mapping SSH relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.CAN_SSH)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.004" in technique_ids

    def test_map_relationship_psremote(self, mapper: TechniqueMapper):
        """Test mapping PSRemote relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.CAN_PSREMOTE)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.006" in technique_ids

    def test_map_relationship_admin(self, mapper: TechniqueMapper):
        """Test mapping admin relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.ADMIN_TO)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.002" in technique_ids or "T1078" in technique_ids

    def test_map_relationship_session(self, mapper: TechniqueMapper):
        """Test mapping session relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.HAS_SESSION)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1550.002" in technique_ids

    def test_map_relationship_exploit(self, mapper: TechniqueMapper):
        """Test mapping exploit relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.CAN_EXPLOIT)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids or "T1068" in technique_ids

    def test_map_relationship_generic_all(self, mapper: TechniqueMapper):
        """Test mapping GenericAll relationship to techniques."""
        techniques = mapper.map_relationship(RelationType.HAS_GENERIC_ALL)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        # DCSync or Account Manipulation
        assert any(t in technique_ids for t in ["T1098", "T1003.006"])

    def test_map_relationship_unmapped(self, mapper: TechniqueMapper):
        """Test mapping unmapped relationship returns empty list."""
        techniques = mapper.map_relationship(RelationType.RELATED_TO)
        assert techniques == []

    # =========================================================================
    # Map Service Tests
    # =========================================================================

    def test_map_service_http(self, mapper: TechniqueMapper):
        """Test mapping HTTP service to techniques."""
        techniques = mapper.map_service("http", 80)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids

    def test_map_service_https(self, mapper: TechniqueMapper):
        """Test mapping HTTPS service to techniques."""
        techniques = mapper.map_service("https", 443)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids

    def test_map_service_http_alt_ports(self, mapper: TechniqueMapper):
        """Test mapping HTTP on alternate ports."""
        techniques_8080 = mapper.map_service("http", 8080)
        techniques_8443 = mapper.map_service("https", 8443)

        assert len(techniques_8080) >= 1
        assert len(techniques_8443) >= 1

    def test_map_service_ssh(self, mapper: TechniqueMapper):
        """Test mapping SSH service to techniques."""
        techniques = mapper.map_service("ssh", 22)

        assert len(techniques) >= 2  # SSH and Valid Accounts
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.004" in technique_ids
        assert "T1078" in technique_ids

    def test_map_service_rdp(self, mapper: TechniqueMapper):
        """Test mapping RDP service to techniques."""
        techniques = mapper.map_service("rdp", 3389)

        assert len(techniques) >= 2
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.001" in technique_ids
        assert "T1078" in technique_ids

    def test_map_service_smb(self, mapper: TechniqueMapper):
        """Test mapping SMB service to techniques."""
        techniques = mapper.map_service("smb", 445)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.002" in technique_ids

    def test_map_service_smb_139(self, mapper: TechniqueMapper):
        """Test mapping SMB on port 139."""
        techniques = mapper.map_service("microsoft-ds", 139)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.002" in technique_ids

    def test_map_service_winrm(self, mapper: TechniqueMapper):
        """Test mapping WinRM service to techniques."""
        techniques = mapper.map_service("winrm", 5985)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.006" in technique_ids

    def test_map_service_winrm_ssl(self, mapper: TechniqueMapper):
        """Test mapping WinRM SSL service."""
        techniques = mapper.map_service("winrm", 5986)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1021.006" in technique_ids

    def test_map_service_kerberos(self, mapper: TechniqueMapper):
        """Test mapping Kerberos service to techniques."""
        techniques = mapper.map_service("kerberos", 88)

        assert len(techniques) >= 2
        technique_ids = [t.technique_id for t in techniques]
        assert "T1558" in technique_ids
        assert "T1558.003" in technique_ids

    def test_map_service_ldap(self, mapper: TechniqueMapper):
        """Test mapping LDAP service to techniques."""
        techniques = mapper.map_service("ldap", 389)

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1003.006" in technique_ids  # DCSync

    def test_map_service_ldaps(self, mapper: TechniqueMapper):
        """Test mapping LDAPS service to techniques."""
        techniques = mapper.map_service("ldaps", 636)

        assert len(techniques) >= 1

    def test_map_service_by_port_only(self, mapper: TechniqueMapper):
        """Test mapping service by port when name doesn't match."""
        # Unknown service name but recognized port
        techniques = mapper.map_service("unknown", 80)
        assert len(techniques) >= 1

        techniques = mapper.map_service("unknown", 3389)
        assert len(techniques) >= 1

    def test_map_service_unknown(self, mapper: TechniqueMapper):
        """Test mapping unknown service returns empty."""
        techniques = mapper.map_service("custom", 12345)
        assert techniques == []

    # =========================================================================
    # Map Vulnerability Tests
    # =========================================================================

    def test_map_vulnerability_rce(self, mapper: TechniqueMapper):
        """Test mapping RCE vulnerability."""
        techniques = mapper.map_vulnerability("Remote Code Execution in Web App")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids

    def test_map_vulnerability_command_injection(self, mapper: TechniqueMapper):
        """Test mapping command injection vulnerability."""
        techniques = mapper.map_vulnerability("Command Injection via User Input")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids

    def test_map_vulnerability_privesc(self, mapper: TechniqueMapper):
        """Test mapping privilege escalation vulnerability."""
        techniques = mapper.map_vulnerability("Local Privilege Escalation")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1068" in technique_ids

    def test_map_vulnerability_lpe(self, mapper: TechniqueMapper):
        """Test mapping LPE vulnerability."""
        techniques = mapper.map_vulnerability("LPE via Service Misconfiguration")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1068" in technique_ids

    def test_map_vulnerability_credential(self, mapper: TechniqueMapper):
        """Test mapping credential-related vulnerability."""
        techniques = mapper.map_vulnerability("Credential Disclosure in Config")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1003" in technique_ids

    def test_map_vulnerability_password(self, mapper: TechniqueMapper):
        """Test mapping password vulnerability."""
        techniques = mapper.map_vulnerability("Password Stored in Plaintext")

        assert len(techniques) >= 1

    def test_map_vulnerability_kerberos(self, mapper: TechniqueMapper):
        """Test mapping Kerberos vulnerability."""
        # Use exact keyword that the mapper looks for
        techniques = mapper.map_vulnerability("Kerberos ticket vulnerability")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1558" in technique_ids

    def test_map_vulnerability_spn(self, mapper: TechniqueMapper):
        """Test mapping SPN vulnerability."""
        techniques = mapper.map_vulnerability("SPN on Privileged User")

        assert len(techniques) >= 1

    def test_map_vulnerability_delegation(self, mapper: TechniqueMapper):
        """Test mapping delegation vulnerability."""
        techniques = mapper.map_vulnerability("Unconstrained Delegation")

        assert len(techniques) >= 1

    def test_map_vulnerability_auth_bypass(self, mapper: TechniqueMapper):
        """Test mapping auth bypass vulnerability."""
        techniques = mapper.map_vulnerability("Authentication Bypass")

        assert len(techniques) >= 1
        technique_ids = [t.technique_id for t in techniques]
        assert "T1078" in technique_ids

    def test_map_vulnerability_default_creds(self, mapper: TechniqueMapper):
        """Test mapping default credentials vulnerability."""
        techniques = mapper.map_vulnerability("Default Credentials Detected")

        assert len(techniques) >= 1

    def test_map_vulnerability_unknown(self, mapper: TechniqueMapper):
        """Test mapping unknown vulnerability type."""
        techniques = mapper.map_vulnerability("Generic Vulnerability")
        assert techniques == []

    # =========================================================================
    # List All Techniques Tests
    # =========================================================================

    def test_list_all_techniques(self, mapper: TechniqueMapper):
        """Test listing all known techniques."""
        techniques = mapper.list_all_techniques()

        assert len(techniques) == len(TECHNIQUE_DATABASE)
        for technique in techniques:
            assert isinstance(technique, AttackTechnique)
            assert technique.technique_id in TECHNIQUE_DATABASE

    def test_list_all_techniques_includes_subtechniques(self, mapper: TechniqueMapper):
        """Test that listing includes subtechniques."""
        techniques = mapper.list_all_techniques()
        technique_ids = [t.technique_id for t in techniques]

        # Check for subtechniques
        assert "T1021.001" in technique_ids
        assert "T1558.003" in technique_ids
        assert "T1003.006" in technique_ids

    # =========================================================================
    # Get Techniques by Tactic Tests
    # =========================================================================

    def test_get_techniques_by_tactic_initial_access(self, mapper: TechniqueMapper):
        """Test getting initial-access techniques."""
        techniques = mapper.get_techniques_by_tactic("initial-access")

        assert len(techniques) >= 1
        for technique in techniques:
            assert technique.tactic == "initial-access"

        technique_ids = [t.technique_id for t in techniques]
        assert "T1190" in technique_ids

    def test_get_techniques_by_tactic_lateral_movement(self, mapper: TechniqueMapper):
        """Test getting lateral-movement techniques."""
        techniques = mapper.get_techniques_by_tactic("lateral-movement")

        assert len(techniques) >= 1
        for technique in techniques:
            assert technique.tactic == "lateral-movement"

    def test_get_techniques_by_tactic_credential_access(self, mapper: TechniqueMapper):
        """Test getting credential-access techniques."""
        techniques = mapper.get_techniques_by_tactic("credential-access")

        assert len(techniques) >= 1
        for technique in techniques:
            assert technique.tactic == "credential-access"

        technique_ids = [t.technique_id for t in techniques]
        assert "T1558" in technique_ids or "T1003" in technique_ids

    def test_get_techniques_by_tactic_privilege_escalation(self, mapper: TechniqueMapper):
        """Test getting privilege-escalation techniques."""
        techniques = mapper.get_techniques_by_tactic("privilege-escalation")

        assert len(techniques) >= 1
        for technique in techniques:
            assert technique.tactic == "privilege-escalation"

    def test_get_techniques_by_tactic_persistence(self, mapper: TechniqueMapper):
        """Test getting persistence techniques."""
        techniques = mapper.get_techniques_by_tactic("persistence")

        assert len(techniques) >= 1
        for technique in techniques:
            assert technique.tactic == "persistence"

    def test_get_techniques_by_tactic_unknown(self, mapper: TechniqueMapper):
        """Test getting techniques for unknown tactic returns empty."""
        techniques = mapper.get_techniques_by_tactic("unknown-tactic")
        assert techniques == []


class TestTechniqueDatabase:
    """Test the technique database structure."""

    def test_all_techniques_have_required_fields(self):
        """Test all techniques have required fields."""
        for tid, data in TECHNIQUE_DATABASE.items():
            assert "name" in data, f"{tid} missing name"
            assert "tactic" in data, f"{tid} missing tactic"
            assert "description" in data, f"{tid} missing description"

    def test_technique_ids_format(self):
        """Test technique IDs follow MITRE format."""
        for tid in TECHNIQUE_DATABASE:
            assert tid.startswith("T"), f"Invalid technique ID: {tid}"
            # Should be Txxxx or Txxxx.xxx format
            if "." in tid:
                main, sub = tid.split(".")
                assert len(main) == 5, f"Invalid main technique ID: {tid}"
                assert len(sub) == 3, f"Invalid subtechnique ID: {tid}"


class TestRelationshipTechniqueMap:
    """Test the relationship to technique mapping."""

    def test_all_mapped_techniques_exist(self):
        """Test all mapped technique IDs exist in database."""
        for rel_type, technique_ids in RELATIONSHIP_TECHNIQUE_MAP.items():
            for tid in technique_ids:
                assert tid in TECHNIQUE_DATABASE, f"{rel_type} maps to unknown technique {tid}"

    def test_attack_relationships_have_mappings(self):
        """Test key attack relationships have technique mappings."""
        key_relationships = [
            RelationType.CAN_RDP,
            RelationType.CAN_SSH,
            RelationType.ADMIN_TO,
            RelationType.CAN_EXPLOIT,
        ]
        for rel_type in key_relationships:
            assert rel_type in RELATIONSHIP_TECHNIQUE_MAP, f"{rel_type} has no technique mapping"
