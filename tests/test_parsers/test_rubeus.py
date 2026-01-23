"""Tests for Rubeus parser."""

import pytest
from pathlib import Path
from textwrap import dedent

from ariadne.parsers.rubeus import RubeusParser
from ariadne.models.asset import User
from ariadne.models.finding import Credential, Misconfiguration
from .base import BaseParserTest


class TestRubeusParser(BaseParserTest):
    """Test RubeusParser functionality."""

    parser_class = RubeusParser
    expected_name = "rubeus"
    expected_patterns = ["*rubeus*.txt", "*rubeus*.log", "*asreproast*.txt", "*kerberoast*.txt"]
    expected_entity_types = ["User", "Credential", "Misconfiguration"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_rubeus_file(self, tmp_path: Path):
        """Test detection of Rubeus output."""
        content = dedent("""\
            [*] Action: AS-REP Roasting
            [*] Target User: testuser
            $krb5asrep$23$testuser@CORP.LOCAL:1234567890abcdef
            """)
        txt_file = tmp_path / "rubeus_output.txt"
        txt_file.write_text(content)

        assert RubeusParser.can_parse(txt_file)

    def test_can_parse_kerberoast_file(self, tmp_path: Path):
        """Test detection of Kerberoast output."""
        content = "$krb5tgs$23$*svc_sql$CORP.LOCAL$sql/server*$1234567890abcdef"
        txt_file = tmp_path / "kerberoast_output.txt"
        txt_file.write_text(content)

        assert RubeusParser.can_parse(txt_file)

    def test_can_parse_asreproast_file(self, tmp_path: Path):
        """Test detection of AS-REP roast output."""
        content = "$krb5asrep$23$asrep_user@CORP.LOCAL:1234567890abcdef"
        txt_file = tmp_path / "asreproast_results.txt"
        txt_file.write_text(content)

        assert RubeusParser.can_parse(txt_file)

    def test_cannot_parse_json_file(self, tmp_path: Path):
        """Test that JSON files are rejected."""
        json_file = tmp_path / "data.json"
        json_file.write_text('{"test": true}')

        assert not RubeusParser.can_parse(json_file)

    def test_cannot_parse_random_txt(self, tmp_path: Path):
        """Test that random text files are rejected."""
        txt_file = tmp_path / "random.txt"
        txt_file.write_text("This is just a random text file.")

        assert not RubeusParser.can_parse(txt_file)

    # =========================================================================
    # AS-REP Roast Parsing Tests
    # =========================================================================

    def test_parse_asrep_hash(self, tmp_path: Path):
        """Test parsing AS-REP roastable hash."""
        content = "$krb5asrep$23$asrep_user@CORP.LOCAL:1234567890abcdef1234567890abcdef"
        txt_file = tmp_path / "asreproast.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)
        misconfigs = self.get_misconfigurations(entities)

        assert len(users) >= 1
        assert users[0].username == "asrep_user"
        assert users[0].domain == "CORP.LOCAL"
        assert "asreproastable" in users[0].tags

        assert len(creds) >= 1
        assert creds[0].credential_type == "kerberos"
        assert "asreproast" in creds[0].tags

        assert len(misconfigs) >= 1
        assert "AS-REP Roastable" in misconfigs[0].title
        assert misconfigs[0].severity == "high"

    def test_parse_multiple_asrep_hashes(self, tmp_path: Path):
        """Test parsing multiple AS-REP hashes."""
        lines = [
            "$krb5asrep$23$user1@CORP.LOCAL:abcdef123456",
            "$krb5asrep$23$user2@CORP.LOCAL:fedcba654321",
        ]
        txt_file = tmp_path / "asreproast.txt"
        txt_file.write_text("\n".join(lines))

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_deduplicates_asrep_users(self, tmp_path: Path):
        """Test that duplicate AS-REP users are not created."""
        lines = [
            "$krb5asrep$23$user1@CORP.LOCAL:abcdef123456",
            "$krb5asrep$23$user1@CORP.LOCAL:abcdef123456",
        ]
        txt_file = tmp_path / "asreproast.txt"
        txt_file.write_text("\n".join(lines))

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) == 1

    # =========================================================================
    # Kerberoast (TGS) Parsing Tests
    # =========================================================================

    def test_parse_tgs_hash(self, tmp_path: Path):
        """Test parsing Kerberoast TGS hash."""
        content = "$krb5tgs$23$*svc_sql$CORP.LOCAL$sql/server*$1234567890abcdef1234567890abcdef"
        txt_file = tmp_path / "kerberoast.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        creds = self.get_credentials(entities)
        misconfigs = self.get_misconfigurations(entities)

        assert len(users) >= 1
        assert users[0].username == "svc_sql"
        assert users[0].domain == "CORP.LOCAL"
        assert "kerberoastable" in users[0].tags

        assert len(creds) >= 1
        assert creds[0].credential_type == "kerberos"
        assert "kerberoast" in creds[0].tags

        assert len(misconfigs) >= 1
        assert "Kerberoastable" in misconfigs[0].title
        assert misconfigs[0].severity == "medium"

    def test_parse_multiple_tgs_hashes(self, tmp_path: Path):
        """Test parsing multiple TGS hashes."""
        lines = [
            "$krb5tgs$23$*svc_sql$CORP.LOCAL$sql/server*$1234567890abcdef",
            "$krb5tgs$23$*svc_web$CORP.LOCAL$http/web*$fedcba098765432",
        ]
        txt_file = tmp_path / "kerberoast.txt"
        txt_file.write_text("\n".join(lines))

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    # =========================================================================
    # Kerberoast Section Parsing Tests
    # =========================================================================

    def test_parse_kerberoast_section(self, tmp_path: Path):
        """Test parsing structured Kerberoast output."""
        content = dedent("""\
            [*] Action: Kerberoasting

            User           : svc_account
            ServicePrincipalName : http/web.corp.local

            User           : svc_backup@CORP.LOCAL
            ServicePrincipalName : backup/server.corp.local
            """)
        txt_file = tmp_path / "rubeus_kerberoast.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        users = self.get_users(entities)
        spn_users = [u for u in users if "has-spn" in (u.tags or [])]
        assert len(spn_users) >= 2

    # =========================================================================
    # Delegation Parsing Tests
    # =========================================================================

    def test_parse_unconstrained_delegation(self, tmp_path: Path):
        """Test parsing unconstrained delegation finding."""
        content = "SERVER01$ has unconstrained delegation enabled"
        txt_file = tmp_path / "rubeus_delegation.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = next((m for m in misconfigs if "Unconstrained" in m.title), None)
        assert delegation is not None
        assert delegation.severity == "critical"
        assert "delegation" in delegation.tags

    def test_parse_constrained_delegation(self, tmp_path: Path):
        """Test parsing constrained delegation finding."""
        content = "SVC_ACCOUNT is constrained delegation to CIFS/server"
        txt_file = tmp_path / "rubeus_delegation.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        delegation = next((m for m in misconfigs if "Constrained" in m.title), None)
        assert delegation is not None
        assert delegation.severity == "high"

    # =========================================================================
    # Ticket Parsing Tests
    # =========================================================================

    def test_parse_base64_ticket(self, tmp_path: Path):
        """Test parsing base64 encoded ticket."""
        # Generate a sample base64-like string
        ticket_data = "doIFojCCBZ6gAwIBBaEDAgEWooIEnzCCBJthggSXMIIEk6ADAgEFoQ8bDUNPUlAuTE9DQUw="
        content = f"Base64EncodedTicket : {ticket_data}"
        txt_file = tmp_path / "rubeus_ticket.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        ticket_creds = [c for c in creds if c.credential_type == "kerberos_ticket"]
        assert len(ticket_creds) >= 1
        assert ticket_creds[0].severity == "high"

    def test_parse_s4u_attack(self, tmp_path: Path):
        """Test parsing S4U attack output."""
        content = "S4U2self for user@CORP.LOCAL to SPN/server.corp.local"
        txt_file = tmp_path / "rubeus_s4u.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        misconfigs = self.get_misconfigurations(entities)
        s4u = next((m for m in misconfigs if "S4U" in m.title), None)
        assert s4u is not None
        assert s4u.check_id == "s4u_attack"

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_file(self, tmp_path: Path):
        """Test handling of empty file."""
        txt_file = tmp_path / "rubeus_empty.txt"
        txt_file.write_text("")

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        # Should not raise, but may have no entities
        assert isinstance(entities, list)

    def test_source_is_rubeus(self, tmp_path: Path):
        """Test that source is set to rubeus."""
        content = "$krb5asrep$23$testuser@CORP.LOCAL:1234567890abcdef"
        txt_file = tmp_path / "rubeus.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        for entity in entities:
            assert entity.source == "rubeus"

    def test_hash_type_extraction(self, tmp_path: Path):
        """Test that encryption type is extracted from hash."""
        # etype 23 is RC4
        content = "$krb5asrep$23$user@CORP.LOCAL:1234567890abcdef"
        txt_file = tmp_path / "rubeus.txt"
        txt_file.write_text(content)

        parser = RubeusParser()
        entities = list(parser.parse(txt_file))

        creds = self.get_credentials(entities)
        assert len(creds) >= 1
        assert creds[0].hash_type == "krb5asrep_etype23"
