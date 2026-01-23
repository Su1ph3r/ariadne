"""Tests for PlumHound parser."""

import json
import pytest
from pathlib import Path

from ariadne.parsers.plumhound import PlumHoundParser
from ariadne.models.asset import Host, User
from ariadne.models.finding import Misconfiguration, Vulnerability
from ariadne.models.relationship import Relationship
from .base import BaseParserTest


class TestPlumHoundParser(BaseParserTest):
    """Test PlumHoundParser functionality."""

    parser_class = PlumHoundParser
    expected_name = "plumhound"
    expected_patterns = ["*plumhound*.csv", "*plumhound*.json", "*PlumHound*.csv", "*PlumHound*.json"]
    expected_entity_types = ["Host", "User", "Misconfiguration", "Vulnerability"]

    # =========================================================================
    # File Detection Tests
    # =========================================================================

    def test_can_parse_plumhound_by_filename(self, tmp_path: Path):
        """Test detection by filename."""
        data = {"query": "Domain Admins", "results": [{"name": "admin@CORP.LOCAL", "type": "User"}]}
        json_file = tmp_path / "plumhound_output.json"
        json_file.write_text(json.dumps(data))

        assert PlumHoundParser.can_parse(json_file)

    def test_can_parse_by_indicators(self, tmp_path: Path):
        """Test detection by content indicators."""
        content = '"UserName","Domain"\n"admin","CORP.LOCAL"\n'
        csv_file = tmp_path / "results.csv"
        csv_file.write_text("BloodHound Query Results\n" + content)

        assert PlumHoundParser.can_parse(csv_file)

    def test_cannot_parse_random_json(self, tmp_path: Path):
        """Test that random JSON is rejected."""
        json_file = tmp_path / "random.json"
        json_file.write_text('{"random": "data"}')

        assert not PlumHoundParser.can_parse(json_file)

    # =========================================================================
    # JSON User Parsing Tests
    # =========================================================================

    def test_parse_json_user(self, tmp_path: Path):
        """Test parsing user from JSON."""
        # PlumHound expects array format or single entry, not results wrapper at top level
        data = [
            {
                "query": "Domain Admins",
                "results": [
                    {"name": "admin@corp.local", "type": "User"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"
        assert users[0].domain == "corp.local"
        assert "bloodhound-finding" in users[0].tags

    def test_parse_user_with_backslash_format(self, tmp_path: Path):
        """Test parsing user with DOMAIN\\user format."""
        data = [
            {
                "query": "High Value Targets",
                "results": [
                    {"name": "CORP\\admin", "type": "User"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"
        assert users[0].domain == "CORP"

    def test_parse_critical_query_results(self, tmp_path: Path):
        """Test that critical queries get critical severity."""
        data = [
            {
                "query": "DCSync Capable Users",
                "results": [
                    {"name": "syncadmin@corp.local", "type": "User"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert misconfigs[0].severity == "critical"

    # =========================================================================
    # JSON Computer Parsing Tests
    # =========================================================================

    def test_parse_json_computer(self, tmp_path: Path):
        """Test parsing computer from JSON."""
        data = [
            {
                "query": "Unconstrained Delegation",
                "results": [
                    {"name": "SRV01$", "type": "Computer"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SRV01"
        assert "bloodhound-finding" in hosts[0].tags

    def test_parse_computer_with_misconfig(self, tmp_path: Path):
        """Test that computers get associated misconfigurations."""
        data = [
            {
                "query": "Kerberoastable Accounts",
                "results": [
                    {"name": "WEB01", "type": "Computer"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        hosts = self.get_hosts(entities)
        misconfigs = self.get_misconfigurations(entities)

        assert len(hosts) >= 1
        assert len(misconfigs) >= 1
        assert "Kerberoastable" in misconfigs[0].title

    # =========================================================================
    # JSON Group Parsing Tests
    # =========================================================================

    def test_parse_json_group(self, tmp_path: Path):
        """Test parsing group from JSON."""
        data = [
            {
                "query": "GPO Abuse Paths",
                "results": [
                    {"name": "IT Admins", "type": "Group"}
                ]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert "IT Admins" in misconfigs[0].title

    # =========================================================================
    # CSV Parsing Tests
    # =========================================================================

    def test_parse_csv_user(self, tmp_path: Path):
        """Test parsing user from CSV."""
        content = '"UserName","Domain"\n"jsmith","CORP.LOCAL"\n'
        csv_file = tmp_path / "plumhound_domain_admins.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "jsmith"

    def test_parse_csv_user_with_upn(self, tmp_path: Path):
        """Test parsing user with UPN format in CSV."""
        content = '"UserName"\n"admin@corp.local"\n'
        csv_file = tmp_path / "plumhound_results.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        users = self.get_users(entities)
        assert len(users) >= 1
        assert users[0].username == "admin"
        assert users[0].domain == "corp.local"

    def test_parse_csv_computer(self, tmp_path: Path):
        """Test parsing computer from CSV."""
        content = '"ComputerName","Domain"\n"SRV01$","CORP.LOCAL"\n'
        csv_file = tmp_path / "plumhound_computers.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        hosts = self.get_hosts(entities)
        assert len(hosts) >= 1
        assert hosts[0].hostname == "SRV01"

    def test_parse_csv_attack_path(self, tmp_path: Path):
        """Test parsing attack path from CSV."""
        content = '"Path","Length"\n"USER@CORP.LOCAL -> ADMIN@CORP.LOCAL","2"\n'
        csv_file = tmp_path / "plumhound_paths.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        path_findings = [m for m in misconfigs if "Attack Path" in m.title]
        assert len(path_findings) >= 1

    def test_csv_critical_filename(self, tmp_path: Path):
        """Test that critical query names in filename give critical severity."""
        content = '"UserName"\n"admin"\n'
        csv_file = tmp_path / "plumhound_kerberoastable.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        misconfigs = self.get_misconfigurations(entities)
        assert len(misconfigs) >= 1
        assert misconfigs[0].severity == "critical"

    # =========================================================================
    # JSON Format Variations Tests
    # =========================================================================

    def test_parse_array_format(self, tmp_path: Path):
        """Test parsing array of entries."""
        data = [
            {"query": "Query1", "results": [{"name": "user1@corp.local", "type": "User"}]},
            {"query": "Query2", "results": [{"name": "user2@corp.local", "type": "User"}]}
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 2

    def test_parse_results_wrapper(self, tmp_path: Path):
        """Test parsing entries inside results wrapper."""
        data = {
            "results": [
                {"query": "Test", "results": [{"name": "user@corp.local", "type": "User"}]}
            ]
        }
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    def test_parse_data_wrapper(self, tmp_path: Path):
        """Test parsing results inside data wrapper."""
        data = {
            "query": "Domain Admins",
            "data": [
                {"name": "admin@corp.local", "type": "User"}
            ]
        }
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    # =========================================================================
    # Edge Cases
    # =========================================================================

    def test_handles_empty_json(self, tmp_path: Path):
        """Test handling of empty JSON."""
        json_file = tmp_path / "plumhound.json"
        json_file.write_text("[]")

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        assert isinstance(entities, list)
        assert len(entities) == 0

    def test_handles_empty_csv(self, tmp_path: Path):
        """Test handling of empty CSV."""
        content = '"UserName","Domain"\n'
        csv_file = tmp_path / "plumhound.csv"
        csv_file.write_text(content)

        parser = PlumHoundParser()
        entities = list(parser.parse(csv_file))

        assert isinstance(entities, list)

    def test_handles_missing_name(self, tmp_path: Path):
        """Test handling of entry without name."""
        data = {
            "query": "Test",
            "results": [{"type": "User"}]
        }
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        # Should not crash, may not produce output
        assert isinstance(entities, list)

    def test_extracts_name_from_alternative_keys(self, tmp_path: Path):
        """Test extraction of name from alternative column names."""
        data = [
            {
                "query": "Test",
                "results": [{"Name": "admin@corp.local", "label": "User"}]
            }
        ]
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        users = self.get_users(entities)
        assert len(users) >= 1

    # =========================================================================
    # Source Attribution Tests
    # =========================================================================

    def test_source_is_plumhound(self, tmp_path: Path):
        """Test that source is set to plumhound."""
        data = {
            "query": "Test",
            "results": [{"name": "user@corp.local", "type": "User"}]
        }
        json_file = tmp_path / "plumhound.json"
        json_file.write_text(json.dumps(data))

        parser = PlumHoundParser()
        entities = list(parser.parse(json_file))

        for entity in entities:
            assert entity.source == "plumhound"
