"""Base test class for parser tests.

Provides common test patterns and assertions for all parser test classes.
Each parser test should inherit from BaseParserTest and implement the required
class attributes and any parser-specific tests.
"""

import pytest
from abc import ABC
from pathlib import Path
from typing import Type

from ariadne.parsers.base import BaseParser, Entity
from ariadne.models.asset import Host, Service, User, CloudResource
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship


class BaseParserTest(ABC):
    """Base class for parser tests.

    Subclasses should define:
        parser_class: The parser class to test
        expected_name: Expected parser name
        expected_patterns: List of expected file patterns
        expected_entity_types: List of expected entity type names

    And implement:
        sample_minimal_content: Minimal valid content for the parser
        sample_complex_content: Realistic fixture content
        malformed_content: Invalid content that should be handled gracefully
    """

    parser_class: Type[BaseParser]
    expected_name: str
    expected_patterns: list[str]
    expected_entity_types: list[str]

    @pytest.fixture
    def parser(self) -> BaseParser:
        """Create parser instance."""
        return self.parser_class()

    # =========================================================================
    # Attribute Tests
    # =========================================================================

    def test_parser_has_name(self, parser: BaseParser):
        """Test parser has a name attribute."""
        assert hasattr(parser, "name")
        assert parser.name is not None
        assert len(parser.name) > 0

    def test_parser_name_matches_expected(self, parser: BaseParser):
        """Test parser name matches expected value."""
        assert parser.name == self.expected_name

    def test_parser_has_file_patterns(self, parser: BaseParser):
        """Test parser has file_patterns attribute."""
        assert hasattr(parser, "file_patterns")
        assert isinstance(parser.file_patterns, list)
        assert len(parser.file_patterns) > 0

    def test_parser_patterns_match_expected(self, parser: BaseParser):
        """Test parser patterns include expected patterns."""
        for pattern in self.expected_patterns:
            assert pattern in parser.file_patterns, (
                f"Expected pattern '{pattern}' not in {parser.file_patterns}"
            )

    def test_parser_has_entity_types(self, parser: BaseParser):
        """Test parser has entity_types attribute."""
        assert hasattr(parser, "entity_types")
        assert isinstance(parser.entity_types, list)

    def test_parser_entity_types_match_expected(self, parser: BaseParser):
        """Test parser entity_types include expected types."""
        for entity_type in self.expected_entity_types:
            assert entity_type in parser.entity_types, (
                f"Expected entity type '{entity_type}' not in {parser.entity_types}"
            )

    def test_parser_has_description(self, parser: BaseParser):
        """Test parser has a description."""
        assert hasattr(parser, "description")
        assert parser.description is not None
        assert len(parser.description) > 0

    # =========================================================================
    # Interface Tests
    # =========================================================================

    def test_parser_has_parse_method(self, parser: BaseParser):
        """Test parser implements parse method."""
        assert hasattr(parser, "parse")
        assert callable(parser.parse)

    def test_parser_has_can_parse_method(self):
        """Test parser class has can_parse classmethod."""
        assert hasattr(self.parser_class, "can_parse")
        assert callable(self.parser_class.can_parse)

    def test_parser_has_parse_file_method(self, parser: BaseParser):
        """Test parser has parse_file convenience method."""
        assert hasattr(parser, "parse_file")
        assert callable(parser.parse_file)

    def test_parser_has_validate_file_method(self, parser: BaseParser):
        """Test parser has validate_file method."""
        assert hasattr(parser, "validate_file")
        assert callable(parser.validate_file)

    # =========================================================================
    # can_parse Tests
    # =========================================================================

    def test_can_parse_returns_bool(self, tmp_path: Path):
        """Test can_parse returns a boolean."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        result = self.parser_class.can_parse(test_file)
        assert isinstance(result, bool)

    def test_cannot_parse_directory(self, tmp_path: Path):
        """Test parser rejects directories."""
        result = self.parser_class.can_parse(tmp_path)
        assert result is False

    def test_cannot_parse_nonexistent_file(self, tmp_path: Path):
        """Test parser handles nonexistent files gracefully."""
        nonexistent = tmp_path / "nonexistent.xml"
        result = self.parser_class.can_parse(nonexistent)
        assert result is False

    # =========================================================================
    # validate_file Tests
    # =========================================================================

    def test_validate_nonexistent_file(self, parser: BaseParser, tmp_path: Path):
        """Test validation fails for nonexistent files."""
        nonexistent = tmp_path / "nonexistent.xml"
        is_valid, errors = parser.validate_file(nonexistent)
        assert is_valid is False
        assert len(errors) > 0
        assert any("not exist" in e.lower() for e in errors)

    def test_validate_empty_file(self, parser: BaseParser, tmp_path: Path):
        """Test validation fails for empty files."""
        empty_file = tmp_path / "empty.xml"
        empty_file.write_text("")
        is_valid, errors = parser.validate_file(empty_file)
        assert is_valid is False
        assert len(errors) > 0
        assert any("empty" in e.lower() for e in errors)

    def test_validate_directory(self, parser: BaseParser, tmp_path: Path):
        """Test validation fails for directories."""
        is_valid, errors = parser.validate_file(tmp_path)
        assert is_valid is False
        assert len(errors) > 0

    # =========================================================================
    # parse_file Tests (convenience method)
    # =========================================================================

    def test_parse_file_returns_result(self, parser: BaseParser, tmp_path: Path):
        """Test parse_file returns ParserResult."""
        from ariadne.parsers.base import ParserResult

        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        result = parser.parse_file(test_file)
        assert isinstance(result, ParserResult)

    def test_parse_file_records_source_file(self, parser: BaseParser, tmp_path: Path):
        """Test parse_file records the source file path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")
        result = parser.parse_file(test_file)
        assert result.source_file == test_file

    # =========================================================================
    # Helper Methods for Subclasses
    # =========================================================================

    def assert_entity_has_source(self, entity: Entity, expected_source: str):
        """Assert entity has correct source."""
        assert hasattr(entity, "source")
        assert entity.source == expected_source

    def assert_entity_has_id(self, entity: Entity):
        """Assert entity has a non-empty id."""
        assert hasattr(entity, "id")
        assert entity.id is not None
        assert len(entity.id) > 0

    def assert_entities_contain_type(
        self, entities: list[Entity], entity_type: type
    ) -> list:
        """Assert entities contain at least one of the given type."""
        filtered = [e for e in entities if isinstance(e, entity_type)]
        assert len(filtered) > 0, f"No entities of type {entity_type.__name__} found"
        return filtered

    def assert_host_has_ip(self, host: Host):
        """Assert host has an IP address."""
        assert host.ip is not None
        assert len(host.ip) > 0

    def assert_service_has_port(self, service: Service):
        """Assert service has a port number."""
        assert service.port is not None
        assert service.port > 0

    def assert_vulnerability_has_severity(self, vuln: Vulnerability):
        """Assert vulnerability has severity."""
        assert vuln.severity is not None
        assert vuln.severity in ["critical", "high", "medium", "low", "info"]

    def assert_credential_has_type(self, cred: Credential):
        """Assert credential has a type."""
        assert cred.credential_type is not None
        assert len(cred.credential_type) > 0

    def assert_relationship_valid(self, rel: Relationship):
        """Assert relationship has required fields."""
        assert rel.source_id is not None
        assert rel.target_id is not None
        assert rel.relation_type is not None

    def count_entities_by_type(self, entities: list[Entity]) -> dict[str, int]:
        """Count entities by type name."""
        counts: dict[str, int] = {}
        for entity in entities:
            type_name = type(entity).__name__
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts

    def get_hosts(self, entities: list[Entity]) -> list[Host]:
        """Extract hosts from entity list."""
        return [e for e in entities if isinstance(e, Host)]

    def get_services(self, entities: list[Entity]) -> list[Service]:
        """Extract services from entity list."""
        return [e for e in entities if isinstance(e, Service)]

    def get_users(self, entities: list[Entity]) -> list[User]:
        """Extract users from entity list."""
        return [e for e in entities if isinstance(e, User)]

    def get_vulnerabilities(self, entities: list[Entity]) -> list[Vulnerability]:
        """Extract vulnerabilities from entity list."""
        return [e for e in entities if isinstance(e, Vulnerability)]

    def get_misconfigurations(self, entities: list[Entity]) -> list[Misconfiguration]:
        """Extract misconfigurations from entity list."""
        return [e for e in entities if isinstance(e, Misconfiguration)]

    def get_credentials(self, entities: list[Entity]) -> list[Credential]:
        """Extract credentials from entity list."""
        return [e for e in entities if isinstance(e, Credential)]

    def get_relationships(self, entities: list[Entity]) -> list[Relationship]:
        """Extract relationships from entity list."""
        return [e for e in entities if isinstance(e, Relationship)]

    def get_cloud_resources(self, entities: list[Entity]) -> list[CloudResource]:
        """Extract cloud resources from entity list."""
        return [e for e in entities if isinstance(e, CloudResource)]
