"""Tests for LLM prompt templates."""

import pytest

from ariadne.llm.prompts import PromptTemplates


class TestPromptTemplateAttributes:
    """Test prompt template class attributes."""

    def test_has_system_prompt(self):
        """Test system prompt exists."""
        assert hasattr(PromptTemplates, "SYSTEM_PROMPT")
        assert isinstance(PromptTemplates.SYSTEM_PROMPT, str)
        assert len(PromptTemplates.SYSTEM_PROMPT) > 0

    def test_has_path_enumeration(self):
        """Test path enumeration template exists."""
        assert hasattr(PromptTemplates, "PATH_ENUMERATION")
        assert isinstance(PromptTemplates.PATH_ENUMERATION, str)

    def test_has_path_validation(self):
        """Test path validation template exists."""
        assert hasattr(PromptTemplates, "PATH_VALIDATION")
        assert isinstance(PromptTemplates.PATH_VALIDATION, str)

    def test_has_technique_mapping(self):
        """Test technique mapping template exists."""
        assert hasattr(PromptTemplates, "TECHNIQUE_MAPPING")
        assert isinstance(PromptTemplates.TECHNIQUE_MAPPING, str)

    def test_has_narrative_generation(self):
        """Test narrative generation template exists."""
        assert hasattr(PromptTemplates, "NARRATIVE_GENERATION")
        assert isinstance(PromptTemplates.NARRATIVE_GENERATION, str)

    def test_has_remediation_suggestions(self):
        """Test remediation suggestions template exists."""
        assert hasattr(PromptTemplates, "REMEDIATION_SUGGESTIONS")
        assert isinstance(PromptTemplates.REMEDIATION_SUGGESTIONS, str)


class TestSystemPrompt:
    """Test system prompt content."""

    def test_mentions_penetration_testing(self):
        """Test system prompt mentions penetration testing."""
        assert "penetration" in PromptTemplates.SYSTEM_PROMPT.lower()

    def test_mentions_red_team(self):
        """Test system prompt mentions red team."""
        assert "red team" in PromptTemplates.SYSTEM_PROMPT.lower()

    def test_mentions_mitre_attack(self):
        """Test system prompt mentions MITRE ATT&CK."""
        assert "mitre" in PromptTemplates.SYSTEM_PROMPT.lower()

    def test_mentions_active_directory(self):
        """Test system prompt mentions Active Directory."""
        assert "active directory" in PromptTemplates.SYSTEM_PROMPT.lower()


class TestPathEnumerationTemplate:
    """Test path enumeration template."""

    def test_has_entry_points_placeholder(self):
        """Test template has entry points placeholder."""
        assert "{entry_points}" in PromptTemplates.PATH_ENUMERATION

    def test_has_targets_placeholder(self):
        """Test template has targets placeholder."""
        assert "{targets}" in PromptTemplates.PATH_ENUMERATION

    def test_has_vulnerabilities_placeholder(self):
        """Test template has vulnerabilities placeholder."""
        assert "{vulnerabilities}" in PromptTemplates.PATH_ENUMERATION

    def test_has_topology_placeholder(self):
        """Test template has topology placeholder."""
        assert "{topology}" in PromptTemplates.PATH_ENUMERATION

    def test_has_relationships_placeholder(self):
        """Test template has relationships placeholder."""
        assert "{relationships}" in PromptTemplates.PATH_ENUMERATION

    def test_requests_json_format(self):
        """Test template requests JSON format."""
        assert "json" in PromptTemplates.PATH_ENUMERATION.lower()

    def test_includes_attack_paths_structure(self):
        """Test template includes attack_paths in JSON structure."""
        assert "attack_paths" in PromptTemplates.PATH_ENUMERATION


class TestPathValidationTemplate:
    """Test path validation template."""

    def test_has_attack_path_placeholder(self):
        """Test template has attack path placeholder."""
        assert "{attack_path}" in PromptTemplates.PATH_VALIDATION

    def test_has_context_placeholder(self):
        """Test template has context placeholder."""
        assert "{context}" in PromptTemplates.PATH_VALIDATION

    def test_requests_feasibility_check(self):
        """Test template requests feasibility check."""
        assert "feasible" in PromptTemplates.PATH_VALIDATION.lower()

    def test_requests_detection_risks(self):
        """Test template requests detection risks."""
        assert "detection" in PromptTemplates.PATH_VALIDATION.lower()


class TestTechniqueMappingTemplate:
    """Test technique mapping template."""

    def test_has_title_placeholder(self):
        """Test template has title placeholder."""
        assert "{title}" in PromptTemplates.TECHNIQUE_MAPPING

    def test_has_finding_type_placeholder(self):
        """Test template has finding type placeholder."""
        assert "{finding_type}" in PromptTemplates.TECHNIQUE_MAPPING

    def test_has_description_placeholder(self):
        """Test template has description placeholder."""
        assert "{description}" in PromptTemplates.TECHNIQUE_MAPPING

    def test_has_asset_placeholder(self):
        """Test template has asset placeholder."""
        assert "{asset}" in PromptTemplates.TECHNIQUE_MAPPING

    def test_has_severity_placeholder(self):
        """Test template has severity placeholder."""
        assert "{severity}" in PromptTemplates.TECHNIQUE_MAPPING

    def test_includes_primary_techniques(self):
        """Test template includes primary_techniques in JSON structure."""
        assert "primary_techniques" in PromptTemplates.TECHNIQUE_MAPPING

    def test_includes_followon_techniques(self):
        """Test template includes followon_techniques in JSON structure."""
        assert "followon_techniques" in PromptTemplates.TECHNIQUE_MAPPING


class TestNarrativeGenerationTemplate:
    """Test narrative generation template."""

    def test_has_attack_path_placeholder(self):
        """Test template has attack path placeholder."""
        assert "{attack_path}" in PromptTemplates.NARRATIVE_GENERATION

    def test_has_steps_placeholder(self):
        """Test template has steps placeholder."""
        assert "{steps}" in PromptTemplates.NARRATIVE_GENERATION

    def test_has_findings_placeholder(self):
        """Test template has findings placeholder."""
        assert "{findings}" in PromptTemplates.NARRATIVE_GENERATION

    def test_mentions_tools_techniques(self):
        """Test template mentions tools/techniques."""
        assert "tools" in PromptTemplates.NARRATIVE_GENERATION.lower()
        assert "techniques" in PromptTemplates.NARRATIVE_GENERATION.lower()


class TestRemediationSuggestionsTemplate:
    """Test remediation suggestions template."""

    def test_has_attack_path_placeholder(self):
        """Test template has attack path placeholder."""
        assert "{attack_path}" in PromptTemplates.REMEDIATION_SUGGESTIONS

    def test_has_vulnerabilities_placeholder(self):
        """Test template has vulnerabilities placeholder."""
        assert "{vulnerabilities}" in PromptTemplates.REMEDIATION_SUGGESTIONS

    def test_includes_remediations_structure(self):
        """Test template includes remediations in JSON structure."""
        assert "remediations" in PromptTemplates.REMEDIATION_SUGGESTIONS

    def test_requests_immediate_actions(self):
        """Test template requests immediate actions."""
        assert "immediate" in PromptTemplates.REMEDIATION_SUGGESTIONS.lower()

    def test_requests_long_term_fixes(self):
        """Test template requests long term fixes."""
        assert "long_term" in PromptTemplates.REMEDIATION_SUGGESTIONS.lower()


class TestFormatPathEnumeration:
    """Test format_path_enumeration method."""

    def test_formats_all_placeholders(self):
        """Test all placeholders are formatted."""
        result = PromptTemplates.format_path_enumeration(
            entry_points="Entry point data",
            targets="Target data",
            vulnerabilities="Vulnerability data",
            topology="Topology data",
            relationships="Relationship data",
        )

        assert "Entry point data" in result
        assert "Target data" in result
        assert "Vulnerability data" in result
        assert "Topology data" in result
        assert "Relationship data" in result
        # Check placeholders are replaced (not the JSON examples with {{ }})
        assert "{entry_points}" not in result
        assert "{targets}" not in result
        assert "{vulnerabilities}" not in result
        assert "{topology}" not in result
        assert "{relationships}" not in result

    def test_returns_string(self):
        """Test method returns string."""
        result = PromptTemplates.format_path_enumeration(
            entry_points="",
            targets="",
            vulnerabilities="",
            topology="",
            relationships="",
        )

        assert isinstance(result, str)


class TestFormatPathValidation:
    """Test format_path_validation method."""

    def test_formats_all_placeholders(self):
        """Test all placeholders are formatted."""
        result = PromptTemplates.format_path_validation(
            attack_path="Attack path data",
            context="Context data",
        )

        assert "Attack path data" in result
        assert "Context data" in result

    def test_returns_string(self):
        """Test method returns string."""
        result = PromptTemplates.format_path_validation(
            attack_path="",
            context="",
        )

        assert isinstance(result, str)


class TestFormatTechniqueMapping:
    """Test format_technique_mapping method."""

    def test_formats_all_placeholders(self):
        """Test all placeholders are formatted."""
        result = PromptTemplates.format_technique_mapping(
            title="Test Title",
            finding_type="Vulnerability",
            description="Test description",
            asset="192.168.1.1",
            severity="High",
        )

        assert "Test Title" in result
        assert "Vulnerability" in result
        assert "Test description" in result
        assert "192.168.1.1" in result
        assert "High" in result

    def test_returns_string(self):
        """Test method returns string."""
        result = PromptTemplates.format_technique_mapping(
            title="",
            finding_type="",
            description="",
            asset="",
            severity="",
        )

        assert isinstance(result, str)


class TestFormatNarrative:
    """Test format_narrative method."""

    def test_formats_all_placeholders(self):
        """Test all placeholders are formatted."""
        result = PromptTemplates.format_narrative(
            attack_path="Attack path data",
            steps="Steps data",
            findings="Findings data",
        )

        assert "Attack path data" in result
        assert "Steps data" in result
        assert "Findings data" in result

    def test_returns_string(self):
        """Test method returns string."""
        result = PromptTemplates.format_narrative(
            attack_path="",
            steps="",
            findings="",
        )

        assert isinstance(result, str)
