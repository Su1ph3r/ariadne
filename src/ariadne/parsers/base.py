"""Base parser interface for the plugin system."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Union

from ariadne.models.asset import Host, Service, User, CloudResource, Container, MobileApp, ApiEndpoint
from ariadne.models.finding import Vulnerability, Misconfiguration, Credential
from ariadne.models.relationship import Relationship

Entity = Union[Host, Service, User, CloudResource, Container, MobileApp, ApiEndpoint, Vulnerability, Misconfiguration, Credential, Relationship]


@dataclass
class ParserResult:
    """Result container from a parser run."""

    entities: list[Entity] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_file: Path | None = None

    @property
    def hosts(self) -> list[Host]:
        return [e for e in self.entities if isinstance(e, Host)]

    @property
    def services(self) -> list[Service]:
        return [e for e in self.entities if isinstance(e, Service)]

    @property
    def vulnerabilities(self) -> list[Vulnerability]:
        return [e for e in self.entities if isinstance(e, Vulnerability)]

    @property
    def relationships(self) -> list[Relationship]:
        return [e for e in self.entities if isinstance(e, Relationship)]


class BaseParser(ABC):
    """Abstract base class for all parsers.

    Parsers are responsible for reading output from security tools
    and normalizing them into Ariadne's unified data model.
    """

    name: str = "base"
    description: str = "Base parser"
    file_patterns: list[str] = []
    entity_types: list[str] = []

    @abstractmethod
    def parse(self, file_path: Path) -> Generator[Entity, None, None]:
        """Parse a file and yield normalized entities.

        Args:
            file_path: Path to the file to parse

        Yields:
            Normalized entity objects (Host, Service, Vulnerability, etc.)
        """
        pass

    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this parser can handle the given file.

        Default implementation checks file extension and patterns.
        Override for more sophisticated detection (e.g., content sniffing).

        Args:
            file_path: Path to check

        Returns:
            True if this parser can handle the file
        """
        import fnmatch

        name = file_path.name
        return any(fnmatch.fnmatch(name, pattern) for pattern in cls.file_patterns)

    def parse_file(self, file_path: Path) -> ParserResult:
        """Parse a file and return a result container.

        This is a convenience wrapper around parse() that collects
        all entities and handles errors.

        Args:
            file_path: Path to the file to parse

        Returns:
            ParserResult containing all parsed entities
        """
        result = ParserResult(source_file=file_path)

        try:
            for entity in self.parse(file_path):
                result.entities.append(entity)
        except Exception as e:
            result.errors.append(f"Error parsing {file_path}: {e}")

        return result

    def validate_file(self, file_path: Path) -> tuple[bool, list[str]]:
        """Validate that a file can be parsed without fully parsing it.

        Args:
            file_path: Path to validate

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        if not file_path.exists():
            errors.append(f"File does not exist: {file_path}")
        elif not file_path.is_file():
            errors.append(f"Path is not a file: {file_path}")
        elif file_path.stat().st_size == 0:
            errors.append(f"File is empty: {file_path}")

        return len(errors) == 0, errors
