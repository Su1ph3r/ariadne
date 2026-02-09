"""Parser registry for discovering and managing parsers."""

import logging
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Generator, Type

from ariadne.parsers.base import BaseParser, Entity, ParserResult

logger = logging.getLogger(__name__)


_PARSER_REGISTRY: dict[str, Type[BaseParser]] = {}


def register_parser(cls: Type[BaseParser]) -> Type[BaseParser]:
    """Decorator to register a parser class.

    Usage:
        @register_parser
        class MyParser(BaseParser):
            name = "my_parser"
            ...
    """
    _PARSER_REGISTRY[cls.name] = cls
    return cls


@dataclass
class ParserInfo:
    """Information about a registered parser."""

    name: str
    description: str
    file_patterns: list[str]
    entity_types: list[str]
    parser_class: Type[BaseParser]


class ParserRegistry:
    """Registry for discovering and managing parsers.

    Parsers can be registered via:
    1. The @register_parser decorator
    2. Entry points (ariadne.parsers)
    3. Manual registration
    """

    def __init__(self, auto_discover: bool = True) -> None:
        self._parsers: dict[str, Type[BaseParser]] = {}
        self._instances: dict[str, BaseParser] = {}

        self._parsers.update(_PARSER_REGISTRY)

        if auto_discover:
            self._discover_entry_points()
            self._discover_builtin()

    def _discover_entry_points(self) -> None:
        """Discover parsers from entry points."""
        try:
            eps = entry_points(group="ariadne.parsers")
            for ep in eps:
                try:
                    parser_class = ep.load()
                    if issubclass(parser_class, BaseParser):
                        self._parsers[ep.name] = parser_class
                except Exception as e:
                    logger.warning(
                        "Failed to load parser entry point '%s': %s", ep.name, e
                    )
        except Exception as e:
            logger.warning("Failed to discover parser entry points: %s", e)

    def _discover_builtin(self) -> None:
        """Import built-in parsers."""
        from ariadne.parsers import (
            nmap,
            nuclei,
            bloodhound,
            nessus,
            crackmapexec,
            certipy,
            impacket,
            masscan,
            pingcastle,
            ldapdomaindump,
            testssl,
            shodan,
            censys,
            metasploit,
            responder,
            smbmap,
            azurehound,
            openvas,
            qualys,
            enum4linux,
            rubeus,
            mimikatz,
            snaffler,
            kerbrute,
            ntlmrelayx,
            rustscan,
            adrecon,
            plumhound,
            grouper2,
            windapsearch,
            ldeep,
            mitm6,
            rpcclient,
            cobaltstrike,
            sliver,
            havoc,
            mythic,
            seatbelt,
            sharpup,
            watson,
            powerview,
            amass,
            subfinder,
            httpx,
            eyewitness,
            vinculum,
        )
        from ariadne.parsers.cloud import (
            aws_scout,
            azure_enum,
        )

        for module in [
            nmap,
            nuclei,
            bloodhound,
            nessus,
            crackmapexec,
            certipy,
            impacket,
            masscan,
            pingcastle,
            ldapdomaindump,
            testssl,
            shodan,
            censys,
            metasploit,
            responder,
            smbmap,
            azurehound,
            openvas,
            qualys,
            enum4linux,
            rubeus,
            mimikatz,
            snaffler,
            kerbrute,
            ntlmrelayx,
            rustscan,
            adrecon,
            plumhound,
            grouper2,
            windapsearch,
            ldeep,
            mitm6,
            rpcclient,
            cobaltstrike,
            sliver,
            havoc,
            mythic,
            seatbelt,
            sharpup,
            watson,
            powerview,
            amass,
            subfinder,
            httpx,
            eyewitness,
            vinculum,
            aws_scout,
            azure_enum,
        ]:
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseParser)
                    and attr is not BaseParser
                    and hasattr(attr, "name")
                ):
                    self._parsers[attr.name] = attr

    def register(self, parser_class: Type[BaseParser]) -> None:
        """Manually register a parser class."""
        self._parsers[parser_class.name] = parser_class

    def get_parser(self, name: str) -> BaseParser | None:
        """Get a parser instance by name."""
        if name not in self._parsers:
            return None

        if name not in self._instances:
            self._instances[name] = self._parsers[name]()

        return self._instances[name]

    def list_parsers(self) -> list[ParserInfo]:
        """List all registered parsers."""
        return [
            ParserInfo(
                name=cls.name,
                description=cls.description,
                file_patterns=cls.file_patterns,
                entity_types=cls.entity_types,
                parser_class=cls,
            )
            for cls in self._parsers.values()
        ]

    def find_parser(self, file_path: Path) -> BaseParser | None:
        """Find a parser that can handle the given file."""
        for parser_class in self._parsers.values():
            if parser_class.can_parse(file_path):
                name = parser_class.name
                if name not in self._instances:
                    self._instances[name] = parser_class()
                return self._instances[name]
        return None

    def parse_file(self, file_path: Path) -> ParserResult:
        """Parse a file using the appropriate parser."""
        parser = self.find_parser(file_path)
        if not parser:
            result = ParserResult(source_file=file_path)
            result.errors.append(f"No parser found for: {file_path}")
            return result

        return parser.parse_file(file_path)

    def parse_path(self, path: Path) -> Generator[Entity, None, None]:
        """Parse all files in a path, yielding entities.

        Args:
            path: File or directory path

        Yields:
            Entities from all parsed files
        """
        if path.is_file():
            files = [path]
        else:
            files = list(path.rglob("*"))
            files = [f for f in files if f.is_file()]

        for file_path in files:
            parser = self.find_parser(file_path)
            if parser:
                try:
                    yield from parser.parse(file_path)
                except Exception as e:
                    logger.warning(
                        "Failed to parse file '%s' with parser '%s': %s",
                        file_path,
                        parser.name,
                        e,
                    )
                    continue

    def parse_all(self, path: Path) -> list[ParserResult]:
        """Parse all files in a path and return results."""
        results = []

        if path.is_file():
            files = [path]
        else:
            files = list(path.rglob("*"))
            files = [f for f in files if f.is_file()]

        for file_path in files:
            parser = self.find_parser(file_path)
            if parser:
                results.append(parser.parse_file(file_path))

        return results
