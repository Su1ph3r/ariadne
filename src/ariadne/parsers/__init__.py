"""Parser plugin system for ingesting security tool outputs."""

from ariadne.parsers.base import BaseParser, ParserResult
from ariadne.parsers.registry import ParserRegistry, register_parser

__all__ = [
    "BaseParser",
    "ParserResult",
    "ParserRegistry",
    "register_parser",
]
