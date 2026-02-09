"""Operator playbook models for executable attack path guidance."""

from pydantic import BaseModel, Field


class PlaybookCommand(BaseModel):
    """A single executable command in a playbook step."""

    tool: str
    command: str
    description: str = ""
    requires_root: bool = False
    requires_implant: bool = False


class PlaybookStep(BaseModel):
    """A single step in an operator playbook, mapped to an attack step."""

    order: int = 0
    attack_step_id: str = ""
    commands: list[PlaybookCommand] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    opsec_notes: list[str] = Field(default_factory=list)
    fallback_commands: list[PlaybookCommand] = Field(default_factory=list)
    expected_output: str = ""
    detection_signatures: list[str] = Field(default_factory=list)
    source: str = "template"


class Playbook(BaseModel):
    """A complete operator playbook for executing an attack path."""

    attack_path_id: str
    steps: list[PlaybookStep] = Field(default_factory=list)
    global_prerequisites: list[str] = Field(default_factory=list)
    global_opsec_notes: list[str] = Field(default_factory=list)
    estimated_time: str = ""
    complexity: str = "medium"
    llm_enhanced: bool = False
