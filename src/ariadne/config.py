"""Configuration management for Ariadne."""

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 60  # Request timeout in seconds
    max_retries: int = 3  # Maximum retry attempts
    retry_delay: float = 1.0  # Base delay for exponential backoff

    def model_post_init(self, __context: object) -> None:
        if self.api_key and self.api_key.startswith("${") and self.api_key.endswith("}"):
            env_var = self.api_key[2:-1]
            self.api_key = os.environ.get(env_var)


class ScoringWeights(BaseModel):
    """Weights for attack path probability scoring."""

    cvss: float = 0.3
    exploit_available: float = 0.25
    network_position: float = 0.2
    privilege_required: float = 0.15
    detection_likelihood: float = 0.1


class ScoringConfig(BaseModel):
    """Scoring configuration."""

    weights: ScoringWeights = Field(default_factory=ScoringWeights)
    min_path_score: float = 0.1
    max_path_length: int = 10
    path_timeout_seconds: float = 30.0  # Timeout for path finding operations
    max_paths_per_query: int = 100  # Maximum paths to return per query


class ParsersConfig(BaseModel):
    """Parser configuration."""

    enabled: list[str] = Field(default_factory=lambda: ["nmap", "nuclei", "bloodhound"])
    custom_paths: list[str] = Field(default_factory=list)
    auto_detect: bool = True


class OutputConfig(BaseModel):
    """Output configuration."""

    default_format: str = "html"
    include_raw_findings: bool = False
    max_paths: int = 20
    template_dir: Optional[str] = None


class WebConfig(BaseModel):
    """Web dashboard configuration."""

    host: str = "127.0.0.1"
    port: int = 8443
    debug: bool = False
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:8443"])
    persistent_sessions: bool = False
    session_ttl_hours: int = 24


class StorageConfig(BaseModel):
    """Storage configuration."""

    data_dir: Optional[str] = None
    session_db: Optional[str] = None

    @property
    def resolved_data_dir(self) -> Path:
        """Get the resolved data directory path."""
        if self.data_dir:
            return Path(self.data_dir)
        return get_ariadne_home() / "data"

    @property
    def resolved_session_db(self) -> Path:
        """Get the resolved session database path."""
        if self.session_db:
            return Path(self.session_db)
        return get_ariadne_home() / "sessions.db"


def get_ariadne_home() -> Path:
    """Get the Ariadne home directory.

    Checks in order:
    1. ARIADNE_HOME environment variable
    2. ~/.ariadne/

    Creates the directory if it doesn't exist.
    """
    env_home = os.environ.get("ARIADNE_HOME")
    if env_home:
        home = Path(env_home)
    else:
        home = Path.home() / ".ariadne"

    home.mkdir(parents=True, exist_ok=True)
    return home


class AriadneConfig(BaseSettings):
    """Main Ariadne configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    parsers: ParsersConfig = Field(default_factory=ParsersConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    mitre_techniques_path: Optional[str] = None  # Path to custom MITRE techniques YAML

    class Config:
        env_prefix = "ARIADNE_"
        env_nested_delimiter = "__"


def load_config(config_path: Optional[Path] = None) -> AriadneConfig:
    """Load configuration from file or use defaults.

    Search order:
    1. Explicit config_path argument
    2. ./config.yaml or ./config.yml (current directory)
    3. ~/.ariadne/config.yaml or ~/.ariadne/config.yml
    4. ~/.config/ariadne/config.yaml (XDG standard)
    5. ARIADNE_* environment variables
    6. Default values
    """
    if config_path and config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
            return AriadneConfig(**data)

    ariadne_home = get_ariadne_home()

    default_paths = [
        Path("config.yaml"),
        Path("config.yml"),
        ariadne_home / "config.yaml",
        ariadne_home / "config.yml",
        Path.home() / ".config" / "ariadne" / "config.yaml",
    ]

    for path in default_paths:
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}
                return AriadneConfig(**data)

    return AriadneConfig()


_config: Optional[AriadneConfig] = None


def get_config() -> AriadneConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: AriadneConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
