"""Attack path models representing synthesized attack chains."""

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class AttackTechnique(BaseModel):
    """A MITRE ATT&CK technique associated with an attack step."""

    technique_id: str
    name: str
    tactic: str
    description: Optional[str] = None
    url: str = ""
    sub_technique: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.url and self.technique_id:
            tid = self.technique_id.replace(".", "/")
            self.url = f"https://attack.mitre.org/techniques/{tid}/"


class AttackStep(BaseModel):
    """A single step in an attack path."""

    id: str = ""
    order: int = 0
    source_asset_id: str
    target_asset_id: str
    relationship_id: Optional[str] = None
    action: str
    description: str
    technique: Optional[AttackTechnique] = None
    finding_ids: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    probability: float = 1.0
    detection_risk: float = 0.5
    impact: str = "medium"
    notes: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid4())

    @property
    def risk_score(self) -> float:
        """Calculate risk score based on probability and detection."""
        return self.probability * (1 - self.detection_risk * 0.5)


class AttackPath(BaseModel):
    """A complete attack path from initial access to objective."""

    id: str = ""
    name: str
    description: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    entry_point_id: str = ""
    target_id: str = ""
    probability: float = 0.0
    impact: str = "high"
    complexity: str = "medium"
    techniques: list[AttackTechnique] = Field(default_factory=list)
    findings_used: list[str] = Field(default_factory=list)
    llm_analysis: Optional[str] = None
    llm_confidence: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"extra": "allow"}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid4())

    @property
    def length(self) -> int:
        """Number of steps in the attack path."""
        return len(self.steps)

    @property
    def tactics_used(self) -> list[str]:
        """List of MITRE ATT&CK tactics used in this path."""
        tactics = []
        for step in self.steps:
            if step.technique and step.technique.tactic not in tactics:
                tactics.append(step.technique.tactic)
        return tactics

    @property
    def risk_score(self) -> float:
        """Overall risk score for the attack path."""
        if not self.steps:
            return 0.0
        return self.probability * self._impact_multiplier

    @property
    def _impact_multiplier(self) -> float:
        """Convert impact string to numeric multiplier."""
        multipliers = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
        }
        return multipliers.get(self.impact.lower(), 0.5)

    def add_step(self, step: AttackStep) -> None:
        """Add a step to the attack path."""
        step.order = len(self.steps)
        self.steps.append(step)
        self._recalculate_probability()

    def _recalculate_probability(self) -> None:
        """Recalculate overall probability from steps."""
        if not self.steps:
            self.probability = 0.0
            return

        prob = 1.0
        for step in self.steps:
            prob *= step.probability
        self.probability = prob

    def to_narrative(self) -> str:
        """Generate a human-readable narrative of the attack path."""
        if not self.steps:
            return "Empty attack path."

        lines = [f"## {self.name}\n"]
        lines.append(f"**Probability:** {self.probability:.1%}")
        lines.append(f"**Impact:** {self.impact.title()}")
        lines.append(f"**Steps:** {len(self.steps)}\n")

        if self.description:
            lines.append(f"{self.description}\n")

        lines.append("### Attack Steps\n")

        for i, step in enumerate(self.steps, 1):
            technique_info = ""
            if step.technique:
                technique_info = f" [{step.technique.technique_id}: {step.technique.name}]"

            lines.append(f"{i}. **{step.action}**{technique_info}")
            lines.append(f"   {step.description}")
            if step.notes:
                lines.append(f"   *Note: {step.notes}*")
            lines.append("")

        if self.llm_analysis:
            lines.append("### AI Analysis\n")
            lines.append(self.llm_analysis)

        return "\n".join(lines)

    def to_graph_data(self) -> dict:
        """Export path as graph visualization data."""
        nodes = []
        edges = []
        seen_nodes = set()

        for step in self.steps:
            if step.source_asset_id not in seen_nodes:
                nodes.append({
                    "id": step.source_asset_id,
                    "type": "asset",
                })
                seen_nodes.add(step.source_asset_id)

            if step.target_asset_id not in seen_nodes:
                nodes.append({
                    "id": step.target_asset_id,
                    "type": "asset",
                })
                seen_nodes.add(step.target_asset_id)

            edges.append({
                "source": step.source_asset_id,
                "target": step.target_asset_id,
                "action": step.action,
                "probability": step.probability,
                "technique": step.technique.technique_id if step.technique else None,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "path_id": self.id,
                "name": self.name,
                "probability": self.probability,
            },
        }
