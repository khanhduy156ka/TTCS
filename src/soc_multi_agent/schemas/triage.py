from enum import Enum

from pydantic import BaseModel, Field


class TriagePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageResult(BaseModel):
    alert_id: str

    category: str
    priority: TriagePriority

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    suspicious: bool

    requires_enrichment: bool
    requires_investigation: bool

    summary: str

    evidence: list[str] = Field(
        default_factory=list
    )

    recommended_next_step: str