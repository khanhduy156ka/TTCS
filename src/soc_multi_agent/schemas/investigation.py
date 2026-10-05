from enum import Enum

from pydantic import BaseModel, Field


class InvestigationVerdict(str, Enum):
    BENIGN = "benign"
    LIKELY_BENIGN = "likely_benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class InvestigationResult(BaseModel):
    alert_id: str

    verdict: InvestigationVerdict

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    key_evidence: list[str] = Field(
        default_factory=list
    )

    contradictions: list[str] = Field(
        default_factory=list
    )

    missing_evidence: list[str] = Field(
        default_factory=list
    )

    validated_mitre_techniques: list[str] = Field(
        default_factory=list
    )

    rejected_mitre_techniques: list[str] = Field(
        default_factory=list
    )

    requires_remediation: bool

    summary: str
    recommended_next_step: str