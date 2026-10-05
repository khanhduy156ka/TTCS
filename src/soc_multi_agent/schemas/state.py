from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from soc_multi_agent.rag.schemas import RetrievedChunk
from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EnrichmentAssessment,
    EnrichmentResult,
)
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
)
from soc_multi_agent.schemas.remediation import (
    RemediationPlan,
)
from soc_multi_agent.schemas.triage import (
    TriageResult,
)


class CaseStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ENRICHED = "enriched"
    INVESTIGATED = "investigated"
    REMEDIATION_PROPOSED = "remediation_proposed"
    PENDING_HUMAN_APPROVAL = "pending_human_approval"
    REMEDIATION_APPROVED = "remediation_approved"
    REMEDIATION_REJECTED = "remediation_rejected"
    MONITORING = "monitoring"
    CLOSED = "closed"
    FAILED = "failed"


class AuditEvent(BaseModel):
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )
    stage: str
    action: str
    detail: str | None = None


class HumanDecision(BaseModel):
    approved: bool
    analyst: str
    reason: str | None = None

    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )


class SOCSharedState(BaseModel):
    case_id: str = ""
    status: CaseStatus = CaseStatus.NEW

    alert: NormalizedAlert | None = None
    triage: TriageResult | None = None

    enrichment: EnrichmentResult | None = None
    enrichment_assessment: (
        EnrichmentAssessment | None
    ) = None

    rag_query: str | None = None
    retrieved_knowledge: list[RetrievedChunk] = Field(
        default_factory=list
    )

    investigation: InvestigationResult | None = None
    remediation: RemediationPlan | None = None

    human_approval_required: bool = False
    human_approved: bool | None = None

    human_decision: HumanDecision | None = None

    stage_durations: dict[str, float] = Field(
        default_factory=dict
    )

    audit_trail: list[AuditEvent] = Field(
        default_factory=list
    )