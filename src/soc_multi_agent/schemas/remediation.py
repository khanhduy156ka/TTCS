from enum import Enum

from pydantic import BaseModel, Field, model_validator


class RemediationPriority(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationAction(BaseModel):
    action: str
    rationale: str
    impact: str
    approval_required: bool = True
    verification: str
    rollback: str | None = None


class RemediationPlan(BaseModel):
    alert_id: str
    required: bool
    priority: RemediationPriority

    actions: list[RemediationAction] = Field(
        default_factory=list
    )

    monitoring_steps: list[str] = Field(
        default_factory=list
    )

    summary: str
    recommended_next_step: str

    @model_validator(mode="after")
    def validate_remediation_consistency(self):
        if not self.required:
            if self.priority != RemediationPriority.NONE:
                raise ValueError(
                    "priority must be 'none' when remediation "
                    "is not required"
                )

            if self.actions:
                raise ValueError(
                    "actions must be empty when remediation "
                    "is not required"
                )

        if self.required:
            if self.priority == RemediationPriority.NONE:
                raise ValueError(
                    "priority cannot be 'none' when remediation "
                    "is required"
                )

            if not self.actions:
                raise ValueError(
                    "actions cannot be empty when remediation "
                    "is required"
                )

        return self