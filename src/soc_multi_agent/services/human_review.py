from soc_multi_agent.schemas.state import (
    AuditEvent,
    CaseStatus,
    HumanDecision,
    SOCSharedState,
)
from soc_multi_agent.services.case_repository import (
    load_case,
    save_case,
)


def _validate_reviewable_case(
    state: SOCSharedState,
) -> None:
    if state.remediation is None:
        raise ValueError(
            "Case has no remediation plan to review."
        )

    if not state.human_approval_required:
        raise ValueError(
            "Case does not require human approval."
        )

    if (
        state.status
        != CaseStatus.PENDING_HUMAN_APPROVAL
    ):
        raise ValueError(
            "Case is not pending human approval. "
            f"Current status: {state.status.value}"
        )

    if state.human_decision is not None:
        raise ValueError(
            "Case already has a human decision."
        )


def review_case(
    case_id: str,
    approved: bool,
    analyst: str,
    reason: str | None = None,
) -> SOCSharedState:
    """
    Record a human analyst decision for a remediation plan.

    This function only records approval or rejection.
    It does not automatically execute remediation actions.
    """

    analyst = analyst.strip()

    if not analyst:
        raise ValueError(
            "analyst must not be empty"
        )

    if reason is not None:
        reason = reason.strip()

        if not reason:
            reason = None

    state = load_case(case_id)

    if state is None:
        raise ValueError(
            f"Case not found: {case_id}"
        )

    _validate_reviewable_case(state)

    decision = HumanDecision(
        approved=approved,
        analyst=analyst,
        reason=reason,
    )

    state.human_approved = approved
    state.human_decision = decision

    if approved:
        state.status = (
            CaseStatus.REMEDIATION_APPROVED
        )

        action = "remediation_approved"

        detail = (
            f"Remediation plan approved by "
            f"{analyst}"
        )

    else:
        state.status = (
            CaseStatus.REMEDIATION_REJECTED
        )

        action = "remediation_rejected"

        detail = (
            f"Remediation plan rejected by "
            f"{analyst}"
        )

    if reason:
        detail += f". Reason: {reason}"

    state.audit_trail.append(
        AuditEvent(
            stage="human_review",
            action=action,
            detail=detail,
        )
    )

    save_case(state)

    return state


def approve_case(
    case_id: str,
    analyst: str,
    reason: str | None = None,
) -> SOCSharedState:
    """
    Approve a remediation plan.

    Approval is persisted but does not execute actions.
    """

    return review_case(
        case_id=case_id,
        approved=True,
        analyst=analyst,
        reason=reason,
    )


def reject_case(
    case_id: str,
    analyst: str,
    reason: str | None = None,
) -> SOCSharedState:
    """
    Reject a remediation plan.
    """

    return review_case(
        case_id=case_id,
        approved=False,
        analyst=analyst,
        reason=reason,
    )