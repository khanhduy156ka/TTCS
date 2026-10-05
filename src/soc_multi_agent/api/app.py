from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from soc_multi_agent.flows.soc_flow import (
    SOCSupervisorFlow,
)
from soc_multi_agent.schemas.alert import (
    NormalizedAlert,
)
from soc_multi_agent.schemas.state import (
    SOCSharedState,
)
from soc_multi_agent.services.case_repository import (
    get_connection,
    list_cases,
    load_case,
)
from soc_multi_agent.services.human_review import (
    approve_case,
    reject_case,
)


app = FastAPI(
    title="SOC Multi-Agent API",
    description=(
        "API gateway for the AI-assisted "
        "multi-agent Security Operations Center."
    ),
    version="0.1.0",
)


class HumanReviewRequest(BaseModel):
    analyst: str = Field(
        min_length=1,
    )
    reason: str | None = None


class AlertSubmissionRequest(BaseModel):
    alert: NormalizedAlert

    case_id: str | None = None


class AlertSubmissionResponse(BaseModel):
    case_id: str
    status: str
    route: str | None = None
    approval_required: bool | None = None
    performance: dict | None = None


@app.get(
    "/health",
)
def health_check() -> dict:
    """
    Check API and PostgreSQL connectivity.
    """

    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1"
                )

                cursor.fetchone()

    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=(
                "API is running but PostgreSQL "
                "is unavailable."
            ),
        ) from error

    return {
        "status": "ok",
        "database": "connected",
    }


@app.get(
    "/cases",
)
def get_cases(
    limit: int = Query(
        default=25,
        ge=1,
        le=100,
    ),
    status: str | None = Query(
        default=None,
    ),
) -> list[dict]:
    """
    Return recent SOC cases.

    The result is limited and can be filtered by status.
    """

    try:
        return list_cases(
            limit=limit,
            status=status,
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve SOC cases.",
        ) from error


@app.get(
    "/cases/{case_id}",
    response_model=SOCSharedState,
)
def get_case(
    case_id: str,
) -> SOCSharedState:
    """
    Return the complete persisted state of one case.
    """

    try:
        state = load_case(
            case_id
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve the SOC case.",
        ) from error

    if state is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    return state


@app.post(
    "/cases/{case_id}/approve",
    response_model=SOCSharedState,
)
def approve_remediation(
    case_id: str,
    request: HumanReviewRequest,
) -> SOCSharedState:
    """
    Record SOC analyst approval.

    Approval does not automatically execute
    remediation actions.
    """

    try:
        return approve_case(
            case_id=case_id,
            analyst=request.analyst,
            reason=request.reason,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to record remediation approval."
            ),
        ) from error


@app.post(
    "/cases/{case_id}/reject",
    response_model=SOCSharedState,
)
def reject_remediation(
    case_id: str,
    request: HumanReviewRequest,
) -> SOCSharedState:
    """
    Record SOC analyst rejection.
    """

    try:
        return reject_case(
            case_id=case_id,
            analyst=request.analyst,
            reason=request.reason,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to record remediation rejection."
            ),
        ) from error


@app.post(
    "/alerts",
    response_model=AlertSubmissionResponse,
)
def submit_alert(
    request: AlertSubmissionRequest,
) -> AlertSubmissionResponse:
    """
    Submit a normalized security alert to the
    SOC multi-agent workflow.

    The workflow persists its state to PostgreSQL
    while processing.
    """

    case_id = (
        request.case_id.strip()
        if request.case_id
        else f"case-{uuid4()}"
    )

    if not case_id:
        raise HTTPException(
            status_code=400,
            detail="case_id must not be empty.",
        )

    existing_case = load_case(
        case_id
    )

    if existing_case is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "A case with this case_id "
                "already exists."
            ),
        )

    flow = SOCSupervisorFlow()

    flow.state.case_id = case_id
    flow.state.alert = request.alert

    try:
        result = flow.kickoff()

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="SOC workflow processing failed.",
        ) from error

    if isinstance(
        result,
        dict,
    ):
        result_data = result

    else:
        result_data = {}

    return AlertSubmissionResponse(
        case_id=case_id,
        status=flow.state.status.value,
        route=result_data.get(
            "route"
        ),
        approval_required=result_data.get(
            "approval_required"
        ),
        performance=result_data.get(
            "performance"
        ),
    )