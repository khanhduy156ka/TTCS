import psycopg
from psycopg import Connection
from psycopg.types.json import Jsonb

from soc_multi_agent.config import settings
from soc_multi_agent.schemas.state import SOCSharedState


def get_connection() -> Connection:
    """
    Create a PostgreSQL connection using the project's
    configured application account.
    """

    return psycopg.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        dbname=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
    )


def save_case(
    state: SOCSharedState,
) -> None:
    """
    Persist the complete validated SOC shared state.

    If the case already exists, its state is updated.
    """

    if not state.case_id:
        raise ValueError(
            "case_id is required before saving a case"
        )

    alert_id = None

    if state.alert is not None:
        alert_id = state.alert.alert_id

    state_data = state.model_dump(
        mode="json",
    )

    query = """
        INSERT INTO soc_cases (
            case_id,
            status,
            alert_id,
            state
        )
        VALUES (
            %s,
            %s,
            %s,
            %s
        )
        ON CONFLICT (case_id)
        DO UPDATE SET
            status = EXCLUDED.status,
            alert_id = EXCLUDED.alert_id,
            state = EXCLUDED.state,
            updated_at = NOW()
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                (
                    state.case_id,
                    state.status.value,
                    alert_id,
                    Jsonb(state_data),
                ),
            )


def load_case(
    case_id: str,
) -> SOCSharedState | None:
    """
    Load a persisted case and reconstruct SOCSharedState.

    Returns None when the case does not exist.
    """

    query = """
        SELECT state
        FROM soc_cases
        WHERE case_id = %s
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                (case_id,),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return SOCSharedState.model_validate(
        row[0]
    )


def list_cases(
    limit: int = 50,
    status: str | None = None,
) -> list[dict]:
    """
    Return recent SOC cases for dashboards and analyst views.

    The complete shared state remains stored in JSONB, while
    this query extracts only the summary fields needed for a
    case list.
    """

    if limit < 1:
        raise ValueError(
            "limit must be greater than zero"
        )

    if status is None:
        query = """
            SELECT
                case_id,
                status,
                alert_id,
                state->'triage'->>'priority' AS priority,
                state->'triage'->>'category' AS category,
                state->'alert'->>'agent_name' AS agent_name,
                state->'alert'->>'computer' AS computer,
                state->'alert'->>'rule_description'
                    AS rule_description,
                created_at,
                updated_at
            FROM soc_cases
            ORDER BY updated_at DESC
            LIMIT %s
        """

        parameters = (
            limit,
        )

    else:
        query = """
            SELECT
                case_id,
                status,
                alert_id,
                state->'triage'->>'priority' AS priority,
                state->'triage'->>'category' AS category,
                state->'alert'->>'agent_name' AS agent_name,
                state->'alert'->>'computer' AS computer,
                state->'alert'->>'rule_description'
                    AS rule_description,
                created_at,
                updated_at
            FROM soc_cases
            WHERE status = %s
            ORDER BY updated_at DESC
            LIMIT %s
        """

        parameters = (
            status,
            limit,
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                parameters,
            )

            rows = cursor.fetchall()

    return [
        {
            "case_id": row[0],
            "status": row[1],
            "alert_id": row[2],
            "priority": row[3],
            "category": row[4],
            "agent_name": row[5],
            "computer": row[6],
            "rule_description": row[7],
            "created_at": row[8],
            "updated_at": row[9],
        }
        for row in rows
    ]


def delete_case(
    case_id: str,
) -> bool:
    """
    Delete a case.

    Intended primarily for development and testing.
    Returns True if a row was deleted.
    """

    query = """
        DELETE FROM soc_cases
        WHERE case_id = %s
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                query,
                (case_id,),
            )

            deleted = cursor.rowcount

    return deleted > 0