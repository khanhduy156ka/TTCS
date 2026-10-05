import json
from typing import Any

from pydantic import BaseModel

from soc_multi_agent.rag.embedding import embed_text
from soc_multi_agent.rag.repository import retrieve_soc_context
from soc_multi_agent.rag.schemas import RetrievedChunk
from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EnrichmentAssessment,
    EnrichmentResult,
)
from soc_multi_agent.schemas.triage import TriageResult


_MAX_FIELD_CHARS = 1200
_MAX_QUERY_CHARS = 6000

_ALERT_QUERY_FIELDS = (
    "rule_id",
    "rule_level",
    "rule_description",
    "rule_groups",
    "channel",
    "provider_name",
    "event_id",
    "mitre_ids",
    "script_block_text",
    "base64_decodings",
    "fim_event",
    "fim_path",
    "fim_mode",
    "fim_diff",
    "fim_changed_attributes",
    "fim_sha256_before",
    "fim_sha256_after",
)

_TRIAGE_QUERY_FIELDS = (
    "category",
    "priority",
    "suspicious",
    "summary",
    "evidence",
    "recommended_next_step",
)

_ENRICHMENT_QUERY_FIELDS = (
    "mitre_techniques",
    "threat_intel",
)

_ASSESSMENT_QUERY_FIELDS = (
    "risk_level",
    "confidence",
    "relevant_findings",
    "inconsistencies",
    "requires_investigation",
    "summary",
    "recommended_next_step",
)


def _model_data(
    model: BaseModel,
) -> dict[str, Any]:
    return model.model_dump(
        mode="json",
        exclude_none=True,
    )


def _compact_value(
    value: Any,
) -> str:
    if isinstance(
        value,
        (dict, list, tuple),
    ):
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    else:
        rendered = str(value)

    rendered = " ".join(
        rendered.split()
    )

    if len(rendered) > _MAX_FIELD_CHARS:
        return (
            rendered[:_MAX_FIELD_CHARS]
            + "..."
        )

    return rendered


def _append_selected_fields(
    lines: list[str],
    *,
    prefix: str,
    data: dict[str, Any],
    fields: tuple[str, ...],
) -> None:
    for field in fields:
        if field not in data:
            continue

        value = data[field]

        if value in (
            None,
            "",
            [],
            {},
        ):
            continue

        lines.append(
            f"{prefix}.{field}: "
            f"{_compact_value(value)}"
        )


def build_investigation_query(
    alert: NormalizedAlert,
    triage: TriageResult,
    enrichment: EnrichmentResult,
    enrichment_assessment: EnrichmentAssessment,
) -> str:
    """
    Build a deterministic, bounded retrieval query from case data.

    The query contains high-signal event and analysis fields only.
    It is used for knowledge retrieval, not as incident evidence.
    """

    lines = [
        (
            "Retrieve the most relevant SOC investigation "
            "playbook and procedure guidance for this case."
        ),
        f"alert.alert_id: {alert.alert_id}",
    ]

    _append_selected_fields(
        lines,
        prefix="alert",
        data=_model_data(alert),
        fields=_ALERT_QUERY_FIELDS,
    )

    _append_selected_fields(
        lines,
        prefix="triage",
        data=_model_data(triage),
        fields=_TRIAGE_QUERY_FIELDS,
    )

    _append_selected_fields(
        lines,
        prefix="enrichment",
        data=_model_data(enrichment),
        fields=_ENRICHMENT_QUERY_FIELDS,
    )

    _append_selected_fields(
        lines,
        prefix="enrichment_assessment",
        data=_model_data(
            enrichment_assessment
        ),
        fields=_ASSESSMENT_QUERY_FIELDS,
    )

    query = "\n".join(lines)

    if len(query) > _MAX_QUERY_CHARS:
        query = (
            query[:_MAX_QUERY_CHARS]
            + "..."
        )

    return query


def retrieve_investigation_knowledge(
    query: str,
) -> list[RetrievedChunk]:
    """
    Retrieve bounded SOC knowledge for Investigation.

    Playbook and procedure collections are independently gated by
    the locked RAG v1 retriever. The embedding itself is not stored
    in case state.
    """

    normalized_query = query.strip()

    if not normalized_query:
        raise ValueError(
            "RAG retrieval query must not be empty."
        )

    query_embedding = embed_text(
        normalized_query
    )

    return retrieve_soc_context(
        query_embedding,
        playbook_chunks=2,
        procedure_chunks=1,
    )
