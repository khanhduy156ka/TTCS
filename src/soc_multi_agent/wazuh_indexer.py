from typing import Any, Literal

import httpx

from soc_multi_agent.config import settings
from soc_multi_agent.services.normalizer import normalize_wazuh_alert


INDEX_SEARCH_PATH = "/wazuh-alerts-*/_search"
SortOrder = Literal["asc", "desc"]

DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
DEFENDER_REMEDIATION_EVENT_ID = "1117"


def search_alerts(
    query: dict[str, Any],
    size: int = 10,
    sort_order: SortOrder = "desc",
) -> list[dict]:
    """Execute a search against the Wazuh Indexer."""
    if size < 1:
        raise ValueError("size must be greater than 0.")
    if size > 1000:
        raise ValueError("size must not exceed 1000.")
    if sort_order not in {"asc", "desc"}:
        raise ValueError("sort_order must be 'asc' or 'desc'.")

    request_body = {
        "size": size,
        "sort": [{"timestamp": {"order": sort_order}}],
        "query": query,
    }

    with httpx.Client(
        base_url=settings.wazuh_indexer_url,
        auth=(
            settings.wazuh_indexer_user,
            settings.wazuh_indexer_password,
        ),
        verify=settings.wazuh_verify_ssl,
        timeout=15.0,
    ) as client:
        response = client.post(
            INDEX_SEARCH_PATH,
            json=request_body,
        )
        response.raise_for_status()
        data = response.json()

    hits = data.get("hits", {}).get("hits", [])
    return [
        hit["_source"]
        for hit in hits
        if "_source" in hit
    ]


def _build_alert_query(
    *,
    min_rule_level: int | None,
    agent_name: str | None,
    timestamp_gte: str | None = None,
) -> dict[str, Any]:
    """Build the common query used by recent and incremental reads."""
    filters: list[dict] = []
    must: list[dict] = []

    if min_rule_level is not None:
        filters.append(
            {
                "range": {
                    "rule.level": {
                        "gte": min_rule_level
                    }
                }
            }
        )

    if timestamp_gte is not None:
        filters.append(
            {
                "range": {
                    "timestamp": {
                        "gte": timestamp_gte
                    }
                }
            }
        )

    if agent_name:
        must.append(
            {
                "match": {
                    "agent.name": agent_name
                }
            }
        )

    if not filters and not must:
        return {"match_all": {}}

    bool_query: dict[str, list[dict]] = {}

    if filters:
        bool_query["filter"] = filters

    if must:
        bool_query["must"] = must

    return {"bool": bool_query}


def get_recent_alerts(
    size: int = 10,
    min_rule_level: int | None = 5,
    agent_name: str | None = None,
) -> list[dict]:
    """Retrieve recent Wazuh alerts, newest first."""
    query = _build_alert_query(
        min_rule_level=min_rule_level,
        agent_name=agent_name,
    )

    return search_alerts(
        query=query,
        size=size,
        sort_order="desc",
    )


def get_alerts_since(
    *,
    timestamp: str,
    size: int = 100,
    min_rule_level: int | None = 5,
    agent_name: str | None = None,
) -> list[dict]:
    """
    Retrieve alerts at or after a watermark timestamp, oldest first.

    The ingestion layer remembers IDs already handled at the exact
    watermark timestamp so same-timestamp events are not lost.
    """
    if not timestamp:
        raise ValueError(
            "timestamp must not be empty."
        )

    query = _build_alert_query(
        min_rule_level=min_rule_level,
        agent_name=agent_name,
        timestamp_gte=timestamp,
    )

    return search_alerts(
        query=query,
        size=size,
        sort_order="asc",
    )


def get_defender_remediation_alerts(
    *,
    detection_id: str,
    timestamp: str,
    agent_name: str | None,
    size: int = 1000,
) -> list[dict]:
    """
    Tìm sự kiện remediation của Microsoft Defender liên quan đến một detection.

    Event 1116 (detection) và Event 1117 (remediation) dùng chung
    "detection ID". Event 1117 có thể có Wazuh rule level thấp hơn
    ngưỡng ingestion chính, nên helper này truy vấn mọi rule level
    rồi đối chiếu cục bộ.

    Cơ chế này áp dụng chung cho các detection của Microsoft Defender.
    """
    if not detection_id:
        return []

    candidates = get_alerts_since(
        timestamp=timestamp,
        size=size,
        min_rule_level=None,
        agent_name=agent_name,
    )

    matches: list[dict] = []

    for raw_alert in candidates:
        data = raw_alert.get("data", {})
        win = data.get("win", {})
        system = win.get("system", {})
        eventdata = win.get("eventdata", {})

        if not isinstance(eventdata, dict):
            continue

        provider_name = str(
            system.get("providerName", "")
        )
        event_id = str(
            system.get("eventID", "")
        )
        candidate_detection_id = str(
            eventdata.get("detection ID", "")
        )

        if (
            provider_name == DEFENDER_PROVIDER
            and event_id
            == DEFENDER_REMEDIATION_EVENT_ID
            and candidate_detection_id
            == detection_id
        ):
            matches.append(raw_alert)

    return matches


def get_failed_login_alerts(
    size: int = 5,
    agent_name: str = "WIN-11",
) -> list[dict]:
    """Retrieve Windows failed-logon alerts for regression testing."""
    query = {
        "bool": {
            "must": [
                {
                    "match": {
                        "agent.name": agent_name
                    }
                },
                {
                    "match": {
                        "data.win.system.eventID": "4625"
                    }
                },
            ]
        }
    }

    return search_alerts(
        query=query,
        size=size,
        sort_order="desc",
    )


def main() -> None:
    """Manual connectivity and normalization test. No LLM is called."""
    alerts = get_recent_alerts(
        size=5,
        min_rule_level=5,
        agent_name="WIN-11",
    )

    print(
        f"Found {len(alerts)} recent alerts "
        "for WIN-11\n"
    )

    for index, raw_alert in enumerate(
        alerts,
        start=1,
    ):
        try:
            normalized = normalize_wazuh_alert(
                raw_alert
            )
        except Exception as error:
            print(
                "===== NORMALIZATION FAILED "
                f"{index} ====="
            )
            print(
                f"Error: {error}\n"
            )
            continue

        print(
            f"===== NORMALIZED ALERT "
            f"{index} ====="
        )
        print(
            normalized.model_dump_json(
                indent=2
            )
        )
        print()


if __name__ == "__main__":
    main()
