import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from soc_multi_agent.schemas.state import INGESTION_HANDOFF_STATUSES
from soc_multi_agent.services.alert_filter import get_candidate_reasons
from soc_multi_agent.services.normalizer import normalize_wazuh_alert
from soc_multi_agent.wazuh_indexer import (
    get_alerts_since,
    get_defender_remediation_alerts,
    get_recent_alerts,
)


DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_POLL_INTERVAL = 15
DEFAULT_API_TIMEOUT_SECONDS = 300.0
DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
DEFENDER_DETECTION_EVENT_ID = "1116"
CORRELATION_RETRY_COUNT = 8
CORRELATION_RETRY_DELAY_SECONDS = 1.5

DEFAULT_STATE_FILE = (
    Path(__file__).resolve().parents[2]
    / ".runtime"
    / "wazuh_ingestion_state.json"
)


def build_case_id(alert_id: str) -> str:
    """Build the deterministic FastAPI case ID for one Wazuh alert."""
    return f"case-wazuh-{alert_id}"


def _defender_detection_id(
    raw_alert: dict[str, Any],
) -> str | None:
    """
    Trả về detection ID ổn định của Microsoft Defender cho Event 1116.

    Việc nhận diện dựa trên provider và event ID, không phụ thuộc
    tên mối đe dọa nên áp dụng chung cho các detection của Defender.
    """
    data = raw_alert.get("data", {})
    win = data.get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    if not isinstance(eventdata, dict):
        return None

    provider_name = str(
        system.get("providerName", "")
    )
    event_id = str(
        system.get("eventID", "")
    )

    if (
        provider_name != DEFENDER_PROVIDER
        or event_id
        != DEFENDER_DETECTION_EVENT_ID
    ):
        return None

    detection_id = eventdata.get(
        "detection ID"
    )

    if detection_id is None:
        return None

    normalized_id = str(
        detection_id
    ).strip()

    return normalized_id or None


def _collect_correlated_events(
    raw_alert: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Collect lower-level events that belong to the same security case.

    Today the deterministic correlation supported here is Microsoft
    Defender Event 1116 -> Event 1117 by "detection ID". The returned
    data is attached to the normalized alert and is not independently
    submitted as another AI case.
    """
    detection_id = _defender_detection_id(
        raw_alert
    )

    if detection_id is None:
        return []

    timestamp = _raw_alert_timestamp(
        raw_alert
    )
    agent = raw_alert.get(
        "agent",
        {},
    )
    agent_name = agent.get("name")

    for attempt in range(
        CORRELATION_RETRY_COUNT
    ):
        related = (
            get_defender_remediation_alerts(
                detection_id=detection_id,
                timestamp=timestamp,
                agent_name=agent_name,
            )
        )

        if related:
            print(
                "  Correlated Defender "
                f"remediation events: "
                f"{len(related)}"
            )
            return related

        if (
            attempt
            < CORRELATION_RETRY_COUNT - 1
        ):
            time.sleep(
                CORRELATION_RETRY_DELAY_SECONDS
            )

    print(
        "  Correlated Defender remediation "
        "event not found within the correlation wait window; "
        "continuing with detection evidence only. Triage must "
        "treat remediation status as unresolved."
    )
    return []


def submit_alert(
    client: httpx.Client,
    api_url: str,
    raw_alert: dict[str, Any],
) -> str:
    """Normalize, correlate, and submit one Wazuh alert to FastAPI."""
    correlated_events = (
        _collect_correlated_events(
            raw_alert
        )
    )

    normalized = normalize_wazuh_alert(
        raw_alert,
        correlated_events=correlated_events,
    )
    case_id = build_case_id(
        normalized.alert_id
    )

    payload = {
        "case_id": case_id,
        "alert": normalized.model_dump(
            mode="json"
        ),
    }

    response = client.post(
        f"{api_url.rstrip('/')}/alerts",
        json=payload,
    )

    if response.status_code == 409:
        body = response.json()
        detail = body.get("detail") if isinstance(body, dict) else None
        if (
            isinstance(detail, dict)
            and detail.get("code") == "duplicate_completed"
            and detail.get("case_id") == case_id
            and isinstance(detail.get("status"), str)
            and detail["status"] in INGESTION_HANDOFF_STATUSES
        ):
            return "duplicate"
        raise ValueError("API did not confirm a completed duplicate.")

    response.raise_for_status()
    body = response.json()
    if (
        not isinstance(body, dict)
        or body.get("case_id") != case_id
        or not isinstance(body.get("status"), str)
        or body["status"] not in INGESTION_HANDOFF_STATUSES
    ):
        raise ValueError("API did not confirm a completed ingestion handoff.")
    return "processed"


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 Wazuh timestamp as an aware datetime."""
    normalized = value.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _raw_alert_id(
    raw_alert: dict[str, Any],
) -> str:
    return str(
        raw_alert.get(
            "id",
            "<missing-id>",
        )
    )


def _raw_alert_timestamp(
    raw_alert: dict[str, Any],
) -> str:
    timestamp = raw_alert.get("timestamp")

    if not isinstance(timestamp, str):
        raise ValueError(
            "Wazuh alert is missing a valid timestamp."
        )

    return timestamp


def _new_checkpoint(
    *,
    timestamp: str,
    alert_ids_at_timestamp: set[str],
    agent_name: str | None,
    min_rule_level: int,
) -> dict[str, Any]:
    return {
        "version": 1,
        "timestamp": timestamp,
        "alert_ids_at_timestamp": sorted(
            alert_ids_at_timestamp
        ),
        "agent_name": agent_name,
        "min_rule_level": min_rule_level,
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }


def load_checkpoint(
    *,
    state_file: Path,
    agent_name: str | None,
    min_rule_level: int,
) -> dict[str, Any] | None:
    """Load a saved watermark for the same Wazuh stream."""
    if not state_file.exists():
        return None

    try:
        data = json.loads(
            state_file.read_text(
                encoding="utf-8",
            )
        )

        timestamp = data.get("timestamp")
        alert_ids = data.get(
            "alert_ids_at_timestamp",
            [],
        )

        if not isinstance(timestamp, str):
            raise ValueError(
                "missing timestamp"
            )

        if not isinstance(alert_ids, list):
            raise ValueError(
                "invalid alert_ids_at_timestamp"
            )

        _parse_timestamp(timestamp)

    except Exception as error:
        raise ValueError(
            "Checkpoint could not be loaded; refusing to create a new baseline."
        ) from error

    if (
        data.get("agent_name") != agent_name
        or data.get("min_rule_level")
        != min_rule_level
    ):
        raise ValueError(
            "Checkpoint stream settings differ; refusing to create a new baseline."
        )

    return _new_checkpoint(
        timestamp=timestamp,
        alert_ids_at_timestamp={
            str(item)
            for item in alert_ids
        },
        agent_name=agent_name,
        min_rule_level=min_rule_level,
    )


def save_checkpoint(
    *,
    state_file: Path,
    checkpoint: dict[str, Any],
) -> None:
    """Persist the watermark atomically."""
    state_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    payload = dict(checkpoint)
    payload["updated_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    temporary_file = state_file.with_suffix(
        state_file.suffix + ".tmp"
    )

    temporary_file.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    temporary_file.replace(state_file)


def initialize_checkpoint(
    *,
    size: int,
    min_rule_level: int,
    agent_name: str | None,
) -> dict[str, Any]:
    """
    Baseline the watcher at the newest currently indexed alert.

    Historical alerts are not submitted on the first watch start.
    """
    baseline_size = min(
        max(size, 100),
        1000,
    )

    recent_alerts = get_recent_alerts(
        size=baseline_size,
        min_rule_level=min_rule_level,
        agent_name=agent_name,
    )

    if not recent_alerts:
        return _new_checkpoint(
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(
                timespec="milliseconds"
            ),
            alert_ids_at_timestamp=set(),
            agent_name=agent_name,
            min_rule_level=min_rule_level,
        )

    newest_timestamp = _raw_alert_timestamp(
        recent_alerts[0]
    )
    newest_time = _parse_timestamp(
        newest_timestamp
    )

    ids_at_newest_timestamp = {
        _raw_alert_id(raw_alert)
        for raw_alert in recent_alerts
        if (
            _parse_timestamp(
                _raw_alert_timestamp(
                    raw_alert
                )
            )
            == newest_time
        )
    }

    return _new_checkpoint(
        timestamp=newest_timestamp,
        alert_ids_at_timestamp=(
            ids_at_newest_timestamp
        ),
        agent_name=agent_name,
        min_rule_level=min_rule_level,
    )


def advance_checkpoint(
    *,
    checkpoint: dict[str, Any],
    raw_alert: dict[str, Any],
) -> None:
    """Advance the in-memory watermark after one safely handled alert."""
    current_timestamp = str(
        checkpoint["timestamp"]
    )
    alert_timestamp = _raw_alert_timestamp(
        raw_alert
    )

    current_time = _parse_timestamp(
        current_timestamp
    )
    alert_time = _parse_timestamp(
        alert_timestamp
    )
    alert_id = _raw_alert_id(
        raw_alert
    )

    if alert_time > current_time:
        checkpoint["timestamp"] = (
            alert_timestamp
        )
        checkpoint[
            "alert_ids_at_timestamp"
        ] = [alert_id]
        return

    if alert_time == current_time:
        ids = {
            str(item)
            for item in checkpoint.get(
                "alert_ids_at_timestamp",
                [],
            )
        }

        ids.add(alert_id)

        checkpoint[
            "alert_ids_at_timestamp"
        ] = sorted(ids)


def fetch_new_alerts(
    *,
    checkpoint: dict[str, Any],
    size: int,
    min_rule_level: int,
    agent_name: str | None,
) -> list[dict]:
    """Fetch only alerts not already covered by the watermark."""
    watermark_timestamp = str(
        checkpoint["timestamp"]
    )
    watermark_time = _parse_timestamp(
        watermark_timestamp
    )

    seen_ids = {
        str(item)
        for item in checkpoint.get(
            "alert_ids_at_timestamp",
            [],
        )
    }

    # Query cung timestamp bang gte va lay du them slot de cac ID da xu ly tai watermark khong chiem het batch
    query_size = min(
        1000,
        size + len(seen_ids),
    )

    raw_alerts = get_alerts_since(
        timestamp=watermark_timestamp,
        size=query_size,
        min_rule_level=min_rule_level,
        agent_name=agent_name,
    )

    new_alerts: list[dict] = []

    for raw_alert in raw_alerts:
        alert_timestamp = (
            _raw_alert_timestamp(
                raw_alert
            )
        )
        alert_time = _parse_timestamp(
            alert_timestamp
        )
        alert_id = _raw_alert_id(
            raw_alert
        )

        if alert_time < watermark_time:
            continue

        if (
            alert_time == watermark_time
            and alert_id in seen_ids
        ):
            continue

        new_alerts.append(
            raw_alert
        )

        if len(new_alerts) >= size:
            break

    return new_alerts


def _print_alert_header(
    *,
    index: int,
    total: int,
    raw_alert: dict[str, Any],
) -> None:
    rule = raw_alert.get(
        "rule",
        {},
    )

    description = str(
        rule.get(
            "description",
            "<no-description>",
        )
    )

    level = rule.get(
        "level",
        "?",
    )

    print(
        f"[{index}/{total}] "
        f"{_raw_alert_id(raw_alert)}"
    )
    print(
        f"  Level: {level}"
    )
    print(
        f"  Description: {description}"
    )


def process_alerts(
    *,
    raw_alerts: list[dict],
    api_url: str,
    dry_run: bool,
    checkpoint: dict[str, Any] | None = None,
    state_file: Path | None = None,
    persist_checkpoint: bool = False,
    stop_on_failure: bool = False,
) -> dict[str, int]:
    """Filter and optionally submit one supplied alert batch."""
    candidate_count = 0
    skipped_count = 0
    processed_count = 0
    duplicate_count = 0
    failed_count = 0

    timeout = httpx.Timeout(
        timeout=DEFAULT_API_TIMEOUT_SECONDS,
        connect=5.0,
    )

    with httpx.Client(
        timeout=timeout
    ) as client:
        for index, raw_alert in enumerate(
            raw_alerts,
            start=1,
        ):
            _print_alert_header(
                index=index,
                total=len(raw_alerts),
                raw_alert=raw_alert,
            )

            reasons = get_candidate_reasons(
                raw_alert
            )

            handled = False

            if not reasons:
                skipped_count += 1
                print(
                    "  Decision: SKIP"
                )
                handled = True

            else:
                candidate_count += 1
                print(
                    "  Decision: CANDIDATE"
                )

                for reason in reasons:
                    print(
                        f"  Reason: {reason}"
                    )

                if dry_run:
                    print(
                        "  Action: DRY-RUN ONLY"
                    )
                    handled = True

                else:
                    try:
                        result = submit_alert(
                            client=client,
                            api_url=api_url,
                            raw_alert=raw_alert,
                        )

                    except Exception as error:
                        failed_count += 1

                        print(
                            f"  Action: FAILED - "
                            f"{error}"
                        )
                        print()

                        if stop_on_failure or checkpoint is not None:
                            print(
                                "Stopping this batch so "
                                "the failed alert can be "
                                "retried next cycle."
                            )
                            print()
                            break

                        continue

                    if result == "duplicate":
                        duplicate_count += 1
                        print(
                            "  Action: "
                            "DUPLICATE - SKIPPED"
                        )

                    else:
                        processed_count += 1
                        print(
                            "  Action: PROCESSED"
                        )

                    handled = True

            if (
                handled
                and checkpoint is not None
            ):
                advance_checkpoint(
                    checkpoint=checkpoint,
                    raw_alert=raw_alert,
                )

                if (
                    persist_checkpoint
                    and state_file is not None
                ):
                    save_checkpoint(
                        state_file=state_file,
                        checkpoint=checkpoint,
                    )

            print()

    summary = {
        "fetched": len(raw_alerts),
        "candidates": candidate_count,
        "skipped": skipped_count,
        "processed": processed_count,
        "duplicates": duplicate_count,
        "failed": failed_count,
    }

    print(
        "===== INGESTION SUMMARY ====="
    )
    print(
        f"Fetched:    "
        f"{summary['fetched']}"
    )
    print(
        f"Candidates: "
        f"{summary['candidates']}"
    )
    print(
        f"Skipped:    "
        f"{summary['skipped']}"
    )

    if not dry_run:
        print(
            f"Processed:  "
            f"{summary['processed']}"
        )
        print(
            f"Duplicates: "
            f"{summary['duplicates']}"
        )
        print(
            f"Failed:     "
            f"{summary['failed']}"
        )

    return summary


def ingest_recent_alerts(
    *,
    size: int = 10,
    min_rule_level: int = 5,
    agent_name: str | None = None,
    api_url: str = DEFAULT_API_URL,
    dry_run: bool = False,
) -> dict[str, int]:
    """
    One-shot/manual mode. It keeps the old recent-alert behavior and
    never reads or changes the live watcher watermark.
    """
    raw_alerts = get_recent_alerts(
        size=size,
        min_rule_level=min_rule_level,
        agent_name=agent_name,
    )

    print(
        f"Fetched "
        f"{len(raw_alerts)} "
        f"recent Wazuh alerts.\n"
    )

    return process_alerts(
        raw_alerts=raw_alerts,
        api_url=api_url,
        dry_run=dry_run,
    )


def run_watch_loop(
    *,
    size: int,
    min_rule_level: int,
    agent_name: str | None,
    api_url: str,
    poll_interval: int,
    dry_run: bool,
    state_file: Path,
    reset_watermark: bool,
) -> None:
    """Continuously ingest only alerts newer than the watermark."""
    if dry_run and reset_watermark:
        raise ValueError("--dry-run cannot be combined with --reset-watermark.")

    print(
        "===== WAZUH LIVE INGESTION ====="
    )
    print(
        f"Agent: "
        f"{agent_name or 'ALL'}"
    )
    print(
        f"Batch size: {size}"
    )
    print(
        f"Minimum Wazuh level: "
        f"{min_rule_level}"
    )
    print(
        f"Polling interval: "
        f"{poll_interval} seconds"
    )
    print(
        f"FastAPI: {api_url}"
    )
    print(
        f"FastAPI timeout: "
        f"{int(DEFAULT_API_TIMEOUT_SECONDS)} "
        f"seconds"
    )
    print(
        f"Dry-run: {dry_run}"
    )
    print(
        f"Checkpoint: "
        f"{state_file}\n"
    )

    if (
        reset_watermark
        and state_file.exists()
    ):
        state_file.unlink()
        print(
            "Existing watermark reset."
        )

    checkpoint = load_checkpoint(
        state_file=state_file,
        agent_name=agent_name,
        min_rule_level=min_rule_level,
    )

    if checkpoint is None:
        checkpoint = initialize_checkpoint(
            size=size,
            min_rule_level=min_rule_level,
            agent_name=agent_name,
        )

        if not dry_run:
            save_checkpoint(
                state_file=state_file,
                checkpoint=checkpoint,
            )

        print(
            "Initialized live baseline at:"
        )

    else:
        print(
            "Resuming from persisted "
            "watermark:"
        )

    print(
        f"  Timestamp: "
        f"{checkpoint['timestamp']}"
    )
    print(
        "  IDs at timestamp: "
        f"{len(checkpoint.get('alert_ids_at_timestamp', []))}\n"
    )
    print(
        "Press Ctrl+C to stop.\n"
    )

    while True:
        try:
            poll_time = (
                datetime.now().astimezone()
            )

            print(
                "=" * 60
            )
            print(
                "Poll time:",
                poll_time.strftime(
                    "%Y-%m-%d %H:%M:%S %z"
                ),
            )
            print(
                "=" * 60
            )

            raw_alerts = fetch_new_alerts(
                checkpoint=checkpoint,
                size=size,
                min_rule_level=min_rule_level,
                agent_name=agent_name,
            )

            if not raw_alerts:
                print(
                    "No new Wazuh alerts "
                    "after watermark."
                )

            else:
                print(
                    f"Fetched "
                    f"{len(raw_alerts)} "
                    f"new Wazuh alerts.\n"
                )

                summary = process_alerts(
                    raw_alerts=raw_alerts,
                    api_url=api_url,
                    dry_run=dry_run,
                    checkpoint=checkpoint,
                    state_file=state_file,
                    persist_checkpoint=(
                        not dry_run
                    ),
                    stop_on_failure=True,
                )

                if summary["failed"] == 0:
                    print(
                        f"Watermark now: "
                        f"{checkpoint['timestamp']}"
                    )

        except KeyboardInterrupt:
            print(
                "\nWazuh live ingestion stopped."
            )
            return

        except Exception as error:
            print(
                f"Polling cycle failed: "
                f"{error}"
            )
            print(
                "The watcher will retry "
                "from the same watermark "
                "on the next cycle."
            )

        print(
            f"\nWaiting "
            f"{poll_interval} seconds "
            f"before next poll...\n"
        )

        try:
            time.sleep(
                poll_interval
            )

        except KeyboardInterrupt:
            print(
                "\nWazuh live ingestion stopped."
            )
            return


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch Wazuh alerts and submit "
            "security-relevant candidates "
            "to the SOC Multi-Agent API."
        )
    )

    parser.add_argument(
        "--size",
        type=int,
        default=10,
        help=(
            "Maximum alert batch size. "
            "In watch mode, a persistent "
            "watermark prevents old alerts "
            "from being scanned again."
        ),
    )

    parser.add_argument(
        "--min-level",
        type=int,
        default=5,
        help=(
            "Minimum Wazuh rule level "
            "fetched from the Indexer "
            "before candidate filtering."
        ),
    )

    parser.add_argument(
        "--agent",
        default=None,
        help=(
            "Optional Wazuh agent name to query. "
            "Omit this option to ingest alerts from all agents."
        ),
    )

    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=(
            "Base URL of the SOC "
            "FastAPI service."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Show candidate decisions "
            "without submitting alerts "
            "to FastAPI or persisting "
            "the live watermark."
        ),
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help=(
            "Continuously ingest only "
            "alerts newer than the "
            "watermark."
        ),
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL,
        help=(
            "Polling interval in seconds "
            "when --watch is enabled."
        ),
    )

    parser.add_argument(
        "--state-file",
        type=Path,
        default=DEFAULT_STATE_FILE,
        help=(
            "Path to the persistent "
            "watch-mode watermark file."
        ),
    )

    parser.add_argument(
        "--reset-watermark",
        action="store_true",
        help=(
            "Discard the saved watch "
            "watermark and create a new "
            "baseline at the newest "
            "currently indexed alert."
        ),
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.size < 1:
        raise ValueError(
            "--size must be greater than 0."
        )

    if args.size > 1000:
        raise ValueError(
            "--size must not exceed 1000."
        )

    if args.min_level < 0:
        raise ValueError(
            "--min-level must not be negative."
        )

    if args.interval < 5:
        raise ValueError(
            "--interval must be at least "
            "5 seconds."
        )

    if (
        args.reset_watermark
        and not args.watch
    ):
        raise ValueError(
            "--reset-watermark requires "
            "--watch."
        )

    if args.watch:
        run_watch_loop(
            size=args.size,
            min_rule_level=args.min_level,
            agent_name=args.agent,
            api_url=args.api_url,
            poll_interval=args.interval,
            dry_run=args.dry_run,
            state_file=args.state_file,
            reset_watermark=(
                args.reset_watermark
            ),
        )
        return

    ingest_recent_alerts(
        size=args.size,
        min_rule_level=args.min_level,
        agent_name=args.agent,
        api_url=args.api_url,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
