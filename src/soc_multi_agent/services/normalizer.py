import base64
import binascii
import re
from typing import Any

from soc_multi_agent.schemas.alert import NormalizedAlert


_FROM_BASE64_STRING_PATTERN = re.compile(
    r"""(?i)\bFromBase64String\s*\(\s*["']([A-Za-z0-9+/]{8,}={0,2})["']\s*\)"""
)

_ENCODED_COMMAND_PATTERN = re.compile(
    r"""(?i)(?:^|[\s;|&])-(?:EncodedCommand|Enc)\s+["']?([A-Za-z0-9+/]{8,}={0,2})["']?"""
)


def _is_reasonably_printable(
    value: str,
) -> bool:
    if not value:
        return False

    printable_count = sum(
        1
        for char in value
        if char.isprintable()
        or char in "\r\n\t"
    )

    return (
        printable_count / len(value)
    ) >= 0.90


def _decode_base64_text(
    candidate: str,
) -> str | None:
    if len(candidate) % 4 != 0:
        return None

    try:
        raw = base64.b64decode(
            candidate,
            validate=True,
        )
    except (
        binascii.Error,
        ValueError,
    ):
        return None

    if not raw:
        return None

    for encoding in (
        "utf-8",
        "utf-16-le",
    ):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue

        decoded = decoded.strip()

        if (
            decoded
            and _is_reasonably_printable(decoded)
        ):
            return decoded

    return None


def _extract_base64_decodings(
    script_block_text: str | None,
) -> dict[str, str]:
    if not script_block_text:
        return {}

    normalized_text = (
        script_block_text
        .replace('\\"', '"')
        .replace("\\'", "'")
    )

    candidates = [
        *_FROM_BASE64_STRING_PATTERN.findall(
            normalized_text
        ),
        *_ENCODED_COMMAND_PATTERN.findall(
            normalized_text
        ),
    ]

    decodings: dict[str, str] = {}

    for candidate in dict.fromkeys(candidates):
        decoded = _decode_base64_text(
            candidate
        )

        if decoded is not None:
            decodings[candidate] = decoded

    return decodings


def _optional_text(
    value: Any,
) -> str | None:
    if value is None:
        return None

    text = str(value).strip()

    return text or None


def _string_list(
    value: Any,
) -> list[str]:
    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set),
    ):
        result: list[str] = []

        for item in value:
            text = _optional_text(item)

            if (
                text
                and text not in result
            ):
                result.append(text)

        return result

    text = _optional_text(value)

    return [text] if text else []


def _optional_bool(
    value: Any,
) -> bool | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False

    text = str(value).strip().lower()

    if text in {
        "true",
        "1",
        "yes",
        "y",
        "on",
    }:
        return True

    if text in {
        "false",
        "0",
        "no",
        "n",
        "off",
    }:
        return False

    return None


def _related_event_summary(
    raw: dict[str, Any],
) -> dict[str, Any]:
    """
    Preserve the security-relevant content of one related Wazuh event.

    The summary deliberately keeps provider-specific eventdata so future
    event sources can add useful fields without requiring a new schema
    field for every vendor-specific attribute.
    """
    rule = raw.get("rule", {})
    data = raw.get("data", {})
    win = data.get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    return {
        "alert_id": raw.get("id"),
        "timestamp": raw.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups", []),
        "event_id": system.get("eventID"),
        "provider_name": system.get("providerName"),
        "computer": system.get("computer"),
        "channel": system.get("channel"),
        "severity_value": system.get("severityValue"),
        "event_message": system.get("message"),
        "event_data": dict(eventdata)
        if isinstance(eventdata, dict)
        else {},
    }


def normalize_wazuh_alert(
    raw: dict,
    correlated_events: list[dict[str, Any]] | None = None,
) -> NormalizedAlert:
    agent = raw.get("agent", {})
    manager = raw.get("manager", {})
    rule = raw.get("rule", {})

    data = raw.get("data", {})

    if not isinstance(data, dict):
        data = {}

    win = data.get("win", {})

    if not isinstance(win, dict):
        win = {}

    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    if not isinstance(system, dict):
        system = {}

    if not isinstance(eventdata, dict):
        eventdata = {}

    syscheck = raw.get("syscheck", {})

    if not isinstance(syscheck, dict):
        syscheck = {}

    changed_attributes = syscheck.get(
        "changed_attributes",
        [],
    )

    if not isinstance(
        changed_attributes,
        list,
    ):
        changed_attributes = []

    mitre = rule.get("mitre", {})

    if not isinstance(mitre, dict):
        mitre = {}

    script_block_text = (
        eventdata.get("scriptBlockText")
        or eventdata.get("ScriptBlockText")
    )

    script_block_id = (
        eventdata.get("scriptBlockId")
        or eventdata.get("ScriptBlockId")
    )

    related = [
        _related_event_summary(item)
        for item in (correlated_events or [])
    ]

    email_urls = _string_list(
        data.get("urls")
        if data.get("urls") is not None
        else data.get("url")
    )

    email_domains = _string_list(
        data.get("domains")
        if data.get("domains") is not None
        else data.get("domain")
    )

    return NormalizedAlert(
        alert_id=raw["id"],
        timestamp=raw["timestamp"],

        agent_id=agent["id"],
        agent_name=agent["name"],
        agent_ip=agent.get("ip"),

        manager_name=manager.get("name"),

        rule_id=rule["id"],
        rule_level=rule["level"],
        rule_description=rule["description"],
        rule_groups=rule.get("groups", []),

        event_id=system.get("eventID"),
        provider_name=system.get("providerName"),
        computer=system.get("computer"),
        channel=system.get("channel"),
        severity_value=system.get(
            "severityValue"
        ),

        subject_user=eventdata.get(
            "subjectUserName"
        ),
        target_user=eventdata.get(
            "targetUserName"
        ),

        source_ip=eventdata.get(
            "ipAddress"
        ),
        source_port=eventdata.get(
            "ipPort"
        ),
        workstation_name=eventdata.get(
            "workstationName"
        ),

        logon_type=eventdata.get(
            "logonType"
        ),
        authentication_package=(
            eventdata.get(
                "authenticationPackageName"
            )
        ),

        process_name=eventdata.get(
            "processName"
        ),

        status=eventdata.get("status"),
        sub_status=eventdata.get(
            "subStatus"
        ),

        script_block_text=script_block_text,
        script_block_id=script_block_id,

        base64_decodings=(
            _extract_base64_decodings(
                script_block_text
            )
        ),

        event_message=system.get("message"),
        event_data=dict(eventdata),

        wazuh_location=raw.get("location"),
        full_log=raw.get("full_log"),

        fim_event=syscheck.get("event"),
        fim_path=syscheck.get("path"),
        fim_mode=syscheck.get("mode"),
        fim_diff=syscheck.get("diff"),
        fim_changed_attributes=[
            str(item)
            for item in changed_attributes
        ],

        fim_size_before=syscheck.get(
            "size_before"
        ),
        fim_size_after=syscheck.get(
            "size_after"
        ),

        fim_md5_before=syscheck.get(
            "md5_before"
        ),
        fim_md5_after=syscheck.get(
            "md5_after"
        ),
        fim_sha1_before=syscheck.get(
            "sha1_before"
        ),
        fim_sha1_after=syscheck.get(
            "sha1_after"
        ),
        fim_sha256_before=syscheck.get(
            "sha256_before"
        ),
        fim_sha256_after=syscheck.get(
            "sha256_after"
        ),

        fim_mtime_before=syscheck.get(
            "mtime_before"
        ),
        fim_mtime_after=syscheck.get(
            "mtime_after"
        ),

        syscheck_data=dict(syscheck),

        email_event_type=_optional_text(
            data.get("event_type")
        ),
        email_sender=_optional_text(
            data.get("sender")
        ),
        email_reply_to=_optional_text(
            data.get("reply_to")
        ),
        email_recipient=_optional_text(
            data.get("recipient")
        ),
        email_subject=_optional_text(
            data.get("subject")
        ),
        email_message_id=_optional_text(
            data.get("message_id")
        ),
        email_body_excerpt=_optional_text(
            data.get("body_excerpt")
        ),

        email_urls=email_urls,
        email_domains=email_domains,

        email_attachment_name=_optional_text(
            data.get("attachment_name")
        ),
        email_attachment_content_type=_optional_text(
            data.get("attachment_content_type")
        ),
        email_attachment_sha256=_optional_text(
            data.get("attachment_sha256")
        ),

        email_user_clicked=_optional_bool(
            data.get("user_clicked")
        ),
        email_attachment_executed=_optional_bool(
            data.get("attachment_executed")
        ),

        correlated_events=related,

        mitre_ids=mitre.get("id", []),
        mitre_techniques=mitre.get(
            "technique",
            [],
        ),
        mitre_tactics=mitre.get(
            "tactic",
            [],
        ),
    )
