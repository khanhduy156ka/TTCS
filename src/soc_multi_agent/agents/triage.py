import json
import re

from crewai import Agent, Crew, Process, Task

from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.triage import (
    TriagePriority,
    TriageResult,
)
from soc_multi_agent.services.llm_service import get_llm


DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
DEFENDER_DETECTION_EVENT_ID = "1116"
DEFENDER_REMEDIATION_EVENT_ID = "1117"

# Gioi han du lieu PowerShell dua vao LLM, ban day du van luu trong NormalizedAlert de phuc vu audit va xu ly phia sau
TRIAGE_SCRIPT_BLOCK_MAX_CHARS = 4000
TRIAGE_DECODED_VALUE_MAX_CHARS = 2000


def _bounded_text(
    value: str,
    max_chars: int,
) -> tuple[str, bool]:
    if len(value) <= max_chars:
        return value, False

    head_chars = max_chars * 3 // 4
    tail_chars = max_chars - head_chars

    bounded = (
        value[:head_chars]
        + "\n...[truncated for triage context]...\n"
        + value[-tail_chars:]
    )

    return bounded, True


def create_triage_agent() -> Agent:
    return Agent(
        role="SOC Triage Analyst",
        goal=(
            "Classify and prioritize security alerts using only "
            "the supplied evidence."
        ),
        backstory=(
            "You are a SOC triage analyst. "
            "You evaluate security alerts conservatively, distinguish "
            "facts from assumptions, and avoid escalating events without "
            "sufficient evidence."
        ),
        llm=get_llm("fast"),
        allow_delegation=False,
        verbose=True,
    )


def _build_triage_context(
    alert: NormalizedAlert,
) -> dict:
    """
    Tạo dữ liệu cảnh báo gọn để đưa vào LLM ở bước Triage.

    Bản đầy đủ vẫn được giữ trong Shared State và persistence. Hàm này chỉ
    loại dữ liệu trùng và giới hạn nội dung PowerShell lớn để tránh Event 4104
    vượt cửa sổ ngữ cảnh của mô hình.
    """
    context = alert.model_dump(
        mode="json"
    )

    event_data = context.get(
        "event_data"
    )

    if isinstance(event_data, dict):
        compact_event_data = dict(
            event_data
        )

        # Bo script_block_text bi lap trong event_data vi da co truong chuan hoa o cap cao hon
        for key in list(
            compact_event_data
        ):
            if key.casefold() == "scriptblocktext":
                compact_event_data.pop(
                    key,
                    None,
                )

        context["event_data"] = (
            compact_event_data
        )
        context.pop(
            "event_message",
            None,
        )

    script_block_text = context.get(
        "script_block_text"
    )

    if isinstance(
        script_block_text,
        str,
    ) and script_block_text:
        bounded_script, truncated = (
            _bounded_text(
                script_block_text,
                TRIAGE_SCRIPT_BLOCK_MAX_CHARS,
            )
        )

        context["script_block_text"] = (
            bounded_script
        )
        context[
            "script_block_text_original_length"
        ] = len(script_block_text)
        context[
            "script_block_text_truncated"
        ] = truncated

        # full_log thuong lap payload PowerShell, van giu de audit nhung khong dua them vao context cua LLM
        context.pop(
            "full_log",
            None,
        )

    base64_decodings = context.get(
        "base64_decodings"
    )

    if isinstance(
        base64_decodings,
        dict,
    ):
        compact_decodings: dict[str, str] = {}

        for candidate, decoded in (
            base64_decodings.items()
        ):
            decoded_text = str(decoded)
            bounded_decoded, _ = (
                _bounded_text(
                    decoded_text,
                    TRIAGE_DECODED_VALUE_MAX_CHARS,
                )
            )
            compact_decodings[
                str(candidate)
            ] = bounded_decoded

        context["base64_decodings"] = (
            compact_decodings
        )

    if context.get("fim_event"):
        # Cac truong FIM da co du before/after va diff can thiet, khong dua them Syscheck raw va full_log vao prompt
        context.pop(
            "syscheck_data",
            None,
        )
        context.pop(
            "full_log",
            None,
        )

    compact_correlated_events = []

    for event in context.get(
        "correlated_events",
        [],
    ):
        compact_event = dict(event)
        correlated_event_data = (
            compact_event.get(
                "event_data"
            )
        )

        if isinstance(
            correlated_event_data,
            dict,
        ):
            compact_data = dict(
                correlated_event_data
            )

            for key in list(
                compact_data
            ):
                if key.casefold() == "scriptblocktext":
                    compact_data.pop(
                        key,
                        None,
                    )

            compact_event[
                "event_data"
            ] = compact_data
            compact_event.pop(
                "event_message",
                None,
            )

        compact_correlated_events.append(
            compact_event
        )

    context[
        "correlated_events"
    ] = compact_correlated_events

    return context

def _is_encoded_powershell_alert(
    alert: NormalizedAlert,
) -> bool:
    """
    Nhận diện PowerShell có nội dung Base64 đã được normalizer giải mã xác định.

    Chuỗi đã giải mã là bằng chứng về nội dung quan sát được, không tự chứng minh
    rằng hoạt động đã được phê duyệt, hợp lệ hay độc hại.
    """
    if not alert.base64_decodings:
        return False

    provider = (alert.provider_name or "").casefold()
    channel = (alert.channel or "").casefold()

    return bool(
        alert.script_block_text
        or "powershell" in provider
        or "powershell" in channel
    )


def _normalize_rule_level_severity_wording(
    alert: NormalizedAlert,
    result: TriageResult,
) -> None:
    """Tách Wazuh rule_level khỏi Windows event-log severity_value."""
    if alert.severity_value is None:
        return

    level = str(alert.rule_level)
    severity = str(alert.severity_value)
    replacement = (
        f"Wazuh rule level is {level}; Windows event-log "
        f"severity_value is {severity}"
    )

    pattern = re.compile(
        rf"(?:Wazuh\s+)?rule\s+level\s+(?:is\s+)?"
        rf"{re.escape(level)}\s*\(\s*{re.escape(severity)}\s*\)",
        flags=re.IGNORECASE,
    )

    result.summary = pattern.sub(
        replacement,
        result.summary,
    )

    result.evidence = [
        pattern.sub(replacement, item)
        for item in result.evidence
    ]


def _apply_encoded_powershell_triage_guardrail(
    alert: NormalizedAlert,
    result: TriageResult,
) -> None:
    """
    Giữ đánh giá PowerShell có Base64 ở mức dựa trên bằng chứng quan sát được.

    Tên hoặc nội dung đã giải mã trông giống internal/test/lab không tự chứng minh
    rằng hoạt động đã được cho phép hay benign. Khi chưa có correlated evidence
    xác nhận authorization/baseline, case vẫn phải đi enrichment và investigation.
    """
    if (
        not _is_encoded_powershell_alert(alert)
        or alert.correlated_events
    ):
        return

    result.suspicious = True
    result.requires_enrichment = True
    result.requires_investigation = True

    cleaned_evidence: list[str] = []

    for item in result.evidence:
        lowered = item.casefold()
        unsupported_benign_inference = (
            (
                "decoded" in lowered
                or "base64" in lowered
            )
            and (
                "appears benign" in lowered
                or "known benign" in lowered
                or "known internal" in lowered
                or "internal identifier" in lowered
                or "lab environment identifier" in lowered
            )
        )

        if not unsupported_benign_inference:
            cleaned_evidence.append(item)

    for candidate, decoded in alert.base64_decodings.items():
        bounded_candidate, _ = _bounded_text(
            str(candidate),
            512,
        )
        bounded_decoded, _ = _bounded_text(
            str(decoded),
            512,
        )
        evidence = (
            "Deterministic Base64 decoding from the normalized alert: "
            f"'{bounded_candidate}' -> '{bounded_decoded}'. "
            "The decoded text alone does not establish authorization, "
            "legitimacy, or benign intent."
        )

        if evidence not in cleaned_evidence:
            cleaned_evidence.append(evidence)

    result.evidence = cleaned_evidence

    severity_clause = (
        f"Wazuh rule level is {alert.rule_level}."
    )

    if alert.severity_value is not None:
        severity_clause = (
            f"Wazuh rule level is {alert.rule_level}; Windows event-log "
            f"severity_value is {alert.severity_value}."
        )

    result.summary = (
        "The alert contains PowerShell script-block telemetry with "
        "deterministic Base64 decoding. The decoded text is observed "
        "content only and does not by itself establish that the execution "
        "was authorized, expected, or benign. "
        + severity_clause
        + " No correlated authorization, baseline, user/process, or "
        "surrounding-event evidence is supplied to establish legitimacy. "
        "The activity therefore remains suspicious and requires enrichment "
        "and investigation, without treating the encoded content alone as "
        "proof of malware or compromise."
    )

    result.recommended_next_step = (
        "Correlate process creation, parent process, user context, network, "
        "and surrounding endpoint telemetry for this PowerShell execution. "
        "Verify authorization or an approved baseline through independent "
        "evidence before classifying the activity as benign."
    )


def _defender_remediation_event(
    alert: NormalizedAlert,
) -> dict | None:
    for event in alert.correlated_events:
        if (
            str(event.get("event_id", ""))
            == DEFENDER_REMEDIATION_EVENT_ID
            and str(
                event.get(
                    "provider_name",
                    "",
                )
            )
            == DEFENDER_PROVIDER
        ):
            return event

    return None


def _build_email_triage_evidence(
    alert: NormalizedAlert,
) -> list[str]:
    """
    Tạo danh sách bằng chứng email từ telemetry đã chuẩn hóa.

    Metadata định tuyến, IOC hoặc hash tệp đính kèm không tự động được xem là
    bằng chứng kết luận độc hại.
    """
    evidence: list[str] = []

    if alert.email_event_type:
        evidence.append(
            f"Email event type: {alert.email_event_type}"
        )

    if alert.email_sender:
        evidence.append(
            f"Observed email sender: {alert.email_sender}"
        )

    if alert.email_reply_to:
        evidence.append(
            f"Observed Reply-To address: {alert.email_reply_to}"
        )

    if (
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    ):
        evidence.append(
            "The observed Sender and Reply-To addresses differ"
        )

    if alert.email_recipient:
        evidence.append(
            f"Observed email recipient: {alert.email_recipient}"
        )

    if alert.email_subject:
        evidence.append(
            f"Observed email subject: {alert.email_subject}"
        )

    for url in alert.email_urls:
        evidence.append(
            f"Observed email URL: {url}"
        )

    for domain in alert.email_domains:
        evidence.append(
            f"Observed email domain: {domain}"
        )

    if alert.email_attachment_name:
        attachment = (
            f"Observed attachment: {alert.email_attachment_name}"
        )

        if alert.email_attachment_content_type:
            attachment += (
                " ("
                f"{alert.email_attachment_content_type}"
                ")"
            )

        evidence.append(attachment)

    if alert.email_attachment_sha256:
        evidence.append(
            "Observed attachment SHA-256: "
            f"{alert.email_attachment_sha256}"
        )

    if alert.email_user_clicked is None:
        evidence.append(
            "No user-click state is supplied in the normalized telemetry"
        )
    else:
        evidence.append(
            "Supplied email telemetry states "
            f"user_clicked={str(alert.email_user_clicked).lower()}; "
            "Triage does not independently verify this state"
        )

    if alert.email_attachment_executed is None:
        evidence.append(
            "No attachment-execution state is supplied in the "
            "normalized telemetry"
        )
    else:
        evidence.append(
            "Supplied email telemetry states "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}; "
            "Triage does not independently verify this state"
        )

    if alert.rule_description:
        evidence.append(
            "Wazuh routing metadata: "
            f"{alert.rule_description}"
        )

    return evidence


def _build_email_triage_summary(
    alert: NormalizedAlert,
) -> str:
    parts = [
        "A structured email-security observation was routed for "
        "phishing investigation."
    ]

    if (
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    ):
        parts.append(
            "The observed Sender and Reply-To addresses differ."
        )

    if alert.email_subject:
        parts.append(
            f"The observed subject is '{alert.email_subject}'."
        )

    if alert.email_urls:
        parts.append(
            "The email telemetry contains "
            f"{len(alert.email_urls)} URL IOC"
            + (
                "."
                if len(alert.email_urls) == 1
                else "s."
            )
        )

    if alert.email_attachment_name:
        parts.append(
            "The telemetry records attachment "
            f"'{alert.email_attachment_name}'."
        )

    parts.append(
        "At triage time, these observations justify enrichment and "
        "investigation when routed by the analyst decision, but they do "
        "not by themselves establish spoofing, malicious attachment "
        "content, credential theft, execution, or endpoint compromise."
    )

    if (
        alert.email_user_clicked is None
        or alert.email_attachment_executed is None
    ):
        parts.append(
            "User interaction or attachment execution is not fully "
            "established by the supplied telemetry."
        )
    else:
        parts.append(
            "The supplied telemetry states "
            f"user_clicked={str(alert.email_user_clicked).lower()} and "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}; "
            "Triage does not independently verify those states."
        )

    return " ".join(parts)


def _build_email_triage_next_step(
    alert: NormalizedAlert,
) -> str:
    return (
        "Enrich the observed URL, domain, IP, and attachment hash IOCs "
        "with approved threat-intelligence sources. Review available "
        "email headers and authentication evidence such as SPF, DKIM, "
        "and DMARC before labeling the sender as spoofed. Correlate "
        "recipient endpoint, browser, proxy, DNS, and authentication "
        "telemetry where available to establish user interaction or "
        "compromise. Do not visit the untrusted URL or execute the "
        "attachment during triage."
    )


def _apply_email_triage_guardrail(
    alert: NormalizedAlert,
    result: TriageResult,
) -> None:
    """
    Giữ nguyên priority, confidence và quyết định định tuyến của LLM, đồng thời
    dựng lại phần bằng chứng email từ các trường xác định. Nếu Wazuh định tuyến
    sự kiện vào nhóm phishing thì dùng ``phishing`` làm category của workflow,
    không xem nhãn này là bằng chứng phishing thành công hay endpoint bị xâm nhập.

    Guardrail này chạy trước bước Threat Intelligence để tránh kết luận sớm IOC,
    tệp đính kèm hoặc spoofing khi chưa có bằng chứng tương ứng.
    """
    # Nhom phishing cua Wazuh chi dung de route/phan loai, khong phai bang chung phishing thanh cong hay endpoint bi compromise
    if any(
        str(group).casefold() == "phishing"
        for group in alert.rule_groups
    ):
        result.category = "phishing"

    result.evidence = _build_email_triage_evidence(
        alert
    )
    result.summary = _build_email_triage_summary(
        alert
    )
    result.recommended_next_step = (
        _build_email_triage_next_step(
            alert
        )
    )


def apply_triage_guardrails(
    alert: NormalizedAlert,
    result: TriageResult,
) -> TriageResult:
    """
    Chỉ hiệu chỉnh kết quả khi cảnh báo có dữ kiện đủ rõ để xử lý xác định.

    Guardrail không được đổi một sự kiện sang loại khác chỉ vì thiếu trường
    không bắt buộc.
    """
    result.alert_id = alert.alert_id

    _normalize_rule_level_severity_wording(
        alert,
        result,
    )

    _apply_encoded_powershell_triage_guardrail(
        alert,
        result,
    )

    if (
        alert.event_id == "4625"
        and alert.logon_type == "2"
    ):
        result.evidence = [
            item
            for item in result.evidence
            if "network logon"
            not in item.lower()
        ]

        interactive_evidence = (
            "Logon type 2 indicates an interactive logon"
        )

        if (
            interactive_evidence
            not in result.evidence
        ):
            result.evidence.append(
                interactive_evidence
            )

    if (
        alert.event_id == "4625"
        and alert.logon_type == "2"
        and alert.source_ip is None
        and alert.sub_status
        == "0xc000006a"
    ):
        result.category = "Authentication"
        result.priority = (
            TriagePriority.LOW
        )
        result.suspicious = False
        result.requires_enrichment = False
        result.requires_investigation = False

        result.evidence = [
            (
                "Windows Security Event ID 4625 indicates "
                "a failed logon attempt"
            ),
            (
                "Logon type 2 indicates an interactive logon"
            ),
            (
                "Status 0xc000006d indicates logon failure"
            ),
            (
                "Sub-status 0xc000006a indicates an "
                "incorrect password"
            ),
            (
                "No source IP or source port is present"
            ),
            (
                "A single failed logon does not establish "
                "brute force, credential stuffing, or "
                "remote malicious activity"
            ),
            (
                "MITRE T1531 is present in the source alert "
                "but is not supported by this event alone"
            ),
        ]

        result.summary = (
            "Local interactive logon failure caused by an "
            "incorrect password. No remote source evidence "
            "or correlated malicious activity is present."
        )

        result.recommended_next_step = (
            "Monitor and correlate with subsequent "
            "authentication failures or account lockouts "
            "before escalation."
        )

    if alert.email_event_type:
        _apply_email_triage_guardrail(
            alert,
            result,
        )
        return result

    if alert.fim_event:
        # FIM xac nhan co thay doi nhung khong xac dinh y dinh hay authorization, tranh ket luan tuyet doi benign/malicious
        result.summary = result.summary.replace(
            "The change is not benign",
            "The change cannot be assumed benign",
        ).replace(
            "the change is not benign",
            "the change cannot be assumed benign",
        )

        cleaned_evidence: list[str] = []

        for item in result.evidence:
            # Giu nguyen Wazuh rule level nhu telemetry goc, khong tu quy doi sang nhan severity
            if (
                "rule level" in item.lower()
                and "high severity" in item.lower()
            ):
                cleaned_evidence.append(
                    item.replace(
                        " (high severity)",
                        "",
                    )
                )
                continue

            cleaned_evidence.append(item)

        result.evidence = cleaned_evidence

    if (
        alert.event_id
        == DEFENDER_DETECTION_EVENT_ID
        and alert.provider_name
        == DEFENDER_PROVIDER
    ):
        # Defender phat hien that van can investigation du AV da xu ly, quarantine chi la bang chung containment
        result.requires_investigation = True

        if (
            _defender_remediation_event(
                alert
            )
            is None
        ):
            unresolved_evidence = (
                "No correlated Defender Event 1117 "
                "remediation evidence is available yet"
            )

            if (
                unresolved_evidence
                not in result.evidence
            ):
                result.evidence.append(
                    unresolved_evidence
                )

    return result


def run_triage(
    alert: NormalizedAlert,
) -> TriageResult:
    agent = create_triage_agent()

    triage_context = (
        _build_triage_context(
            alert
        )
    )

    task = Task(
        description=f"""
Analyze the following normalized security alert.

Alert:
{json.dumps(triage_context, indent=2, ensure_ascii=False)}

Requirements:
- Use only the supplied alert evidence.
- Classify the alert into an appropriate security category.
- Assign priority as low, medium, high, or critical.
- Triage priority means current SOC response urgency after considering
  containment/remediation evidence; it is not automatically the same as
  a vendor's raw threat-severity label.
- Distinguish Wazuh rule_level from Windows event-log severity_value and from
  provider-specific threat severity stored in event_data. Never combine them into
  wording such as "rule level 10 (VERBOSE)"; report each field separately.
- For encoded PowerShell, a decoded value that looks like an internal, test, lab,
  administrative, or trusted-looking identifier does not by itself prove that the
  execution was authorized, expected, legitimate, or benign.
- If encoded PowerShell is observed and no supplied authorization, baseline, or
  correlated evidence establishes legitimacy, keep the event suspicious and route
  it to enrichment/investigation. Encoding alone still does not justify disruptive
  remediation or a claim of compromise.
- Estimate confidence between 0.0 and 1.0.
- Decide whether the alert is suspicious.
- Decide whether enrichment is required.
- Decide whether further investigation is required.
- Do not infer a remote attacker when no remote-source evidence exists.
- Missing source IP does not change the event into an authentication event.
- Do not infer brute force from a single failed authentication event.
- Do not describe an event as an authentication failure unless the supplied
  alert actually represents an authentication event.
- For Windows authentication events, Logon Type 2 means interactive logon,
  not network logon.
- Do not treat a supplied MITRE ATT&CK mapping as unquestionable evidence.
- Do not treat use of PowerShell alone as proof of malicious activity.
- A decoded Base64 value that resembles an internal, lab, test, administrative,
  trusted, or familiar identifier is not by itself evidence of authorization or
  benignity. Do not classify the activity as benign from naming semantics alone.
- When encoded PowerShell is observed and no independent authorization, baseline,
  user/process, or correlated execution-context evidence is supplied, require
  enrichment and further investigation while avoiding claims of compromise.
- For email-security events, treat Wazuh rule descriptions and groups as
  routing/detection metadata rather than standalone proof of phishing.
- A Sender/From and Reply-To mismatch is relevant evidence but does not by
  itself prove spoofing or malicious intent.
- Do not call an email sender or domain spoofed unless supplied header or
  authentication evidence establishes spoofing.
- Do not call an email URL, domain, or attachment malicious merely because
  the string, file name, or hash is present. Threat-intelligence enrichment
  is a separate stage.
- The presence of an attachment hash does not establish that the file is
  known malware, clean, or benign.
- If email_user_clicked or email_attachment_executed is null, treat the
  corresponding user-action state as unknown.
- If those fields explicitly contain true or false, report only that the
  supplied telemetry states that value; do not claim independent verification.
- For manager-originated email telemetry, the Wazuh agent/manager identity
  identifies the telemetry source and must not be treated as the recipient
  endpoint or as evidence that the manager host is compromised.
- Do not recommend visiting an untrusted URL or executing an attachment in
  order to triage the event.
- For Wazuh FIM/Syscheck events, use fim_event, fim_path, fim_diff,
  changed attributes, hashes, sizes, and timestamps as the authoritative
  file-change evidence.
- A FIM modification proves that file contents or metadata changed, but it
  does not identify the actor or prove malicious intent by itself.
- If a monitored file changes from a security-enabling value to a
  security-weakening value (for example, "mode=secure" to "mode=disabled")
  and no authorization evidence is supplied, treat the event as suspicious
  and require further investigation rather than assuming it is benign.
- Do not claim a user/process performed the FIM change unless the supplied
  evidence identifies that actor.
- For a Microsoft Defender Event 1116, use event_data and correlated_events
  to distinguish detection from remediation. A successful quarantine proves
  that the AV action succeeded; it does not by itself prove that a genuine
  malware incident is benign.
- If Defender remediation evidence is missing, treat remediation status as
  unresolved rather than assuming that the threat was removed.
- After successful quarantine, do not use "verify that the file is still
  present" as the primary next step; absence may be the expected result.
- Do not automatically close an alert solely because it appears low risk.
- Separate observed facts from assumptions.
- Keep recommendations relevant to the actual event type.
- Provide concise evidence supporting the decision.
- Provide the safest reasonable next step for a SOC analyst.
""",
        expected_output=(
            "A structured TriageResult containing category, priority, "
            "confidence, suspicious flag, routing decisions, summary, "
            "evidence, and recommended next step."
        ),
        agent=agent,
        output_pydantic=TriageResult,
    )

    crew = Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff()

    if result.pydantic is None:
        raise RuntimeError(
            "CrewAI did not return a valid TriageResult."
        )

    triage = result.pydantic

    return apply_triage_guardrails(
        alert,
        triage,
    )
