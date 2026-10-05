from datetime import datetime

from crewai import Agent, Crew, Process, Task

from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EnrichmentAssessment,
    EnrichmentResult,
    EntityType,
)
from soc_multi_agent.services.llm_service import get_llm


_SECURITY_ENABLED_VALUES = {
    "secure",
    "enabled",
    "enable",
    "true",
    "on",
    "active",
}

_SECURITY_DISABLED_VALUES = {
    "disabled",
    "disable",
    "false",
    "off",
    "inactive",
    "insecure",
}


def create_enrichment_agent() -> Agent:
    return Agent(
        role="SOC Enrichment Analyst",
        goal=(
            "Analyze enrichment evidence associated with a security "
            "alert and determine which findings are relevant for "
            "further investigation."
        ),
        backstory=(
            "You are a SOC enrichment analyst. "
            "You analyze structured evidence collected from trusted "
            "tools such as MITRE ATT&CK and threat intelligence services. "
            "You do not invent missing evidence and do not treat a "
            "single reputation signal or MITRE mapping as definitive proof."
        ),
        llm=get_llm("enrichment"),
        allow_delegation=False,
        verbose=True,
    )


def _compact_alert_context(
    alert: NormalizedAlert,
) -> dict:
    """
    Keep security-relevant normalized evidence while avoiding duplicated
    raw FIM payloads in the LLM prompt.
    """
    context = alert.model_dump(mode="json")

    if alert.fim_event:
        context.pop(
            "syscheck_data",
            None,
        )
        context.pop(
            "full_log",
            None,
        )

    if context.get("event_data"):
        context.pop(
            "event_message",
            None,
        )

    return context


def _fim_diff_values(
    alert: NormalizedAlert,
) -> tuple[str | None, str | None]:
    """
    Extract the single before/after content lines emitted by Wazuh
    report_changes.
    """
    if not alert.fim_diff:
        return None, None

    before: str | None = None
    after: str | None = None

    for raw_line in alert.fim_diff.splitlines():
        line = raw_line.strip()

        if line.startswith("< ") and before is None:
            before = line[2:].strip()
        elif line.startswith("> ") and after is None:
            after = line[2:].strip()

    return before, after


def _extract_assignment_value(
    text: str | None,
) -> str | None:
    if not text:
        return None

    if "=" in text:
        _, value = text.split("=", 1)
        return value.strip().lower()

    return text.strip().lower()


def _is_security_weakening_fim_change(
    alert: NormalizedAlert,
) -> bool:
    if (
        alert.fim_event or ""
    ).lower() != "modified":
        return False

    before, after = _fim_diff_values(
        alert
    )

    before_value = _extract_assignment_value(
        before
    )
    after_value = _extract_assignment_value(
        after
    )

    return (
        before_value in _SECURITY_ENABLED_VALUES
        and after_value in _SECURITY_DISABLED_VALUES
    )


def _fim_elapsed_seconds(
    alert: NormalizedAlert,
) -> int | None:
    if (
        not alert.fim_mtime_before
        or not alert.fim_mtime_after
    ):
        return None

    try:
        before = datetime.fromisoformat(
            alert.fim_mtime_before
        )
        after = datetime.fromisoformat(
            alert.fim_mtime_after
        )
    except ValueError:
        return None

    delta = int(
        (after - before).total_seconds()
    )

    if delta < 0:
        return None

    return delta


def _permission_principals(
    alert: NormalizedAlert,
) -> list[str]:
    raw_permissions = (
        alert.syscheck_data.get(
            "win_perm_after",
            [],
        )
        if alert.syscheck_data
        else []
    )

    principals: list[str] = []

    if not isinstance(
        raw_permissions,
        list,
    ):
        return principals

    for entry in raw_permissions:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        name = entry.get("name")

        if (
            isinstance(name, str)
            and name
            and name not in principals
        ):
            principals.append(name)

    return principals


def _deterministic_threat_intel_findings(
    enrichment: EnrichmentResult,
) -> list[str]:
    """
    Build provider-scoped findings directly from structured VirusTotal data.

    No engine count, category, or reputation is transferred between IOCs.
    VirusTotal "unknown" is never interpreted as clean or benign.
    """
    findings: list[str] = []

    for item in enrichment.threat_intel:
        entity_label = item.entity_type.value

        if not item.known:
            findings.append(
                "VirusTotal returned no object/report for "
                f"{entity_label} '{item.value}' at lookup time. "
                "This means the IOC was unknown to VirusTotal at that time; "
                "it is not evidence that the IOC is clean, benign, safe, "
                "or scanned with zero detections."
            )
            continue

        statement = (
            f"VirusTotal has a report for {entity_label} '{item.value}' "
            f"with {item.malicious} malicious, "
            f"{item.suspicious} suspicious, "
            f"{item.harmless} harmless, and "
            f"{item.undetected} undetected analysis results."
        )

        if item.categories:
            statement += (
                " Provider categories for this exact IOC are: "
                + "; ".join(item.categories)
                + "."
            )
        else:
            statement += (
                " No provider categories were returned for this exact IOC."
            )

        statement += (
            " This is threat-intelligence evidence about the queried IOC "
            "and does not by itself prove user interaction, execution, "
            "credential compromise, or endpoint compromise."
        )

        findings.append(statement)

    return findings


def _email_observation_findings(
    alert: NormalizedAlert,
) -> list[str]:
    """
    Build only directly observed email-security facts.
    """
    findings: list[str] = []

    if alert.email_sender:
        findings.append(
            f"Observed email sender: {alert.email_sender}."
        )

    if alert.email_reply_to:
        findings.append(
            f"Observed Reply-To address: {alert.email_reply_to}."
        )

    if (
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    ):
        findings.append(
            "The observed From/Sender and Reply-To addresses differ."
        )

    if alert.email_recipient:
        findings.append(
            f"Observed email recipient: {alert.email_recipient}."
        )

    if alert.email_subject:
        findings.append(
            f"Observed email subject: {alert.email_subject}."
        )

    if alert.email_attachment_name:
        findings.append(
            "Observed attachment: "
            f"{alert.email_attachment_name}"
            + (
                f" ({alert.email_attachment_content_type})."
                if alert.email_attachment_content_type
                else "."
            )
        )

    if alert.email_user_clicked is None:
        findings.append(
            "No user-click state was supplied in the normalized telemetry; "
            "user interaction with the URL remains unknown."
        )
    else:
        findings.append(
            "The supplied email telemetry states "
            f"user_clicked={str(alert.email_user_clicked).lower()}. "
            "This enrichment stage does not independently verify that state."
        )

    if alert.email_attachment_executed is None:
        findings.append(
            "No attachment-execution state was supplied in the normalized "
            "telemetry; attachment execution remains unknown."
        )
    else:
        findings.append(
            "The supplied email telemetry states "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}. "
            "This enrichment stage does not independently verify that state."
        )

    return findings


def _email_summary(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
) -> str:
    parts: list[str] = [
        "The case contains structured email-security telemetry for "
        "phishing investigation."
    ]

    if (
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    ):
        parts.append(
            "The supplied Sender and Reply-To addresses are different."
        )

    known_findings = [
        item
        for item in enrichment.threat_intel
        if item.known
    ]

    unknown_findings = [
        item
        for item in enrichment.threat_intel
        if not item.known
    ]

    if known_findings:
        for item in known_findings:
            statement = (
                f"VirusTotal reports {item.malicious} malicious and "
                f"{item.suspicious} suspicious analysis results for the "
                f"{item.entity_type.value} '{item.value}'."
            )

            if item.categories:
                statement += (
                    " Categories for this exact IOC include: "
                    + "; ".join(item.categories)
                    + "."
                )
            else:
                statement += (
                    " No categories were returned for this exact IOC."
                )

            parts.append(statement)

    for item in unknown_findings:
        parts.append(
            "VirusTotal returned no object/report for "
            f"{item.entity_type.value} '{item.value}' at lookup time; "
            "this unknown status is not evidence of benignity."
        )

    if not enrichment.threat_intel:
        parts.append(
            "No VirusTotal findings are available in this enrichment "
            "result; absence of provider output is not evidence of benignity."
        )

    if (
        alert.email_user_clicked is None
        or alert.email_attachment_executed is None
    ):
        parts.append(
            "User interaction or attachment-execution state is not fully "
            "established by the supplied telemetry."
        )
    else:
        parts.append(
            "The supplied telemetry states "
            f"user_clicked={str(alert.email_user_clicked).lower()} and "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}; "
            "this enrichment stage does not independently verify those states."
        )

    parts.append(
        "Threat-intelligence reputation supports continued investigation "
        "of the email and its IOCs, but does not by itself establish "
        "credential theft, execution, or endpoint compromise."
    )

    return " ".join(parts)


def _email_recommended_next_step(
    alert: NormalizedAlert,
) -> str:
    return (
        "Review available email-header and authentication evidence "
        "(such as SPF, DKIM, and DMARC) without assuming spoofing from the "
        "address alone. Correlate recipient endpoint, browser, proxy, DNS, "
        "and authentication telemetry where available to establish whether "
        "the URL was accessed or credentials were submitted. Analyze the "
        f"attachment '{alert.email_attachment_name or 'attachment'}' in a "
        "controlled file-analysis workflow if additional file assessment is "
        "required. Do not infer endpoint compromise solely from IOC "
        "reputation."
    )


def _is_encoded_powershell_alert(
    alert: NormalizedAlert,
) -> bool:
    if not alert.base64_decodings:
        return False

    provider = (alert.provider_name or "").casefold()
    channel = (alert.channel or "").casefold()

    return bool(
        alert.script_block_text
        or "powershell" in provider
        or "powershell" in channel
    )


def _apply_encoded_powershell_enrichment_guardrail(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
    result: EnrichmentAssessment,
) -> EnrichmentAssessment:
    """
    Giữ kết luận PowerShell bám theo telemetry xác định.

    Khi chưa có correlated evidence, tên hoặc nội dung decoded trông giống nội bộ,
    test hay lab không đủ để xác nhận authorization/benignity.
    """
    if (
        not _is_encoded_powershell_alert(alert)
        or alert.correlated_events
    ):
        return result

    decoded_values = list(
        dict.fromkeys(
            str(value)
            for value in alert.base64_decodings.values()
        )
    )

    findings: list[str] = []

    if alert.script_block_text:
        findings.append(
            "Observed PowerShell script-block telemetry contains encoded "
            "content with deterministic Base64 decoding."
        )

    if decoded_values:
        findings.append(
            "Deterministic decoded Base64 value(s): "
            + "; ".join(repr(value) for value in decoded_values)
            + ". The decoded text is content evidence only; its naming does "
            "not establish authorization, legitimacy, or benign intent."
        )

    for technique in enrichment.mitre_techniques:
        findings.append(
            "MITRE enrichment for the observed behavior includes "
            f"{technique.technique_id} ({technique.name})."
        )

    if not enrichment.threat_intel:
        findings.append(
            "No threat-intelligence findings are available for this case; "
            "absence of provider findings is not evidence of benignity."
        )

    findings.append(
        "No correlated event evidence was supplied to establish that the "
        "PowerShell execution was authorized, expected, or part of an "
        "approved baseline."
    )

    result.relevant_findings = findings
    result.requires_investigation = True
    result.summary = (
        "The alert contains PowerShell script-block telemetry with deterministic "
        "Base64 decoding. The decoded text must be treated as observed content, "
        "not as proof that the execution was authorized or benign. The available "
        "enrichment supports the observed PowerShell/encoded-content behavior, "
        "but no correlated authorization or baseline evidence is supplied. "
        "Deeper investigation is therefore required before classifying the "
        "activity as benign or malicious."
    )
    result.recommended_next_step = (
        "Correlate process-tree, parent-process, user, script-origin, change or "
        "authorization records, and surrounding endpoint/network telemetry. "
        "Confirm whether the PowerShell execution was expected before closing "
        "the case as benign; do not infer compromise solely from encoding."
    )

    return result


def apply_enrichment_guardrails(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
    result: EnrichmentAssessment,
) -> EnrichmentAssessment:
    """
    Apply deterministic evidence finalization after the LLM assessment.

    The LLM retains responsibility for risk/confidence/routing assessment.
    For email-security cases, analyst-facing evidence, summary, and next-step
    wording are rebuilt from structured telemetry and TI data so the final
    result cannot transfer properties between IOCs or reinterpret provider
    unknown status as benign.
    """
    result.alert_id = alert.alert_id

    result = _apply_encoded_powershell_enrichment_guardrail(
        alert,
        enrichment,
        result,
    )

    if alert.email_event_type:
        result.relevant_findings = (
            _email_observation_findings(alert)
            + _deterministic_threat_intel_findings(
                enrichment
            )
        )

        # IOC trong Enrichment lay tu cung normalized alert, chenh lech verdict count khong du de coi la contradiction
        result.inconsistencies = []

        result.summary = _email_summary(
            alert,
            enrichment,
        )

        result.recommended_next_step = (
            _email_recommended_next_step(
                alert
            )
        )

        return result

    if not alert.fim_event:
        return result

    # Giu cac guardrail FIM hien co
    cleaned_findings: list[str] = []

    for finding in result.relevant_findings:
        lowered = finding.lower()

        if (
            "permission" in lowered
            and "privileged" in lowered
        ):
            continue

        if (
            alert.fim_diff
            and (
                "actual content is not known" in lowered
                or "content is not known" in lowered
                or "content is unknown" in lowered
            )
        ):
            continue

        if (
            "interval" in lowered
            and (
                "timestamp" in lowered
                or "modification" in lowered
            )
        ):
            continue

        cleaned_findings.append(
            finding
        )

    principals = _permission_principals(
        alert
    )

    if principals:
        neutral_permission_finding = (
            "Post-change Windows permission data is present for: "
            + ", ".join(principals)
            + ". These entries describe observed access-control principals "
            "and do not by themselves identify the actor that modified the file."
        )

        if (
            neutral_permission_finding
            not in cleaned_findings
        ):
            cleaned_findings.append(
                neutral_permission_finding
            )

    before, after = _fim_diff_values(
        alert
    )

    if before is not None and after is not None:
        deterministic_change = (
            f"Wazuh FIM report_changes recorded content changing "
            f"from '{before}' to '{after}'."
        )

        if deterministic_change not in cleaned_findings:
            cleaned_findings.append(
                deterministic_change
            )

    elapsed_seconds = _fim_elapsed_seconds(
        alert
    )

    if elapsed_seconds is not None:
        timing_finding = (
            "The FIM before/after modification timestamps are "
            f"{elapsed_seconds} seconds apart "
            f"({alert.fim_mtime_before} to {alert.fim_mtime_after})."
        )

        if timing_finding not in cleaned_findings:
            cleaned_findings.append(
                timing_finding
            )

    result.relevant_findings = (
        cleaned_findings
    )

    if _is_security_weakening_fim_change(
        alert
    ):
        result.requires_investigation = True

    return result


def run_enrichment_analysis(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
) -> EnrichmentAssessment:
    agent = create_enrichment_agent()

    alert_context = _compact_alert_context(
        alert
    )

    task = Task(
        description=f"""
Analyze the following security alert and enrichment evidence.

Normalized alert:
{alert_context}

Enrichment evidence:
{enrichment.model_dump_json(indent=2)}

Requirements:
- Evaluate only the supplied evidence.
- Identify enrichment findings relevant to the alert.
- Identify genuine inconsistencies between the alert evidence and enrichment
  data.
- Treat each threat-intelligence finding as scoped to its exact entity_type
  and value. Never transfer categories, reputation, or engine counts from one
  URL, domain, IP, or hash to another IOC.
- For VirusTotal data, known=false means VirusTotal did not return an object
  or report for that IOC at lookup time. It does not mean the IOC was scanned
  clean, benign, safe, or received zero malicious detections.
- A known VirusTotal object with zero malicious detections is also not proof
  that an IOC is benign.
- VirusTotal engine counts and categories are threat-intelligence evidence
  about the queried IOC. They do not by themselves prove user interaction,
  execution, credential theft, endpoint compromise, or successful intrusion.
- Do not call an email sender spoofed unless supplied header/authentication
  evidence establishes spoofing.
- If email_user_clicked or email_attachment_executed is null, treat the user
  action as unknown.
- If those fields explicitly contain true or false, treat them only as supplied
  telemetry and do not invent an independent verification source.
- Treat base64_decodings in the normalized alert as deterministic tool output.
- Use decoded Base64 values exactly as supplied in base64_decodings.
- Never independently decode, replace, reinterpret, or guess encoded content.
- A decoded value that looks like an internal, test, lab, administrative, or
  trusted-looking identifier is still only content evidence. Its name or text
  does not establish authorization, expected use, legitimacy, or benign intent.
- For encoded PowerShell, do not classify the activity as benign or stop deeper
  investigation unless supplied authorization, baseline, or correlated telemetry
  actually supports that conclusion.
- If an encoded-looking value has no deterministic decoded value, state that
  it has not been decoded rather than inventing a result.
- Do not assume a MITRE ATT&CK mapping is correct merely because it is present.
- Validate MITRE technique IDs against the observed behavior.
- MITRE ATT&CK tactic labels may differ between data sources or ATT&CK
  versions. A tactic-name difference alone is not evidence that a technique
  ID is invalid and must not be treated as a security contradiction.
- Prefer the structured MITRE enrichment data when describing current tactic
  metadata.
- Do not recommend automatically modifying SIEM rules or MITRE mappings based
  on a single alert.
- Do not classify an IP as malicious solely because one engine reports it as
  malicious.
- Do not invent missing IP, domain, hash, user, or host information.
- For Wazuh FIM events, treat fim_diff, before/after hashes, changed
  attributes, path, event type, and timestamps as authoritative file-change
  evidence.
- A FIM change proves that a file changed; it does not identify the actor or
  prove malicious intent.
- Do not describe Users, Authenticated Users, or all listed Windows permission
  principals as privileged accounts.
- A security-weakening FIM content change without supplied authorization
  evidence requires deeper investigation even when MITRE enrichment itself is
  consistent.
- Estimate confidence from 0.0 to 1.0.
- Decide whether deeper investigation is required.
- Provide a concise analyst-facing summary.
- Recommend the next SOC step.
""",
        expected_output=(
            "A structured EnrichmentAssessment containing risk level, "
            "confidence, relevant findings, inconsistencies, investigation "
            "decision, summary, and recommended next step."
        ),
        agent=agent,
        output_pydantic=EnrichmentAssessment,
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
            "CrewAI did not return a valid EnrichmentAssessment."
        )

    return apply_enrichment_guardrails(
        alert,
        enrichment,
        result.pydantic,
    )
