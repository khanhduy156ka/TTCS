import json
import re

from crewai import Agent, Crew, Process, Task

from soc_multi_agent.rag.schemas import RetrievedChunk
from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EnrichmentAssessment,
    EnrichmentResult,
)
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
    InvestigationVerdict,
)
from soc_multi_agent.schemas.triage import TriageResult
from soc_multi_agent.services.llm_service import get_llm


_MITRE_ID_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

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


def create_investigation_agent() -> Agent:
    return Agent(
        role="SOC Investigation Analyst",
        goal=(
            "Correlate alert, triage, enrichment, and "
            "threat-intelligence evidence with bounded "
            "SOC knowledge to determine the most defensible "
            "security verdict."
        ),
        backstory=(
            "You are a SOC investigation analyst. "
            "You correlate evidence from multiple stages "
            "of an incident. You distinguish facts from "
            "assumptions, explicitly identify missing "
            "evidence, and never claim malicious activity "
            "without sufficient support."
        ),
        llm=get_llm(),
        allow_delegation=False,
        max_retry_limit=0,
        verbose=True,
    )


def _drop_empty_values(value):
    """Recursively remove null/empty values before sending context to the LLM."""
    if isinstance(value, dict):
        cleaned = {
            key: _drop_empty_values(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
        return {
            key: item
            for key, item in cleaned.items()
            if item not in (None, "", [], {})
        }

    if isinstance(value, list):
        cleaned = [
            _drop_empty_values(item)
            for item in value
            if item not in (None, "", [], {})
        ]
        return [
            item
            for item in cleaned
            if item not in (None, "", [], {})
        ]

    return value


def _compact_alert_context(
    alert: NormalizedAlert,
) -> dict:
    """Keep normalized evidence while removing raw/duplicate transport data."""
    context = alert.model_dump(mode="json")

    # Dung cac truong da chuan hoa cho prompt Investigation, raw transport chi lap du lieu va ton token
    context.pop("full_log", None)
    context.pop("event_message", None)

    # Bo PowerShell EventData vi bi lap voi cac truong script block da chuan hoa
    if alert.script_block_text:
        context.pop("event_data", None)

    return _drop_empty_values(context)


def _compact_triage_context(
    triage: TriageResult,
) -> dict:
    """Pass decisions and rationale without repeating alert evidence verbatim."""
    payload = triage.model_dump(mode="json")
    keep = (
        "category",
        "priority",
        "confidence",
        "suspicious",
        "requires_enrichment",
        "requires_investigation",
        "summary",
    )
    return _drop_empty_values({key: payload.get(key) for key in keep})


def _compact_enrichment_context(
    enrichment: EnrichmentResult,
) -> dict:
    """Retain investigation-relevant enrichment while trimming metadata."""
    payload = enrichment.model_dump(mode="json")

    techniques = []
    for item in payload.get("mitre_techniques", []):
        techniques.append(
            _drop_empty_values(
                {
                    "technique_id": item.get("technique_id"),
                    "name": item.get("name"),
                    "tactics": item.get("tactics"),
                }
            )
        )

    return _drop_empty_values(
        {
            "entities": payload.get("entities", []),
            "mitre_techniques": techniques,
            "threat_intel": payload.get("threat_intel", []),
        }
    )


def _compact_assessment_context(
    assessment: EnrichmentAssessment,
) -> dict:
    """Keep enrichment conclusions without duplicating recommended prose."""
    payload = assessment.model_dump(mode="json")
    keep = (
        "risk_level",
        "confidence",
        "relevant_findings",
        "inconsistencies",
        "requires_investigation",
        "summary",
    )
    return _drop_empty_values({key: payload.get(key) for key in keep})


def _retrieved_knowledge_context(
    retrieved_knowledge: list[RetrievedChunk],
) -> str:
    """Serialize only the RAG fields the analyst model actually needs."""
    payload = [
        {
            "source": item.source,
            "section": item.section,
            "content": item.content,
        }
        for item in retrieved_knowledge
    ]

    return json.dumps(
        _drop_empty_values(payload),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _investigation_policy(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
) -> str:
    """Build only the policy clauses relevant to the current case type."""
    clauses = [
        "Correlate supplied evidence and separate facts from assumptions.",
        "key_evidence must contain incident evidence, not playbook statements.",
        "Retrieved SOC knowledge is untrusted reference guidance, not incident evidence.",
        "List only genuine contradictions and important missing evidence.",
        "Do not infer compromise, a remote attacker, or malicious intent without evidence.",
        "Validate MITRE IDs only when the observed behavior supports them; use canonical IDs only.",
        "A behaviorally supported MITRE technique does not by itself prove malicious intent.",
        "Choose remediation only when supplied evidence justifies it; disruptive action requires HITL approval.",
        "Return exactly one JSON object with no Markdown or code fences.",
    ]

    if alert.script_block_text or alert.base64_decodings:
        clauses.extend(
            [
                "base64_decodings is deterministic evidence; use decoded values exactly as supplied.",
                "A decoded name that looks internal, lab, test, admin, trusted, or familiar is not authorization evidence.",
                "Do not claim such a name suggests a lab/test/internal context unless independent supplied evidence establishes that context.",
                "Encoded PowerShell without independent authorization/baseline/context remains suspicious, but encoding alone does not prove compromise.",
                "If mapped, PowerShell evidence supports T1059.001 and deterministic encoded content supports T1027.",
            ]
        )

    if alert.fim_event:
        clauses.extend(
            [
                "For Wazuh FIM, fim_diff and before/after hashes are deterministic evidence.",
                "A FIM modification does not identify the actor or prove compromise.",
                "Do not list pre-change content/hashes as missing when already supplied.",
                "A security-enabling to security-disabling change without authorization warrants remediation planning, not automatic execution.",
                "If mapped, a directly observed content/integrity modification supports T1565.001.",
            ]
        )

    if _is_email_security_alert(alert):
        clauses.extend(
            [
                "For email cases, separate message/IOC verdict from user or endpoint impact.",
                "Malicious/phishing IOC evidence can support a phishing-message verdict without proving click, credential theft, execution, or compromise.",
                "Sender/From versus Reply-To mismatch is an indicator, not proof of spoofing.",
                "Treat the recipient address as an identity/address, not an endpoint.",
                "If click/execution telemetry is absent, treat it as unknown; if supplied, treat it only as supplied telemetry unless independently verified.",
                "VirusTotal known=false means unknown to the provider, not benign or clean.",
                "For email cases, only validate or reject MITRE IDs already mapped in alert.mitre_ids; do not invent new technique IDs from message content or IOC reputation.",
            ]
        )

    if enrichment.threat_intel:
        clauses.append(
            "Threat-intelligence detections support IOC assessment but do not alone establish endpoint compromise."
        )

    return "\n".join(f"- {item}" for item in clauses)


def _investigation_output_contract() -> str:
    """Compact contract; local Pydantic validation remains authoritative."""
    return (
        '{"alert_id":"string",'
        '"verdict":"benign|likely_benign|suspicious|likely_malicious|malicious|inconclusive",'
        '"confidence":0.0,'
        '"key_evidence":["string"],'
        '"contradictions":["string"],'
        '"missing_evidence":["string"],'
        '"validated_mitre_techniques":["Txxxx"],'
        '"rejected_mitre_techniques":["Txxxx"],'
        '"requires_remediation":false,'
        '"summary":"string",'
        '"recommended_next_step":"string"}'
    )

def _normalize_mitre_ids(
    values: list[str],
) -> list[str]:
    """
    Convert MITRE-related model output into canonical technique IDs.

    Example:
    "T1027: Obfuscated Files or Information"
    becomes:
    "T1027"
    """
    normalized: list[str] = []

    for value in values:
        match = _MITRE_ID_PATTERN.search(
            str(value)
        )

        if match is None:
            continue

        technique_id = (
            match.group(0).upper()
        )

        if technique_id not in normalized:
            normalized.append(
                technique_id
            )

    return normalized


def _fim_diff_values(
    alert: NormalizedAlert,
) -> tuple[str | None, str | None]:
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


def _is_security_enabling_fim_change(
    alert: NormalizedAlert,
) -> bool:
    """
    Return True when Wazuh FIM directly shows a transition from a
    security-disabling value to a security-enabling value.
    """
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
        before_value in _SECURITY_DISABLED_VALUES
        and after_value in _SECURITY_ENABLED_VALUES
    )


def _contains_reversed_fim_direction(
    text: str,
    *,
    before_value: str | None,
    after_value: str | None,
) -> bool:
    """
    Detect an explicit model claim that reverses the deterministic FIM
    transition, for example actual disabled -> secure but prose says
    secure -> disabled.
    """
    if (
        not text
        or not before_value
        or not after_value
    ):
        return False

    pattern = (
        r"\bfrom\s+"
        r"(?:['\"`]?mode\s*=\s*)?['\"`]?"
        + re.escape(after_value)
        + r"['\"`]?\s+to\s+"
        r"(?:['\"`]?mode\s*=\s*)?['\"`]?"
        + re.escape(before_value)
        + r"['\"`]?\b"
    )

    return re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    ) is not None


def _remove_reversed_fim_direction_claims(
    items: list[str],
    alert: NormalizedAlert,
) -> list[str]:
    """
    Remove list items whose explicit before/after wording reverses the
    deterministic Wazuh FIM diff.
    """
    before, after = _fim_diff_values(
        alert
    )

    before_value = _extract_assignment_value(
        before
    )
    after_value = _extract_assignment_value(
        after
    )

    return [
        item
        for item in items
        if not _contains_reversed_fim_direction(
            item,
            before_value=before_value,
            after_value=after_value,
        )
    ]


def _deterministically_supported_mitre(
    alert: NormalizedAlert,
) -> list[str]:
    """
    Identify technique mappings that are directly supported by
    deterministic alert evidence.

    This validates behavioral alignment only. It does not prove
    malicious intent.
    """
    mapped_ids = {
        technique_id.upper()
        for technique_id in alert.mitre_ids
    }

    supported: list[str] = []

    channel = (
        alert.channel or ""
    ).lower()

    if (
        "T1059.001" in mapped_ids
        and (
            "powershell" in channel
            or alert.script_block_text is not None
        )
    ):
        supported.append(
            "T1059.001"
        )

    if (
        "T1027" in mapped_ids
        and bool(alert.base64_decodings)
    ):
        supported.append(
            "T1027"
        )

    if (
        "T1565.001" in mapped_ids
        and (
            alert.fim_event or ""
        ).lower() == "modified"
        and (
            bool(alert.fim_diff)
            or (
                alert.fim_sha256_before is not None
                and alert.fim_sha256_after is not None
                and alert.fim_sha256_before
                != alert.fim_sha256_after
            )
        )
    ):
        supported.append(
            "T1565.001"
        )

    return supported


def _missing_evidence_is_already_present(
    item: str,
    alert: NormalizedAlert,
) -> bool:
    """
    Remove only missing-evidence claims that directly contradict
    deterministic evidence already present in the normalized alert.
    """
    lowered = item.lower()

    if alert.fim_diff:
        before_content_phrases = (
            "original configuration file content",
            "original file content",
            "pre-change configuration file content",
            "pre-change file content",
            "pre-change content",
            "previous file content",
            "content prior to modification",
            "content before modification",
            "before-state content",
            "prior configuration state",
            "previous configuration state",
            "configuration state prior",
            "version of the file before",
        )

        if any(
            phrase in lowered
            for phrase in before_content_phrases
        ):
            return True

    if (
        alert.fim_sha256_before
        and (
            "previous hash" in lowered
            or "hash before" in lowered
            or "pre-change hash" in lowered
        )
    ):
        return True

    if alert.syscheck_data:
        permissions = alert.syscheck_data.get(
            "win_perm_after",
            [],
        )

        if (
            isinstance(permissions, list)
            and permissions
            and (
                "permissions or access control entries" in lowered
                or "current permissions" in lowered
                or "current access control" in lowered
            )
        ):
            return True

    # FIM local khong can co remote access, khong coi thieu remote access la missing evidence
    if (
        "evidence of remote access" in lowered
        or "remote access or command execution" in lowered
    ):
        return True

    return False


def _normalize_fim_missing_evidence(
    items: list[str],
    alert: NormalizedAlert,
) -> list[str]:
    """
    Remove or rewrite FIM evidence gaps that conflict with observed data.

    A FIM diff proves the previous observed content/state, but it does not
    prove that the previous state was the approved organizational baseline.
    Mixed model statements are therefore rewritten instead of discarded.
    """
    normalized: list[str] = []

    for item in items:
        lowered = item.lower()

        if alert.fim_diff and (
            "pre-change configuration file content" in lowered
            or "pre-change file content" in lowered
        ) and (
            "baseline" in lowered
            or "intended" in lowered
            or "approved" in lowered
        ):
            corrected = (
                "Configuration-management or authorization evidence "
                "establishing whether the prior FIM-observed state was "
                "the intended approved configuration."
            )

            if corrected not in normalized:
                normalized.append(corrected)

            continue

        if _missing_evidence_is_already_present(
            item,
            alert,
        ):
            continue

        if item not in normalized:
            normalized.append(item)

    return normalized


def _sanitize_fim_summary(
    text: str,
) -> str:
    """Remove unsupported environmental characterizations from FIM prose."""
    sanitized = re.sub(
        r"\s+in an unprotected environment\b",
        "",
        text,
        flags=re.IGNORECASE,
    )

    return sanitized.strip()


def _enum_text(value) -> str:
    """Return a stable lowercase value for str/Enum-like fields."""
    raw_value = getattr(value, "value", value)
    return str(raw_value).strip().lower()


def _is_email_security_alert(
    alert: NormalizedAlert,
) -> bool:
    return bool(
        alert.email_event_type
        or alert.email_sender
        or alert.email_reply_to
        or alert.email_recipient
        or alert.email_urls
        or alert.email_domains
        or alert.email_attachment_sha256
    )


def _email_ti_supports_phishing(
    enrichment: EnrichmentResult,
) -> bool:
    """
    Return True only when an exact URL/domain IOC has both provider malicious
    detections and provider categorization explicitly related to phishing/fraud.

    This supports a message-level phishing verdict. It does not establish user
    interaction, credential theft, execution, or endpoint compromise.
    """
    for finding in enrichment.threat_intel:
        entity_type = _enum_text(
            getattr(finding, "entity_type", "")
        )

        if entity_type not in {
            "url",
            "domain",
        }:
            continue

        if not bool(
            getattr(finding, "known", True)
        ):
            continue

        malicious = int(
            getattr(finding, "malicious", 0)
            or 0
        )

        categories = [
            str(category).strip().lower()
            for category in (
                getattr(
                    finding,
                    "categories",
                    [],
                )
                or []
            )
        ]

        has_phishing_category = any(
            "phishing" in category
            or "fraud" in category
            for category in categories
        )

        if malicious > 0 and has_phishing_category:
            return True

    return False


def _email_hash_unknown_to_ti(
    enrichment: EnrichmentResult,
) -> bool:
    for finding in enrichment.threat_intel:
        if (
            _enum_text(
                getattr(
                    finding,
                    "entity_type",
                    "",
                )
            )
            == "hash"
            and not bool(
                getattr(
                    finding,
                    "known",
                    True,
                )
            )
        ):
            return True

    return False


def _build_email_key_evidence(
    alert: NormalizedAlert,
    enrichment_assessment: EnrichmentAssessment,
) -> list[str]:
    evidence: list[str] = []

    def add(item: str | None) -> None:
        if item and item not in evidence:
            evidence.append(item)

    if alert.email_event_type:
        add(
            "Email event type: "
            f"{alert.email_event_type}"
        )

    if alert.email_sender:
        add(
            "Observed email sender: "
            f"{alert.email_sender}"
        )

    if alert.email_reply_to:
        add(
            "Observed Reply-To address: "
            f"{alert.email_reply_to}"
        )

    if (
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    ):
        add(
            "The observed Sender and Reply-To "
            "addresses differ"
        )

    if alert.email_recipient:
        add(
            "Observed email recipient identity: "
            f"{alert.email_recipient}"
        )

    if alert.email_subject:
        add(
            "Observed email subject: "
            f"{alert.email_subject}"
        )

    for url in alert.email_urls:
        add(
            "Observed email URL: "
            f"{url}"
        )

    for domain in alert.email_domains:
        add(
            "Observed email domain: "
            f"{domain}"
        )

    if alert.email_attachment_name:
        if alert.email_attachment_content_type:
            add(
                "Observed email attachment: "
                f"{alert.email_attachment_name} "
                f"({alert.email_attachment_content_type})"
            )
        else:
            add(
                "Observed email attachment: "
                f"{alert.email_attachment_name}"
            )

    if alert.email_attachment_sha256:
        add(
            "Observed email attachment SHA-256: "
            f"{alert.email_attachment_sha256}"
        )

    if alert.email_user_clicked is not None:
        add(
            "Supplied email telemetry states "
            f"user_clicked={str(alert.email_user_clicked).lower()}; "
            "this Investigation stage does not independently "
            "verify that state"
        )

    if alert.email_attachment_executed is not None:
        add(
            "Supplied email telemetry states "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}; "
            "this Investigation stage does not independently "
            "verify that state"
        )

    # Ket qua Enrichment email da duoc chot bang logic deterministic, chi dung dung ket qua provider de TI khong bi lan IOC
    for finding in enrichment_assessment.relevant_findings:
        if finding.startswith("VirusTotal"):
            add(finding)

    return evidence


def _build_email_missing_evidence(
    alert: NormalizedAlert,
) -> list[str]:
    missing = [
        (
            "Original email header authentication and alignment evidence "
            "(for example SPF, DKIM, and DMARC results) for the message."
        ),
        (
            "Independent recipient interaction evidence from browser, proxy, "
            "DNS, endpoint, or identity telemetry establishing whether the "
            "URL was accessed or credentials were submitted."
        ),
        (
            "Evidence of credential submission, suspicious authentication, "
            "malicious execution, persistence, or other endpoint impact."
        ),
    ]

    if alert.email_body_excerpt:
        missing.insert(
            1,
            (
                "Original message headers needed to evaluate delivery path "
                "and message provenance beyond the normalized fields "
                "currently supplied."
            ),
        )
    else:
        missing.insert(
            1,
            (
                "Original message headers and message body or bounded body "
                "excerpt needed to evaluate delivery path, lure content, "
                "and message provenance beyond the normalized fields "
                "currently supplied."
            ),
        )

    if alert.email_attachment_name:
        missing.append(
            "Controlled file-analysis evidence for attachment "
            f"'{alert.email_attachment_name}' if attachment malware status "
            "must be determined."
        )

    if alert.email_user_clicked is not None:
        missing.append(
            "Independent browser/proxy/endpoint telemetry verifying the "
            f"supplied user_clicked={str(alert.email_user_clicked).lower()} "
            "state."
        )

    if alert.email_attachment_executed is not None:
        missing.append(
            "Independent endpoint telemetry verifying the supplied "
            "attachment_executed="
            f"{str(alert.email_attachment_executed).lower()} state."
        )

    return missing


def _apply_email_investigation_guardrail(
    alert: NormalizedAlert,
    enrichment: EnrichmentResult,
    enrichment_assessment: EnrichmentAssessment,
    result: InvestigationResult,
) -> InvestigationResult:
    """
    Finalize email-investigation semantics from normalized telemetry and
    deterministic Enrichment output.

    The email/message verdict is deliberately separated from user-impact and
    endpoint-compromise conclusions. Malicious/phishing TI about an exact IOC
    can support classifying the message as likely phishing without proving that
    the recipient interacted with it or that a host was compromised.
    """
    if not _is_email_security_alert(alert):
        return result

    phishing_ti_supported = (
        _email_ti_supports_phishing(
            enrichment
        )
    )

    hash_unknown = _email_hash_unknown_to_ti(
        enrichment
    )

    sender_reply_mismatch = bool(
        alert.email_sender
        and alert.email_reply_to
        and alert.email_sender.casefold()
        != alert.email_reply_to.casefold()
    )

    no_positive_impact_evidence = (
        alert.email_user_clicked is not True
        and alert.email_attachment_executed is not True
        and not alert.correlated_events
    )

    if (
        phishing_ti_supported
        and no_positive_impact_evidence
    ):
        # Voi email chi co bang chung gioi han, giu verdict phishing than trong va khong suy dien endpoint compromise
        result.verdict = (
            InvestigationVerdict.LIKELY_MALICIOUS
        )

    result.key_evidence = (
        _build_email_key_evidence(
            alert,
            enrichment_assessment,
        )
    )

    result.missing_evidence = (
        _build_email_missing_evidence(
            alert
        )
    )

    # Khong co bang chung user/endpoint impact thi khong tao host remediation chi tu reputation cua IOC
    if no_positive_impact_evidence:
        result.requires_remediation = False

    summary_parts: list[str] = []

    if phishing_ti_supported:
        summary_parts.append(
            "The available evidence supports classifying this message as "
            "likely malicious phishing. Threat intelligence for an exact "
            "email URL or domain includes malicious detections together with "
            "provider phishing/fraud categorization."
        )
    else:
        summary_parts.append(
            "The message remains suspicious and requires phishing "
            "investigation, but the currently supplied threat-intelligence "
            "evidence does not by itself establish a likely-malicious "
            "message verdict."
        )

    if sender_reply_mismatch:
        summary_parts.append(
            "The observed Sender and Reply-To addresses differ; this is a "
            "relevant email indicator but does not by itself prove spoofing."
        )

    if hash_unknown:
        summary_parts.append(
            "VirusTotal returned no object/report for the supplied attachment "
            "hash at lookup time, so attachment malware status is not "
            "established and the unknown result must not be treated as "
            "benignity."
        )

    if alert.email_user_clicked is not None:
        summary_parts.append(
            "The supplied telemetry states user_clicked="
            f"{str(alert.email_user_clicked).lower()}, but Investigation does "
            "not independently verify that state."
        )

    if alert.email_attachment_executed is not None:
        summary_parts.append(
            "The supplied telemetry states attachment_executed="
            f"{str(alert.email_attachment_executed).lower()}, but "
            "Investigation does not independently verify that state."
        )

    summary_parts.append(
        "No supplied evidence establishes credential submission, malicious "
        "attachment execution, persistence, or endpoint compromise. IOC "
        "reputation therefore supports the phishing assessment but does not "
        "justify claiming host compromise."
    )

    if not result.requires_remediation:
        summary_parts.append(
            "The current evidence does not justify disruptive endpoint "
            "remediation."
        )

    result.summary = " ".join(summary_parts)

    result.recommended_next_step = (
        "Review the original message headers and authentication/alignment "
        "evidence (including SPF, DKIM, and DMARC where available) without "
        "assuming spoofing from Sender/Reply-To mismatch alone. Correlate the "
        "recipient identity with browser, proxy, DNS, endpoint, and "
        "authentication telemetry to determine whether the URL was accessed "
        "or credentials were submitted. Analyze the attachment in a "
        "controlled file-analysis workflow if its malware status must be "
        "determined. Consider IOC blocking or message containment only through "
        "approved controls, and do not isolate a host or reset credentials "
        "solely from threat-intelligence reputation."
    )

    return result


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


def _apply_encoded_powershell_investigation_guardrail(
    alert: NormalizedAlert,
    result: InvestigationResult,
) -> InvestigationResult:
    """
    Chặn false-benign khi decoded PowerShell chỉ trông giống nội bộ/test/lab.

    Guardrail chỉ nâng các verdict benign-like/inconclusive khi không có correlated
    evidence hỗ trợ authorization. Nó không tự nâng suspicious thành malicious và
    không tự bật remediation.
    """
    if (
        not _is_encoded_powershell_alert(alert)
        or alert.correlated_events
    ):
        return result

    if result.verdict not in {
        InvestigationVerdict.BENIGN,
        InvestigationVerdict.LIKELY_BENIGN,
        InvestigationVerdict.INCONCLUSIVE,
    }:
        return result

    result.verdict = InvestigationVerdict.SUSPICIOUS

    decoded_values = list(
        dict.fromkeys(
            str(value)
            for value in alert.base64_decodings.values()
        )
    )

    key_evidence: list[str] = []

    if alert.script_block_text:
        key_evidence.append(
            "PowerShell script-block telemetry is present in the normalized alert."
        )

    if decoded_values:
        key_evidence.append(
            "Deterministic Base64 decoding produced: "
            + "; ".join(repr(value) for value in decoded_values)
            + ". The decoded text alone does not establish authorization or "
            "benign intent."
        )

    if "T1059.001" in result.validated_mitre_techniques:
        key_evidence.append(
            "Observed PowerShell behavior supports MITRE ATT&CK T1059.001."
        )

    if "T1027" in result.validated_mitre_techniques:
        key_evidence.append(
            "Observed deterministic encoded-content behavior supports MITRE "
            "ATT&CK T1027."
        )

    result.key_evidence = key_evidence

    authorization_gap = (
        "Authorization, change-management, baseline, or other correlated "
        "evidence establishing that the PowerShell execution was expected "
        "and approved."
    )

    if authorization_gap not in result.missing_evidence:
        result.missing_evidence.append(
            authorization_gap
        )

    result.summary = (
        "The case contains PowerShell script-block telemetry with deterministic "
        "Base64 decoding. The decoded text is observed content but does not by "
        "itself prove that the execution was authorized, expected, or benign. "
        "The behavior supports the validated PowerShell/encoded-content MITRE "
        "techniques, while correlated authorization and execution-context evidence "
        "is not supplied. The most defensible current verdict is suspicious, not "
        "benign. The supplied evidence does not by itself establish malware "
        "execution, persistence, credential theft, or endpoint compromise."
    )

    if not result.requires_remediation:
        result.summary += (
            " The current evidence does not justify disruptive remediation."
        )

    result.recommended_next_step = (
        "Verify whether the PowerShell execution was authorized by correlating "
        "process-tree and parent-process telemetry, user context, script origin, "
        "change or approval records, and surrounding endpoint/network events. "
        "Escalate remediation only if additional evidence establishes harmful "
        "activity or an unauthorized security impact."
    )

    return result


def apply_investigation_guardrails(
    alert: NormalizedAlert,
    result: InvestigationResult,
) -> InvestigationResult:
    """
    Apply deterministic consistency rules after LLM analysis.

    The guardrails preserve deterministic MITRE/FIM evidence, remove
    contradictory missing-evidence claims, and ensure that a verified
    security-weakening configuration change reaches remediation planning
    without falsely attributing malicious intent or an actor.
    """
    result.alert_id = alert.alert_id

    validated = _normalize_mitre_ids(
        result.validated_mitre_techniques
    )

    rejected = _normalize_mitre_ids(
        result.rejected_mitre_techniques
    )

    # Voi email, Investigation chi xac nhan hoac bac bo MITRE da co tu telemetry/Wazuh, khong giu technique do LLM tu suy dien
    if _is_email_security_alert(alert):
        mapped_email_ids = set(
            _normalize_mitre_ids(
                list(alert.mitre_ids)
            )
        )

        validated = [
            technique_id
            for technique_id in validated
            if technique_id in mapped_email_ids
        ]

        rejected = [
            technique_id
            for technique_id in rejected
            if technique_id in mapped_email_ids
        ]

    for technique_id in (
        _deterministically_supported_mitre(
            alert
        )
    ):
        if technique_id not in validated:
            validated.append(
                technique_id
            )

    validated_set = set(validated)

    rejected = [
        technique_id
        for technique_id in rejected
        if technique_id not in validated_set
    ]

    result.validated_mitre_techniques = (
        validated
    )

    result.rejected_mitre_techniques = (
        rejected
    )

    result = _apply_encoded_powershell_investigation_guardrail(
        alert,
        result,
    )

    if alert.fim_event:
        result.missing_evidence = (
            _normalize_fim_missing_evidence(
                result.missing_evidence,
                alert,
            )
        )
        result.summary = _sanitize_fim_summary(
            result.summary
        )

    if _is_security_weakening_fim_change(
        alert
    ):
        # Neu cau hinh hien tai yeu hon truoc, tao restoration plan nhung van phai qua human approval
        result.requires_remediation = True

        if result.verdict in {
            "benign",
            "likely_benign",
            "inconclusive",
        }:
            result.verdict = "suspicious"

        before, after = _fim_diff_values(
            alert
        )

        change_evidence = (
            f"Wazuh FIM recorded a security-weakening content change "
            f"from '{before}' to '{after}'."
        )

        if (
            before is not None
            and after is not None
            and change_evidence
            not in result.key_evidence
        ):
            result.key_evidence.append(
                change_evidence
            )

        remediation_note = (
            "The observed file state is security-weaker than the previous "
            "FIM-observed state. Remediation planning is required, but any "
            "restoration or other system-changing action must remain subject "
            "to SOC analyst approval because authorization and actor identity "
            "have not yet been established."
        )

        if remediation_note not in result.summary:
            result.summary = (
                result.summary.rstrip()
                + " "
                + remediation_note
            )

        result.recommended_next_step = (
            "Prepare a remediation plan to restore the previous "
            "security-enabling configuration only after SOC analyst approval. "
            "In parallel, review available access/process telemetry to determine "
            "whether the modification was authorized and, if possible, identify "
            "the responsible actor or process."
        )

    elif _is_security_enabling_fim_change(
        alert
    ):
        # Neu Wazuh cho thay cau hinh da chuyen tu tat sang bat, khong de RAG/model dao nguoc telemetry va tu tao remediation
        result.requires_remediation = False

        result.key_evidence = (
            _remove_reversed_fim_direction_claims(
                result.key_evidence,
                alert,
            )
        )
        result.contradictions = (
            _remove_reversed_fim_direction_claims(
                result.contradictions,
                alert,
            )
        )
        result.missing_evidence = (
            _remove_reversed_fim_direction_claims(
                result.missing_evidence,
                alert,
            )
        )

        before, after = _fim_diff_values(
            alert
        )

        change_evidence = (
            f"Wazuh FIM recorded a security-enabling content change "
            f"from '{before}' to '{after}'."
        )

        if (
            before is not None
            and after is not None
            and change_evidence
            not in result.key_evidence
        ):
            result.key_evidence.append(
                change_evidence
            )

        path = (
            alert.fim_path
            or "the monitored file"
        )

        result.summary = (
            f"Wazuh FIM recorded a modification to '{path}' from "
            f"'{before}' to '{after}'. The current FIM-observed state is "
            f"security-enabling relative to the previous observed state. "
            "The modification still warrants investigation because authorization "
            "and actor/process identity have not been established, but this "
            "security-enabling transition does not by itself justify remediation."
        )

        result.recommended_next_step = (
            "Continue investigation and monitoring. Verify whether the change "
            "was authorized and correlate available process, file-access, and "
            "user activity telemetry where available. Do not prepare a restoration "
            "solely because of this security-enabling transition."
        )

    return result


def _parse_investigation_result(raw: str) -> InvestigationResult:
    """Parse one InvestigationResult locally without another LLM call."""
    text = raw.strip()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        payload = None

        for index, char in enumerate(text):
            if char != "{":
                continue

            try:
                candidate, _ = decoder.raw_decode(
                    text[index:]
                )
            except json.JSONDecodeError:
                continue

            if isinstance(candidate, dict):
                payload = candidate
                break

        if payload is None:
            raise RuntimeError(
                "Investigation LLM did not return a JSON object."
            )

    if not isinstance(payload, dict):
        raise RuntimeError(
            "Investigation LLM output must be a JSON object."
        )

    try:
        return InvestigationResult.model_validate(
            payload
        )
    except Exception as exc:
        raise RuntimeError(
            "Investigation LLM returned JSON that does not match "
            "InvestigationResult."
        ) from exc



def run_investigation(
    alert: NormalizedAlert,
    triage: TriageResult,
    enrichment: EnrichmentResult,
    enrichment_assessment: EnrichmentAssessment,
    retrieved_knowledge: list[RetrievedChunk] | None = None,
) -> InvestigationResult:
    agent = create_investigation_agent()

    alert_context = json.dumps(
        _compact_alert_context(alert),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    triage_context = json.dumps(
        _compact_triage_context(triage),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    enrichment_context = json.dumps(
        _compact_enrichment_context(enrichment),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    assessment_context = json.dumps(
        _compact_assessment_context(enrichment_assessment),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    knowledge_context = _retrieved_knowledge_context(
        retrieved_knowledge or []
    )
    policy = _investigation_policy(
        alert,
        enrichment,
    )
    output_contract = _investigation_output_contract()

    task = Task(
        description=f"""
Investigate this security case and return the most defensible evidence-based verdict.

ALERT={alert_context}
TRIAGE={triage_context}
ENRICHMENT={enrichment_context}
ENRICHMENT_ASSESSMENT={assessment_context}
SOC_KNOWLEDGE={knowledge_context}

POLICY:
{policy}

OUTPUT JSON CONTRACT:
{output_contract}

Use confidence from 0.0 to 1.0. Keep summary and recommended_next_step concise.
""",
        expected_output=(
            "One valid JSON object matching the InvestigationResult contract."
        ),
        agent=agent,
    )

    crew = Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )

    result = crew.kickoff()

    investigation_result = _parse_investigation_result(
        result.raw
    )

    guarded_result = apply_investigation_guardrails(
        alert,
        investigation_result,
    )

    return _apply_email_investigation_guardrail(
        alert,
        enrichment,
        enrichment_assessment,
        guarded_result,
    )
