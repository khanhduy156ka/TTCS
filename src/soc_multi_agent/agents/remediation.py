import re

from crewai import Agent, Crew, Process, Task

from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
)
from soc_multi_agent.schemas.remediation import (
    RemediationAction,
    RemediationPlan,
    RemediationPriority,
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


def create_remediation_agent() -> Agent:
    return Agent(
        role="SOC Remediation Analyst",
        goal=(
            "Develop safe, evidence-based remediation and "
            "containment proposals for SOC analysts."
        ),
        backstory=(
            "You are a SOC remediation analyst. "
            "You prepare response plans based only on validated "
            "investigation evidence. You do not automatically execute "
            "disruptive actions and you preserve human control over "
            "high-impact security decisions."
        ),
        llm=get_llm(),
        allow_delegation=False,
        verbose=True,
    )


def _compact_alert_context(
    alert: NormalizedAlert,
) -> dict:
    """
    Keep the normalized evidence needed for remediation while avoiding
    duplicate raw payloads in the LLM prompt.
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
    Extract the first explicit before/after content lines emitted by
    Wazuh report_changes.
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


def _build_fim_remediation_plan(
    alert: NormalizedAlert,
) -> RemediationPlan:
    """
    Deterministic remediation plan for a directly observed
    security-weakening FIM modification.

    This is intentionally a plan only. It does not execute the restoration.
    """
    before, after = _fim_diff_values(
        alert
    )

    path = (
        alert.fim_path
        or "the monitored file"
    )

    secure_state = (
        before
        or "the previous FIM-observed secure state"
    )

    weakened_state = (
        after
        or "the currently observed weaker state"
    )

    if alert.fim_sha256_before:
        verification = (
            f"After an approved restoration, verify that '{path}' contains "
            f"the previous FIM-observed secure state ('{secure_state}') and "
            f"that its SHA-256 matches the pre-change value "
            f"{alert.fim_sha256_before}. Confirm that Wazuh FIM records the "
            f"restoration and that no unexpected subsequent modification occurs."
        )
    else:
        verification = (
            f"After an approved restoration, verify that '{path}' contains "
            f"the previous FIM-observed secure state ('{secure_state}'). "
            f"Confirm that Wazuh FIM records the restoration and that no "
            f"unexpected subsequent modification occurs."
        )

    rollback = (
        "Before executing the approved restoration, preserve the current "
        "pre-remediation file content and integrity metadata. If the restoration "
        "causes an unexpected operational impact, an analyst may manually restore "
        "that preserved pre-remediation state after a separate review. Rollback "
        "must not be automatic."
    )

    action = RemediationAction(
        action=(
            f"Restore '{path}' to the previous FIM-observed secure state "
            f"('{secure_state}')."
        ),
        rationale=(
            f"Wazuh FIM directly observed the protected file change from "
            f"'{secure_state}' to '{weakened_state}'. The current state is "
            f"security-weaker than the previous observed state, while the "
            f"available evidence does not establish who or what performed the "
            f"change. Restoration should therefore be proposed, but only after "
            f"SOC analyst approval."
        ),
        impact=(
            f"Changes '{path}' back to the previous security-enabling content. "
            f"This is a system-changing action and may affect applications or "
            f"services that depend on the current configuration."
        ),
        approval_required=True,
        verification=verification,
        rollback=rollback,
    )

    monitoring_steps = [
        (
            f"Review available process, file-access, and user activity telemetry "
            f"around the FIM modification time to determine whether the change "
            f"was authorized and, where evidence permits, identify the responsible "
            f"actor or process."
        ),
        (
            f"Continue real-time Wazuh FIM monitoring for '{path}' and correlate "
            f"any subsequent modifications with endpoint activity."
        ),
        (
            "Check the protected directory for similar unexpected integrity "
            "changes without assuming persistence, lateral movement, or broader "
            "compromise unless additional evidence supports those conclusions."
        ),
    ]

    return RemediationPlan(
        alert_id=alert.alert_id,
        required=True,
        priority=RemediationPriority.MEDIUM,
        actions=[action],
        monitoring_steps=monitoring_steps,
        summary=(
            f"Wazuh FIM confirmed that '{path}' changed from the previous "
            f"security-enabling state '{secure_state}' to the weaker state "
            f"'{weakened_state}'. The change warrants a controlled restoration "
            f"plan, but the available evidence does not establish malicious "
            f"intent, compromise, or actor identity."
        ),
        recommended_next_step=(
            "Submit the restoration action for SOC analyst review. If approved, "
            "perform the restoration through an authorized response mechanism, "
            "verify the restored content and integrity evidence, and continue "
            "monitoring. If rejected, preserve the current state and document "
            "the analyst's decision for further investigation."
        ),
    )


def _qualify_compromise_language(
    text: str,
) -> str:
    """
    Avoid definitive compromise wording when Investigation did not establish
    a malicious verdict.
    """
    replacements = (
        (
            r"\bthe compromised host\b",
            "the potentially compromised host",
        ),
        (
            r"\bthe compromised system\b",
            "the potentially compromised system",
        ),
        (
            r"\bcompromised host\b",
            "potentially compromised host",
        ),
        (
            r"\bcompromised system\b",
            "potentially compromised system",
        ),
    )

    result = text

    for pattern, replacement in replacements:
        result = re.sub(
            pattern,
            replacement,
            result,
            flags=re.IGNORECASE,
        )

    return result


def apply_remediation_guardrails(
    investigation: InvestigationResult,
    remediation: RemediationPlan,
) -> RemediationPlan:
    """
    Apply deterministic safety and factual-consistency checks to
    the remediation plan after LLM generation.
    """
    evidence_collection_prefixes = (
        "capture ",
        "collect ",
        "acquire ",
        "export ",
        "retrieve ",
        "query ",
        "review ",
        "inspect ",
    )

    for action in remediation.actions:
        action_name = (
            action.action.strip().lower()
        )

        # Tac vu chi doc hoac thu thap bang chung thuong khong can rollback
        if action_name.startswith(
            evidence_collection_prefixes
        ):
            action.rollback = None

        # Disk image chi luu persistent storage, khong bao gom RAM volatile
        if (
            "disk image" in action_name
            or "disk imaging" in action_name
        ):
            verification_text = (
                action.verification.lower()
            )

            if (
                "volatile memory" in verification_text
                or "volatile data" in verification_text
                or "ram" in verification_text
            ):
                action.verification = (
                    "Validate the forensic disk image integrity using "
                    "cryptographic hashes and confirm that the acquired "
                    "image is readable and complete."
                )

    # Khong de LLM bien verdict khong malicious thanh ket luan host da bi compromise
    if investigation.verdict.value != "malicious":
        for action in remediation.actions:
            action.action = _qualify_compromise_language(
                action.action
            )
            action.rationale = _qualify_compromise_language(
                action.rationale
            )
            action.impact = _qualify_compromise_language(
                action.impact
            )
            action.verification = _qualify_compromise_language(
                action.verification
            )

            if action.rollback is not None:
                action.rollback = _qualify_compromise_language(
                    action.rollback
                )

        remediation.summary = (
            _qualify_compromise_language(
                remediation.summary
            )
        )
        remediation.recommended_next_step = (
            _qualify_compromise_language(
                remediation.recommended_next_step
            )
        )
        remediation.monitoring_steps = [
            _qualify_compromise_language(
                step
            )
            for step in remediation.monitoring_steps
        ]

    return remediation


def run_remediation(
    alert: NormalizedAlert,
    investigation: InvestigationResult,
) -> RemediationPlan:

    # Khong can goi LLM neu Investigation khong yeu cau remediation
    if not investigation.requires_remediation:
        return RemediationPlan(
            alert_id=alert.alert_id,
            required=False,
            priority=RemediationPriority.NONE,
            actions=[],
            monitoring_steps=[
                (
                    "Continue monitoring the affected asset for related "
                    "security events and correlate new evidence before escalation."
                ),
                (
                    "Review any unresolved evidence gaps identified by the "
                    "Investigation stage if additional telemetry becomes available."
                ),
            ],
            summary=(
                "No active remediation is required based on "
                "the current investigation evidence."
            ),
            recommended_next_step=(
                "Continue monitoring and correlation. "
                "Escalate only if new evidence increases risk."
            ),
        )

    # Thay doi FIM lam yeu cau hinh da co du bang chung deterministic de tao restoration proposal gioi han ma khong can LLM
    if _is_security_weakening_fim_change(
        alert
    ):
        return _build_fim_remediation_plan(
            alert
        )

    agent = create_remediation_agent()

    alert_context = _compact_alert_context(
        alert
    )

    task = Task(
        description=f"""
Develop a remediation plan for the following investigated security case.

Normalized alert:
{alert_context}

Investigation result:
{investigation.model_dump_json(indent=2)}

Requirements:
- Base the plan only on supplied evidence.
- Do not invent compromise indicators.
- The investigation has determined that remediation is required.
- Set required to true.
- Priority must be low, medium, high, or critical.
- Priority must not be "none".
- Propose only actions justified by the investigation evidence.
- Do not automatically block IP addresses.
- Do not automatically disable user accounts.
- Do not automatically terminate processes.
- Do not automatically modify firewall rules.
- Do not automatically modify Wazuh/SIEM rules or MITRE mappings.
- Any potentially disruptive response action must require human approval.
- Never recommend arbitrary shell commands as automatic actions.
- Each proposed remediation action must include:
  rationale, impact, approval requirement, verification,
  and rollback information when applicable.
- Do not claim that a disk image preserves volatile memory.
  Memory capture and disk imaging are separate evidence-collection actions.
- For evidence-collection or other read-only actions, do not invent rollback
  steps. Set rollback to null when rollback is not applicable.
- Put read-only investigation follow-up in monitoring_steps when it does not
  need to be represented as a remediation action.
- Do not cite a specific Windows Event ID unless that identifier is explicitly
  supported by supplied evidence or is necessary and known to be correct.
- Do not describe a host as definitively compromised unless the supplied
  investigation evidence establishes compromise. Prefer "affected",
  "suspected", or "potentially compromised" when appropriate.
- Do not claim persistence, lateral movement, privilege escalation, or data
  exfiltration has occurred unless supplied evidence establishes it.
- Use monitoring_steps for post-remediation verification,
  continued observation, or correlation.
- Keep the plan concise and suitable for a SOC analyst.
""",
        expected_output=(
            "A structured RemediationPlan containing whether "
            "remediation is required, priority, proposed actions, "
            "monitoring steps, summary, and recommended next step."
        ),
        agent=agent,
        output_pydantic=RemediationPlan,
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
            "CrewAI did not return a valid RemediationPlan."
        )

    remediation = result.pydantic

    # Giu invariant giua cac stage, Investigation da yeu cau remediation thi plan khong duoc dao nguoc quyet dinh
    if not remediation.required:
        raise RuntimeError(
            "RemediationPlan contradicts InvestigationResult: "
            "requires_remediation=True but required=False."
        )

    return apply_remediation_guardrails(
        investigation,
        remediation,
    )
