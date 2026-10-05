from datetime import datetime, timedelta, timezone
from html import escape

import streamlit as st

from soc_multi_agent.schemas.state import (
    CaseStatus,
    SOCSharedState,
)
from soc_multi_agent.services.case_repository import (
    list_cases,
    load_case,
)
from soc_multi_agent.services.human_review import (
    approve_case,
    reject_case,
)


VN_TIMEZONE = timezone(
    timedelta(hours=7)
)


st.set_page_config(
    page_title="SOC Multi-Agent",
    page_icon="🛡️",
    layout="wide",
)


def apply_ui_styles() -> None:
    st.markdown(
        """
<style>
/* General spacing */
.block-container {
    max-width: 1500px;
    padding-top: 3rem;
    padding-bottom: 4rem;
}

/* Text inside table-like columns */
.soc-cell {
    width: 100%;
    min-width: 0;
    overflow-wrap: anywhere;
    word-break: normal;
    white-space: normal;
    line-height: 1.45;
}

/* Summary card value */
.soc-summary-value {
    width: 100%;
    min-width: 0;
    overflow-wrap: anywhere;
    word-break: normal;
    white-space: normal;
    font-size: 1.45rem;
    font-weight: 650;
    line-height: 1.25;
    margin-top: 0.25rem;
}

/* Slightly soften bordered Streamlit containers */
div[data-testid="stVerticalBlockBorderWrapper"] {
    border-radius: 0.75rem;
}

/* Keep columns aligned at the top */
div[data-testid="stHorizontalBlock"] {
    align-items: stretch;
}

/* Give tabs a little more breathing room */
button[data-baseweb="tab"] {
    padding-left: 0.8rem;
    padding-right: 0.8rem;
}

/* Reduce unnecessary whitespace inside case rows */
.soc-row-separator {
    border-bottom: 1px solid rgba(128, 128, 128, 0.16);
    margin: 0.15rem 0 0.55rem 0;
}
</style>
        """,
        unsafe_allow_html=True,
    )


def refresh_app() -> None:
    st.rerun()


def format_label(
    value: str | None,
) -> str:
    if not value:
        return "-"

    return value.replace(
        "_",
        " ",
    ).strip().title()


def format_datetime(
    value: datetime | None,
) -> str:
    if value is None:
        return "-"

    if value.tzinfo is None:
        value = value.replace(
            tzinfo=timezone.utc
        )

    local_value = value.astimezone(
        VN_TIMEZONE
    )

    return local_value.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def render_wrapped_text(
    value: str | None,
    bold: bool = False,
) -> None:
    safe_value = escape(
        str(value or "-")
    )

    weight = (
        "600"
        if bold
        else "400"
    )

    html = (
        '<div class="soc-cell" '
        f'style="font-weight:{weight};">'
        f"{safe_value}"
        "</div>"
    )

    st.markdown(
        html,
        unsafe_allow_html=True,
    )


def render_summary_value(
    value: str,
) -> None:
    safe_value = escape(value)

    html = (
        '<div class="soc-summary-value">'
        f"{safe_value}"
        "</div>"
    )

    st.markdown(
        html,
        unsafe_allow_html=True,
    )


def render_case_summary(
    state: SOCSharedState,
) -> None:
    status = format_label(
        state.status.value
    )

    priority = "-"

    if state.triage is not None:
        priority = format_label(
            state.triage.priority.value
        )

    verdict = "-"

    if state.investigation is not None:
        verdict = format_label(
            state.investigation.verdict.value
        )

    approval = "Not Required"

    if state.human_approval_required:
        if state.human_approved is True:
            approval = "Approved"

        elif state.human_approved is False:
            approval = "Rejected"

        else:
            approval = "Pending"

    values = [
        (
            "Status",
            status,
        ),
        (
            "Priority",
            priority,
        ),
        (
            "Verdict",
            verdict,
        ),
        (
            "Human Approval",
            approval,
        ),
    ]

    columns = st.columns(
        [
            1.15,
            0.9,
            1.15,
            1.0,
        ],
        gap="large",
    )

    for column, (
        label,
        value,
    ) in zip(
        columns,
        values,
    ):
        with column:
            with st.container(
                border=True
            ):
                st.caption(
                    label
                )

                render_summary_value(
                    value
                )


def render_case_list(
    cases: list[dict],
) -> None:
    if not cases:
        st.info(
            "No cases are available."
        )
        return

    column_widths = [
        2.8,
        2.0,
        1.0,
        1.5,
        1.4,
        2.1,
    ]

    headers = [
        "Case ID",
        "Status",
        "Priority",
        "Category",
        "Host",
        "Updated",
    ]

    header_columns = st.columns(
        column_widths,
        gap="large",
    )

    for column, header in zip(
        header_columns,
        headers,
    ):
        with column:
            render_wrapped_text(
                header,
                bold=True,
            )

    st.divider()

    for case in cases:
        row = st.columns(
            column_widths,
            gap="large",
        )

        host = (
            case["computer"]
            or case["agent_name"]
            or "-"
        )

        values = [
            case["case_id"],
            format_label(
                case["status"]
            ),
            format_label(
                case["priority"]
            ),
            format_label(
                case["category"]
            ),
            host,
            format_datetime(
                case["updated_at"]
            ),
        ]

        for column, value in zip(
            row,
            values,
        ):
            with column:
                render_wrapped_text(
                    value
                )

        st.markdown(
            '<div class="soc-row-separator"></div>',
            unsafe_allow_html=True,
        )


def render_alert(
    state: SOCSharedState,
) -> None:
    if state.alert is None:
        st.info(
            "No alert data available."
        )
        return

    st.json(
        state.alert.model_dump(
            mode="json",
        )
    )


def render_triage(
    state: SOCSharedState,
) -> None:
    if state.triage is None:
        st.info(
            "This case has not completed triage."
        )
        return

    triage = state.triage

    col1, col2, col3 = st.columns(
        3,
        gap="large",
    )

    with col1:
        st.metric(
            "Category",
            format_label(
                triage.category
            ),
        )

    with col2:
        st.metric(
            "Priority",
            format_label(
                triage.priority.value
            ),
        )

    with col3:
        st.metric(
            "Confidence",
            f"{triage.confidence:.0%}",
        )

    st.write(
        "**Suspicious:**",
        triage.suspicious,
    )

    st.write(
        "**Requires enrichment:**",
        triage.requires_enrichment,
    )

    st.write(
        "**Requires investigation:**",
        triage.requires_investigation,
    )

    st.subheader(
        "Summary"
    )

    st.write(
        triage.summary
    )

    st.subheader(
        "Evidence"
    )

    if triage.evidence:
        for evidence in triage.evidence:
            st.write(
                f"- {evidence}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Recommended next step"
    )

    st.write(
        triage.recommended_next_step
    )


def render_enrichment(
    state: SOCSharedState,
) -> None:
    if state.enrichment is None:
        st.info(
            "No enrichment data is available."
        )
        return

    enrichment = state.enrichment

    st.subheader(
        "Entities"
    )

    if enrichment.entities:
        for entity in enrichment.entities:
            with st.expander(
                (
                    f"{format_label(entity.entity_type.value)}: "
                    f"{entity.value}"
                )
            ):
                st.write(
                    "**Type:**",
                    format_label(
                        entity.entity_type.value
                    ),
                )

                st.write(
                    "**Value:**",
                    entity.value,
                )

                st.write(
                    "**Source field:**",
                    entity.source_field,
                )
    else:
        st.write(
            "No entities extracted."
        )

    st.subheader(
        "MITRE ATT&CK"
    )

    if enrichment.mitre_techniques:
        for technique in (
            enrichment.mitre_techniques
        ):
            with st.expander(
                (
                    f"{technique.technique_id} - "
                    f"{technique.name}"
                )
            ):
                st.write(
                    "**Tactics:**",
                    ", ".join(
                        technique.tactics
                    )
                    or "-",
                )

                st.write(
                    "**Platforms:**",
                    ", ".join(
                        technique.platforms
                    )
                    or "-",
                )

                st.write(
                    "**Revoked:**",
                    technique.revoked,
                )

                st.write(
                    "**Deprecated:**",
                    technique.deprecated,
                )

                if technique.source_url:
                    st.write(
                        "**Source:**",
                        technique.source_url,
                    )
    else:
        st.write(
            "No MITRE ATT&CK techniques."
        )

    st.subheader(
        "Threat Intelligence"
    )

    if enrichment.threat_intel:
        for finding in enrichment.threat_intel:
            with st.expander(
                (
                    f"{finding.provider}: "
                    f"{finding.value}"
                )
            ):
                st.json(
                    finding.model_dump(
                        mode="json",
                    )
                )
    else:
        st.write(
            "No threat intelligence findings."
        )

    st.subheader(
        "Enrichment Assessment"
    )

    assessment = (
        state.enrichment_assessment
    )

    if assessment is None:
        st.info(
            "No enrichment assessment is available."
        )
        return

    col1, col2, col3 = st.columns(
        3,
        gap="large",
    )

    with col1:
        st.metric(
            "Risk Level",
            format_label(
                assessment.risk_level
            ),
        )

    with col2:
        st.metric(
            "Confidence",
            f"{assessment.confidence:.0%}",
        )

    with col3:
        st.metric(
            "Investigation Required",
            (
                "Yes"
                if assessment.requires_investigation
                else "No"
            ),
        )

    st.write(
        "**Summary:**",
        assessment.summary,
    )

    st.write(
        "**Relevant findings:**"
    )

    if assessment.relevant_findings:
        for item in assessment.relevant_findings:
            st.write(
                f"- {item}"
            )
    else:
        st.write(
            "None"
        )

    st.write(
        "**Inconsistencies:**"
    )

    if assessment.inconsistencies:
        for item in assessment.inconsistencies:
            st.write(
                f"- {item}"
            )
    else:
        st.write(
            "None"
        )

    st.write(
        "**Recommended next step:**",
        assessment.recommended_next_step,
    )


def render_investigation(
    state: SOCSharedState,
) -> None:
    if state.investigation is None:
        st.info(
            "This case has not reached investigation."
        )
        return

    investigation = state.investigation

    col1, col2, col3 = st.columns(
        3,
        gap="large",
    )

    with col1:
        st.metric(
            "Verdict",
            format_label(
                investigation.verdict.value
            ),
        )

    with col2:
        st.metric(
            "Confidence",
            f"{investigation.confidence:.0%}",
        )

    with col3:
        st.metric(
            "Remediation Required",
            (
                "Yes"
                if investigation.requires_remediation
                else "No"
            ),
        )

    st.subheader(
        "Summary"
    )

    st.write(
        investigation.summary
    )

    st.subheader(
        "Key Evidence"
    )

    if investigation.key_evidence:
        for item in investigation.key_evidence:
            st.write(
                f"- {item}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Contradictions"
    )

    if investigation.contradictions:
        for item in investigation.contradictions:
            st.write(
                f"- {item}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Missing Evidence"
    )

    if investigation.missing_evidence:
        for item in investigation.missing_evidence:
            st.write(
                f"- {item}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Validated MITRE ATT&CK Techniques"
    )

    if investigation.validated_mitre_techniques:
        for technique in (
            investigation.validated_mitre_techniques
        ):
            st.write(
                f"- {technique}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Rejected MITRE ATT&CK Techniques"
    )

    if investigation.rejected_mitre_techniques:
        for technique in (
            investigation.rejected_mitre_techniques
        ):
            st.write(
                f"- {technique}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Recommended next step"
    )

    st.write(
        investigation.recommended_next_step
    )


def render_remediation(
    state: SOCSharedState,
) -> None:
    if state.remediation is None:
        st.info(
            "No remediation plan is available."
        )
        return

    remediation = state.remediation

    col1, col2 = st.columns(
        2,
        gap="large",
    )

    with col1:
        st.metric(
            "Required",
            (
                "Yes"
                if remediation.required
                else "No"
            ),
        )

    with col2:
        st.metric(
            "Priority",
            format_label(
                remediation.priority.value
            ),
        )

    st.subheader(
        "Summary"
    )

    st.write(
        remediation.summary
    )

    st.subheader(
        "Proposed Actions"
    )

    if not remediation.actions:
        st.write(
            "No remediation actions were proposed."
        )

    for index, action in enumerate(
        remediation.actions,
        start=1,
    ):
        with st.expander(
            (
                f"Action {index}: "
                f"{action.action}"
            ),
            expanded=True,
        ):
            st.write(
                "**Rationale:**",
                action.rationale,
            )

            st.write(
                "**Impact:**",
                action.impact,
            )

            st.write(
                "**Approval required:**",
                action.approval_required,
            )

            st.write(
                "**Verification:**",
                action.verification,
            )

            st.write(
                "**Rollback:**",
                (
                    action.rollback
                    or "Not applicable"
                ),
            )

    st.subheader(
        "Monitoring Steps"
    )

    if remediation.monitoring_steps:
        for step in remediation.monitoring_steps:
            st.write(
                f"- {step}"
            )
    else:
        st.write(
            "None"
        )

    st.subheader(
        "Recommended next step"
    )

    st.write(
        remediation.recommended_next_step
    )


def render_human_decision(
    state: SOCSharedState,
) -> None:
    st.subheader(
        "Human Review"
    )

    if state.human_decision is None:
        st.write(
            "No analyst decision has been recorded."
        )
        return

    decision = state.human_decision

    if decision.approved:
        st.success(
            "Remediation plan approved."
        )
    else:
        st.error(
            "Remediation plan rejected."
        )

    st.write(
        "**Analyst:**",
        decision.analyst,
    )

    st.write(
        "**Reason:**",
        (
            decision.reason
            or "No reason provided"
        ),
    )

    st.write(
        "**Decision time:**",
        format_datetime(
            decision.decided_at
        ),
    )


def render_audit_trail(
    state: SOCSharedState,
) -> None:
    if not state.audit_trail:
        st.info(
            "No audit events are available."
        )
        return

    for index, event in enumerate(
        state.audit_trail,
        start=1,
    ):
        with st.expander(
            (
                f"{index}. "
                f"{format_label(event.stage)} / "
                f"{format_label(event.action)}"
            )
        ):
            st.write(
                "**Timestamp:**",
                format_datetime(
                    event.timestamp
                ),
            )

            st.write(
                "**Stage:**",
                format_label(
                    event.stage
                ),
            )

            st.write(
                "**Action:**",
                format_label(
                    event.action
                ),
            )

            st.write(
                "**Detail:**",
                event.detail or "-",
            )


def render_performance(
    state: SOCSharedState,
) -> None:
    if not state.stage_durations:
        st.info(
            "No performance measurements available."
        )
        return

    total = sum(
        state.stage_durations.values()
    )

    st.metric(
        "Total measured processing time",
        f"{total:.3f} seconds",
    )

    st.divider()

    for stage, duration in (
        state.stage_durations.items()
    ):
        col1, col2 = st.columns(
            [2, 1],
            gap="large",
        )

        with col1:
            render_wrapped_text(
                format_label(stage)
            )

        with col2:
            render_wrapped_text(
                f"{duration:.3f} s"
            )


def render_hitl_controls(
    state: SOCSharedState,
) -> None:
    if (
        state.status
        != CaseStatus.PENDING_HUMAN_APPROVAL
    ):
        return

    st.divider()

    st.header(
        "Human-in-the-Loop Decision"
    )

    st.warning(
        "The remediation plan requires SOC analyst "
        "approval. Approval records the decision only; "
        "it does not automatically execute remediation "
        "actions."
    )

    analyst = st.text_input(
        "Analyst",
        placeholder="soc-analyst-01",
        key=f"analyst_{state.case_id}",
    )

    reason = st.text_area(
        "Decision reason",
        placeholder=(
            "Describe why the remediation plan "
            "should be approved or rejected."
        ),
        key=f"reason_{state.case_id}",
    )

    col1, col2 = st.columns(
        2,
        gap="large",
    )

    with col1:
        if st.button(
            "Approve remediation",
            type="primary",
            use_container_width=True,
            key=f"approve_{state.case_id}",
        ):
            if not analyst.strip():
                st.error(
                    "Analyst name is required."
                )
            else:
                try:
                    approve_case(
                        case_id=state.case_id,
                        analyst=analyst,
                        reason=reason,
                    )

                    st.success(
                        "Remediation plan approved "
                        "and saved to PostgreSQL."
                    )

                    refresh_app()

                except Exception as error:
                    st.error(
                        f"Approval failed: {error}"
                    )

    with col2:
        if st.button(
            "Reject remediation",
            use_container_width=True,
            key=f"reject_{state.case_id}",
        ):
            if not analyst.strip():
                st.error(
                    "Analyst name is required."
                )
            else:
                try:
                    reject_case(
                        case_id=state.case_id,
                        analyst=analyst,
                        reason=reason,
                    )

                    st.success(
                        "Remediation plan rejected "
                        "and saved to PostgreSQL."
                    )

                    refresh_app()

                except Exception as error:
                    st.error(
                        f"Rejection failed: {error}"
                    )


def main() -> None:
    apply_ui_styles()

    st.title(
        "SOC Multi-Agent Dashboard"
    )

    st.caption(
        "AI-assisted Security Operations Center"
    )

    try:
        cases = list_cases(
            limit=100,
        )

    except Exception as error:
        st.error(
            (
                "Unable to load cases from PostgreSQL: "
                f"{error}"
            )
        )
        return

    if not cases:
        st.info(
            "No SOC cases are currently stored."
        )
        return

    st.sidebar.header(
        "Cases"
    )

    if st.sidebar.button(
        "Refresh cases",
        use_container_width=True,
    ):
        refresh_app()

    status_options = [
        "all",
        *sorted(
            {
                case["status"]
                for case in cases
            }
        ),
    ]

    selected_status = (
        st.sidebar.selectbox(
            "Status filter",
            status_options,
            format_func=format_label,
        )
    )

    if selected_status != "all":
        visible_cases = [
            case
            for case in cases
            if case["status"]
            == selected_status
        ]
    else:
        visible_cases = cases

    if not visible_cases:
        st.warning(
            "No cases match the selected filter."
        )
        return

    case_ids = [
        case["case_id"]
        for case in visible_cases
    ]

    selected_case_id = (
        st.sidebar.selectbox(
            "Select case",
            case_ids,
        )
    )

    st.header(
        "Case List"
    )

    render_case_list(
        visible_cases
    )

    try:
        state = load_case(
            selected_case_id
        )

    except Exception as error:
        st.error(
            f"Unable to load case: {error}"
        )
        return

    if state is None:
        st.error(
            "The selected case no longer exists."
        )
        return

    st.divider()

    st.header(
        f"Case: {state.case_id}"
    )

    render_case_summary(
        state
    )

    st.write("")

    if state.alert is not None:
        detail_col1, detail_col2 = st.columns(
            [
                1.7,
                1.0,
            ],
            gap="large",
        )

        with detail_col1:
            st.write(
                "**Alert:**",
                state.alert.rule_description,
            )

            st.write(
                "**Alert ID:**",
                state.alert.alert_id,
            )

        with detail_col2:
            st.write(
                "**Host:**",
                (
                    state.alert.computer
                    or state.alert.agent_name
                ),
            )

            st.write(
                "**Agent:**",
                state.alert.agent_name,
            )

    st.write("")

    (
        alert_tab,
        triage_tab,
        enrichment_tab,
        investigation_tab,
        remediation_tab,
        human_tab,
        audit_tab,
        performance_tab,
    ) = st.tabs(
        [
            "Alert",
            "Triage",
            "Enrichment",
            "Investigation",
            "Remediation",
            "Human Review",
            "Audit Trail",
            "Performance",
        ]
    )

    with alert_tab:
        render_alert(
            state
        )

    with triage_tab:
        render_triage(
            state
        )

    with enrichment_tab:
        render_enrichment(
            state
        )

    with investigation_tab:
        render_investigation(
            state
        )

    with remediation_tab:
        render_remediation(
            state
        )

    with human_tab:
        render_human_decision(
            state
        )

    with audit_tab:
        render_audit_trail(
            state
        )

    with performance_tab:
        render_performance(
            state
        )

    render_hitl_controls(
        state
    )


if __name__ == "__main__":
    main()