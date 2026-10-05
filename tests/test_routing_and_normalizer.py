import base64

import pytest

from soc_multi_agent.flows.soc_flow import SOCSupervisorFlow
from soc_multi_agent.schemas.enrichment import EnrichmentAssessment
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
    InvestigationVerdict,
)
from soc_multi_agent.schemas.state import CaseStatus
from soc_multi_agent.schemas.triage import (
    TriagePriority,
    TriageResult,
)
from soc_multi_agent.services.alert_filter import (
    get_candidate_reasons,
    is_candidate_alert,
)
from soc_multi_agent.services.normalizer import normalize_wazuh_alert


def _raw_alert(
    alert_id: str,
    *,
    rule_level: int = 5,
    rule_description: str = "Test alert",
    rule_groups: list[str] | None = None,
    mitre_ids: list[str] | None = None,
) -> dict:
    return {
        "id": alert_id,
        "timestamp": "2026-10-05T21:00:00+07:00",
        "agent": {
            "id": "001",
            "name": "WIN-11",
            "ip": "10.10.10.20",
        },
        "manager": {
            "name": "ubuntu-lab-soc",
        },
        "rule": {
            "id": "REG1000",
            "level": rule_level,
            "description": rule_description,
            "groups": rule_groups or [],
            "mitre": {
                "id": mitre_ids or [],
                "technique": [],
                "tactic": [],
            },
        },
    }


def _triage(
    alert_id: str = "route-001",
    *,
    requires_enrichment: bool = False,
    requires_investigation: bool = False,
) -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        category="test",
        priority=TriagePriority.LOW,
        confidence=0.5,
        suspicious=False,
        requires_enrichment=requires_enrichment,
        requires_investigation=requires_investigation,
        summary="Test triage",
        evidence=[],
        recommended_next_step="Continue",
    )


def _assessment(
    alert_id: str = "route-001",
    *,
    requires_investigation: bool = False,
) -> EnrichmentAssessment:
    return EnrichmentAssessment(
        alert_id=alert_id,
        risk_level="low",
        confidence=0.5,
        relevant_findings=[],
        inconsistencies=[],
        requires_investigation=requires_investigation,
        summary="Test enrichment",
        recommended_next_step="Continue",
    )


def _investigation(
    alert_id: str = "route-001",
    *,
    requires_remediation: bool = False,
) -> InvestigationResult:
    return InvestigationResult(
        alert_id=alert_id,
        verdict=InvestigationVerdict.SUSPICIOUS,
        confidence=0.5,
        key_evidence=[],
        contradictions=[],
        missing_evidence=[],
        validated_mitre_techniques=[],
        rejected_mitre_techniques=[],
        requires_remediation=requires_remediation,
        summary="Test investigation",
        recommended_next_step="Continue",
    )


@pytest.mark.parametrize(
    (
        "raw",
        "expected_candidate",
        "reason_fragment",
    ),
    [
        (
            _raw_alert(
                "filter-sca",
                rule_level=12,
                rule_description="SCA policy result",
                rule_groups=["sca"],
                mitre_ids=["T1059.001"],
            ),
            False,
            None,
        ),
        (
            _raw_alert(
                "filter-cis",
                rule_level=12,
                rule_description="CIS Microsoft Windows benchmark result",
                rule_groups=["windows"],
                mitre_ids=["T1059.001"],
            ),
            False,
            None,
        ),
        (
            _raw_alert(
                "filter-mitre",
                rule_level=5,
                mitre_ids=["T1059.001"],
            ),
            True,
            "MITRE ATT&CK mapping",
        ),
        (
            _raw_alert(
                "filter-level",
                rule_level=10,
            ),
            True,
            "rule level 10 >= 10",
        ),
        (
            _raw_alert(
                "filter-auth",
                rule_level=5,
                rule_groups=["authentication_failed"],
            ),
            True,
            "authentication_failed",
        ),
        (
            _raw_alert(
                "filter-low-no-signal",
                rule_level=9,
            ),
            False,
            None,
        ),
    ],
)
def test_alert_filter_candidate_rules(
    raw: dict,
    expected_candidate: bool,
    reason_fragment: str | None,
) -> None:
    candidate, reasons = is_candidate_alert(raw)

    assert candidate is expected_candidate
    assert reasons == get_candidate_reasons(raw)

    if reason_fragment is None:
        assert reasons == []
    else:
        assert any(
            reason_fragment in reason
            for reason in reasons
        )


def test_normalizer_decodes_utf16_powershell_encoded_command() -> None:
    decoded = "Write-Host SOC-LAB"
    encoded = base64.b64encode(
        decoded.encode("utf-16-le")
    ).decode("ascii")

    raw = _raw_alert(
        "norm-ps-utf16",
        rule_level=10,
        rule_groups=["windows", "powershell"],
        mitre_ids=["T1059.001", "T1027"],
    )
    raw["data"] = {
        "win": {
            "system": {
                "eventID": "4104",
                "providerName": "Microsoft-Windows-PowerShell",
                "channel": "Microsoft-Windows-PowerShell/Operational",
            },
            "eventdata": {
                "scriptBlockId": "block-utf16",
                "scriptBlockText": (
                    "powershell.exe -EncodedCommand "
                    + encoded
                ),
            },
        }
    }

    alert = normalize_wazuh_alert(raw)

    assert alert.script_block_id == "block-utf16"
    assert alert.base64_decodings == {
        encoded: decoded,
    }


def test_normalizer_email_lists_and_optional_bools() -> None:
    raw = _raw_alert(
        "norm-mail",
        rule_level=10,
        rule_groups=["email", "phishing"],
        mitre_ids=["T1566.002"],
    )
    raw["data"] = {
        "event_type": "phishing_email",
        "sender": "sender@example.invalid",
        "recipient": "user@example.local",
        "urls": [
            "https://example.invalid/a",
            "https://example.invalid/a",
            "https://example.invalid/b",
        ],
        "domain": "example.invalid",
        "user_clicked": "yes",
        "attachment_executed": "0",
    }

    alert = normalize_wazuh_alert(raw)

    assert alert.email_urls == [
        "https://example.invalid/a",
        "https://example.invalid/b",
    ]
    assert alert.email_domains == [
        "example.invalid",
    ]
    assert alert.email_user_clicked is True
    assert alert.email_attachment_executed is False


def test_normalizer_invalid_optional_bool_becomes_none() -> None:
    raw = _raw_alert(
        "norm-mail-unknown-bool",
        rule_level=10,
    )
    raw["data"] = {
        "event_type": "email",
        "user_clicked": "unknown",
        "attachment_executed": "",
    }

    alert = normalize_wazuh_alert(raw)

    assert alert.email_user_clicked is None
    assert alert.email_attachment_executed is None


def test_normalizer_preserves_correlated_event_security_context() -> None:
    raw = _raw_alert(
        "norm-related-main",
        rule_level=10,
    )
    related = _raw_alert(
        "norm-related-child",
        rule_level=8,
        rule_description="Related Defender event",
        rule_groups=["windows", "windows_defender"],
    )
    related["data"] = {
        "win": {
            "system": {
                "eventID": "1117",
                "providerName": "Microsoft-Windows-Windows Defender",
                "computer": "WIN-11",
                "channel": "Microsoft-Windows-Windows Defender/Operational",
                "severityValue": "INFORMATION",
                "message": "Threat quarantined",
            },
            "eventdata": {
                "detectionId": "det-001",
                "actionName": "Quarantine",
            },
        }
    }

    alert = normalize_wazuh_alert(
        raw,
        correlated_events=[related],
    )

    assert len(alert.correlated_events) == 1

    event = alert.correlated_events[0]

    assert event["alert_id"] == "norm-related-child"
    assert event["event_id"] == "1117"
    assert event["provider_name"] == (
        "Microsoft-Windows-Windows Defender"
    )
    assert event["event_data"]["detectionId"] == "det-001"
    assert event["event_data"]["actionName"] == "Quarantine"


@pytest.fixture
def flow(monkeypatch: pytest.MonkeyPatch) -> SOCSupervisorFlow:
    # Khong ghi PostgreSQL khi test routing
    monkeypatch.setattr(
        SOCSupervisorFlow,
        "_persist_state",
        lambda self: None,
    )
    return SOCSupervisorFlow()


def test_supervisor_routes_triage_to_monitor(
    flow: SOCSupervisorFlow,
) -> None:
    flow.state.triage = _triage()

    route = flow.route_after_triage()

    assert route == "monitor"
    assert flow.state.status == CaseStatus.MONITORING
    assert flow.state.audit_trail[-1].action == (
        "route_to_monitoring"
    )


@pytest.mark.parametrize(
    (
        "requires_enrichment",
        "requires_investigation",
    ),
    [
        (True, False),
        (False, True),
        (True, True),
    ],
)
def test_supervisor_routes_triage_to_deeper_analysis(
    flow: SOCSupervisorFlow,
    requires_enrichment: bool,
    requires_investigation: bool,
) -> None:
    flow.state.triage = _triage(
        requires_enrichment=requires_enrichment,
        requires_investigation=requires_investigation,
    )

    route = flow.route_after_triage()

    assert route == "deeper_analysis"
    assert flow.state.audit_trail[-1].action == (
        "route_to_enrichment"
    )


def test_supervisor_routes_enrichment_to_monitor(
    flow: SOCSupervisorFlow,
) -> None:
    flow.state.triage = _triage(
        requires_enrichment=True,
        requires_investigation=False,
    )
    flow.state.enrichment_assessment = _assessment(
        requires_investigation=False,
    )

    route = flow.route_after_enrichment()

    assert route == "monitor"
    assert flow.state.status == CaseStatus.MONITORING
    assert flow.state.audit_trail[-1].action == (
        "route_to_monitoring"
    )


@pytest.mark.parametrize(
    (
        "triage_requires_investigation",
        "assessment_requires_investigation",
    ),
    [
        (True, False),
        (False, True),
        (True, True),
    ],
)
def test_supervisor_routes_enrichment_to_investigation(
    flow: SOCSupervisorFlow,
    triage_requires_investigation: bool,
    assessment_requires_investigation: bool,
) -> None:
    flow.state.triage = _triage(
        requires_enrichment=True,
        requires_investigation=triage_requires_investigation,
    )
    flow.state.enrichment_assessment = _assessment(
        requires_investigation=assessment_requires_investigation,
    )

    route = flow.route_after_enrichment()

    assert route == "investigate"
    assert flow.state.audit_trail[-1].action == (
        "route_to_investigation"
    )


@pytest.mark.parametrize(
    (
        "requires_remediation",
        "expected_route",
        "expected_status",
        "expected_action",
    ),
    [
        (
            False,
            "monitor",
            CaseStatus.MONITORING,
            "route_to_monitoring",
        ),
        (
            True,
            "remediate",
            CaseStatus.INVESTIGATED,
            "route_to_remediation",
        ),
    ],
)
def test_supervisor_routes_after_investigation(
    flow: SOCSupervisorFlow,
    requires_remediation: bool,
    expected_route: str,
    expected_status: CaseStatus,
    expected_action: str,
) -> None:
    flow.state.status = CaseStatus.INVESTIGATED
    flow.state.investigation = _investigation(
        requires_remediation=requires_remediation,
    )

    route = flow.route_after_investigation()

    assert route == expected_route
    assert flow.state.status == expected_status
    assert flow.state.audit_trail[-1].action == expected_action


def test_supervisor_missing_results_fail_closed(
    flow: SOCSupervisorFlow,
) -> None:
    assert flow.route_after_triage() == "failed"
    assert flow.state.status == CaseStatus.FAILED

    flow.state.status = CaseStatus.NEW
    flow.state.triage = _triage()
    flow.state.enrichment_assessment = None

    assert flow.route_after_enrichment() == "failed"
    assert flow.state.status == CaseStatus.FAILED

    flow.state.status = CaseStatus.NEW
    flow.state.investigation = None

    assert flow.route_after_investigation() == "failed"
    assert flow.state.status == CaseStatus.FAILED
