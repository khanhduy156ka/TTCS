from soc_multi_agent.agents.enrichment import apply_enrichment_guardrails
from soc_multi_agent.agents.investigation import (
    _apply_email_investigation_guardrail,
    apply_investigation_guardrails,
)
from soc_multi_agent.agents.triage import apply_triage_guardrails
from soc_multi_agent.schemas.enrichment import (
    EnrichmentAssessment,
    EnrichmentResult,
    EntityType,
    MitreTechniqueContext,
    ThreatIntelFinding,
)
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
    InvestigationVerdict,
)
from soc_multi_agent.schemas.triage import (
    TriagePriority,
    TriageResult,
)
from soc_multi_agent.services.normalizer import normalize_wazuh_alert


def _raw_base_alert(
    alert_id: str,
    *,
    rule_id: str,
    rule_level: int,
    rule_description: str,
    rule_groups: list[str],
    mitre_ids: list[str] | None = None,
) -> dict:
    return {
        "id": alert_id,
        "timestamp": "2026-10-05T20:00:00+07:00",
        "agent": {
            "id": "001",
            "name": "WIN-11",
            "ip": "10.10.10.20",
        },
        "manager": {
            "name": "ubuntu-lab-soc",
        },
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_description,
            "groups": rule_groups,
            "mitre": {
                "id": mitre_ids or [],
                "technique": [],
                "tactic": [],
            },
        },
    }


def _triage_result(
    alert_id: str,
    *,
    suspicious: bool = False,
    requires_enrichment: bool = False,
    requires_investigation: bool = False,
) -> TriageResult:
    return TriageResult(
        alert_id=alert_id,
        category="unknown",
        priority=TriagePriority.LOW,
        confidence=0.5,
        suspicious=suspicious,
        requires_enrichment=requires_enrichment,
        requires_investigation=requires_investigation,
        summary="Initial model result",
        evidence=[],
        recommended_next_step="Initial next step",
    )


def _enrichment_assessment(
    alert_id: str,
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
        summary="Initial model result",
        recommended_next_step="Initial next step",
    )


def _investigation_result(
    alert_id: str,
    *,
    verdict: InvestigationVerdict = InvestigationVerdict.BENIGN,
    requires_remediation: bool = False,
    validated_mitre_techniques: list[str] | None = None,
    rejected_mitre_techniques: list[str] | None = None,
) -> InvestigationResult:
    return InvestigationResult(
        alert_id=alert_id,
        verdict=verdict,
        confidence=0.5,
        key_evidence=[],
        contradictions=[],
        missing_evidence=[],
        validated_mitre_techniques=validated_mitre_techniques or [],
        rejected_mitre_techniques=rejected_mitre_techniques or [],
        requires_remediation=requires_remediation,
        summary="Initial model result",
        recommended_next_step="Initial next step",
    )


def test_suspicious_encoded_powershell_guardrails() -> None:
    encoded = "U09DLUxBQi1QUy1FMkUtUkFHLTE="

    raw = _raw_base_alert(
        "reg-ps-001",
        rule_id="92057",
        rule_level=10,
        rule_description="PowerShell script block contains encoded content",
        rule_groups=["windows", "powershell"],
        mitre_ids=["T1059.001", "T1027"],
    )
    raw["data"] = {
        "win": {
            "system": {
                "eventID": "4104",
                "providerName": "Microsoft-Windows-PowerShell",
                "computer": "WIN-11",
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "severityValue": "WARNING",
            },
            "eventdata": {
                "scriptBlockId": "reg-ps-block-001",
                "scriptBlockText": (
                    "powershell.exe -EncodedCommand "
                    + encoded
                ),
            },
        }
    }

    alert = normalize_wazuh_alert(raw)

    assert alert.base64_decodings == {
        encoded: "SOC-LAB-PS-E2E-RAG-1"
    }

    triage = apply_triage_guardrails(
        alert,
        _triage_result(alert.alert_id),
    )

    assert triage.suspicious is True
    assert triage.requires_enrichment is True
    assert triage.requires_investigation is True
    assert any(
        "Deterministic Base64 decoding"
        in item
        for item in triage.evidence
    )

    enrichment = EnrichmentResult(
        alert_id=alert.alert_id,
        mitre_techniques=[
            MitreTechniqueContext(
                technique_id="T1059.001",
                name="PowerShell",
            ),
            MitreTechniqueContext(
                technique_id="T1027",
                name="Obfuscated Files or Information",
            ),
        ],
    )
    assessment = apply_enrichment_guardrails(
        alert,
        enrichment,
        _enrichment_assessment(alert.alert_id),
    )

    assert assessment.requires_investigation is True
    assert any(
        "decoded Base64"
        in item
        or "Base64 decoding"
        in item
        for item in assessment.relevant_findings
    )

    investigation = apply_investigation_guardrails(
        alert,
        _investigation_result(alert.alert_id),
    )

    assert investigation.verdict == InvestigationVerdict.SUSPICIOUS
    assert investigation.requires_remediation is False
    assert set(
        investigation.validated_mitre_techniques
    ) == {
        "T1059.001",
        "T1027",
    }
    assert any(
        "Authorization"
        in item
        for item in investigation.missing_evidence
    )


def test_fim_security_weakening_requires_investigation_and_remediation() -> None:
    raw = _raw_base_alert(
        "reg-fim-001",
        rule_id="550",
        rule_level=7,
        rule_description="Integrity checksum changed",
        rule_groups=["syscheck"],
        mitre_ids=["T1565.001"],
    )
    raw["syscheck"] = {
        "event": "modified",
        "path": r"C:\SOC-Lab\Protected\config.txt",
        "mode": "scheduled",
        "diff": "< mode=secure\n> mode=disabled",
        "changed_attributes": ["size", "sha256"],
        "sha256_before": "a" * 64,
        "sha256_after": "b" * 64,
    }

    alert = normalize_wazuh_alert(raw)

    enrichment = EnrichmentResult(
        alert_id=alert.alert_id,
    )
    assessment = _enrichment_assessment(
        alert.alert_id,
        requires_investigation=False,
    )
    assessment.relevant_findings = [
        "The actual content is not known",
    ]

    guarded_assessment = apply_enrichment_guardrails(
        alert,
        enrichment,
        assessment,
    )

    assert guarded_assessment.requires_investigation is True
    assert all(
        "content is not known"
        not in item.lower()
        for item in guarded_assessment.relevant_findings
    )
    assert any(
        "mode=secure"
        in item
        and "mode=disabled"
        in item
        for item in guarded_assessment.relevant_findings
    )

    investigation = apply_investigation_guardrails(
        alert,
        _investigation_result(
            alert.alert_id,
            verdict=InvestigationVerdict.BENIGN,
            requires_remediation=False,
        ),
    )

    assert investigation.verdict == InvestigationVerdict.SUSPICIOUS
    assert investigation.requires_remediation is True
    assert "T1565.001" in investigation.validated_mitre_techniques
    assert any(
        "security-weakening"
        in item
        for item in investigation.key_evidence
    )
    assert "SOC analyst approval" in investigation.summary


def test_fim_security_enabling_does_not_trigger_restoration() -> None:
    raw = _raw_base_alert(
        "reg-fim-002",
        rule_id="550",
        rule_level=7,
        rule_description="Integrity checksum changed",
        rule_groups=["syscheck"],
        mitre_ids=["T1565.001"],
    )
    raw["syscheck"] = {
        "event": "modified",
        "path": r"C:\SOC-Lab\Protected\config.txt",
        "mode": "scheduled",
        "diff": "< mode=disabled\n> mode=secure",
        "changed_attributes": ["size", "sha256"],
    }

    alert = normalize_wazuh_alert(raw)

    result = _investigation_result(
        alert.alert_id,
        verdict=InvestigationVerdict.SUSPICIOUS,
        requires_remediation=True,
    )
    result.key_evidence = [
        "The change disabled a security setting and requires restoration",
    ]

    investigation = apply_investigation_guardrails(
        alert,
        result,
    )

    assert investigation.requires_remediation is False
    assert any(
        "security-enabling"
        in item
        for item in investigation.key_evidence
    )
    assert "does not by itself justify remediation" in investigation.summary


def test_phishing_email_ti_does_not_imply_endpoint_compromise() -> None:
    attachment_hash = "1" * 64

    raw = _raw_base_alert(
        "reg-mail-001",
        rule_id="100500",
        rule_level=10,
        rule_description="Structured phishing email telemetry",
        rule_groups=["email", "phishing"],
        mitre_ids=["T1566.002"],
    )
    raw["data"] = {
        "event_type": "phishing_email",
        "sender": "billing@example.invalid",
        "reply_to": "collect@example.test",
        "recipient": "user@example.local",
        "subject": "Invoice review required",
        "body_excerpt": "Review the attached invoice and sign in.",
        "urls": [
            "https://login-example.invalid/verify",
        ],
        "domains": [
            "login-example.invalid",
        ],
        "attachment_name": "invoice.pdf",
        "attachment_content_type": "application/pdf",
        "attachment_sha256": attachment_hash,
        "user_clicked": False,
        "attachment_executed": False,
    }

    alert = normalize_wazuh_alert(raw)

    triage = apply_triage_guardrails(
        alert,
        _triage_result(
            alert.alert_id,
            suspicious=True,
            requires_enrichment=True,
            requires_investigation=True,
        ),
    )

    assert triage.category == "phishing"
    assert any(
        "Sender and Reply-To"
        in item
        for item in triage.evidence
    )

    enrichment = EnrichmentResult(
        alert_id=alert.alert_id,
        threat_intel=[
            ThreatIntelFinding(
                provider="VirusTotal",
                entity_type=EntityType.URL,
                value="https://login-example.invalid/verify",
                known=True,
                malicious=4,
                suspicious=1,
                harmless=0,
                undetected=60,
                categories=["phishing"],
            ),
            ThreatIntelFinding(
                provider="VirusTotal",
                entity_type=EntityType.HASH,
                value=attachment_hash,
                known=False,
            ),
        ],
    )

    assessment = _enrichment_assessment(
        alert.alert_id,
        requires_investigation=True,
    )
    assessment.inconsistencies = [
        "Model-generated contradiction that must not survive",
    ]

    guarded_assessment = apply_enrichment_guardrails(
        alert,
        enrichment,
        assessment,
    )

    assert guarded_assessment.inconsistencies == []
    assert any(
        "4 malicious"
        in item
        and "phishing"
        in item.lower()
        for item in guarded_assessment.relevant_findings
    )
    assert any(
        "unknown to VirusTotal"
        in item
        and "not evidence"
        in item
        for item in guarded_assessment.relevant_findings
    )

    investigation = apply_investigation_guardrails(
        alert,
        _investigation_result(
            alert.alert_id,
            verdict=InvestigationVerdict.MALICIOUS,
            requires_remediation=True,
            validated_mitre_techniques=[
                "T1566.002",
                "T1059.001",
            ],
            rejected_mitre_techniques=[
                "T1566.002",
                "T1027",
            ],
        ),
    )

    investigation = _apply_email_investigation_guardrail(
        alert,
        enrichment,
        guarded_assessment,
        investigation,
    )

    assert investigation.verdict == InvestigationVerdict.LIKELY_MALICIOUS
    assert investigation.requires_remediation is False
    assert investigation.validated_mitre_techniques == [
        "T1566.002"
    ]
    assert "T1059.001" not in investigation.validated_mitre_techniques
    assert "T1027" not in investigation.rejected_mitre_techniques
    assert any(
        item.startswith("VirusTotal")
        for item in investigation.key_evidence
    )
    assert "does not justify claiming host compromise" in investigation.summary
    assert "does not justify disruptive endpoint remediation" in investigation.summary
