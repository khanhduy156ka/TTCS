from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.services.normalizer import normalize_wazuh_alert


# Chi dung rule level lam fallback cho alert nghiem trong, khong dung level >= 7 vi SCA/CIS co the sinh nhieu compliance alert 7-9
MIN_HIGH_PRIORITY_LEVEL = 10


# Cac Wazuh rule group lien quan truc tiep toi incident analysis pipeline hien tai
SECURITY_RELEVANT_GROUPS = {
    "authentication_failed",
}


# Khong dua nhom configuration/compliance truc tiep vao multi-agent incident response pipeline
EXCLUDED_GROUPS = {
    "sca",
}


# Mot so alert nhieu/compliance co the khong mang group sca, nen kiem tra them description
EXCLUDED_DESCRIPTION_PATTERNS = (
    "cis microsoft windows",
    "sca summary:",
    "sessionenv was unavailable to handle",
)


AlertInput = NormalizedAlert | dict


def _to_normalized_alert(
    alert: AlertInput,
) -> NormalizedAlert:
    """
    Convert a raw Wazuh alert dictionary to NormalizedAlert.

    If the alert is already normalized, return it unchanged.
    """
    if isinstance(alert, NormalizedAlert):
        return alert

    if isinstance(alert, dict):
        return normalize_wazuh_alert(alert)

    raise TypeError(
        "alert must be a NormalizedAlert or raw Wazuh alert dict"
    )


def _normalize_groups(
    groups: list[str],
) -> set[str]:
    """
    Normalize Wazuh rule groups for reliable comparison.
    """
    return {
        group.strip().lower()
        for group in groups
        if group and group.strip()
    }


def _is_excluded_alert(
    alert: NormalizedAlert,
) -> bool:
    """
    Return True when the alert should not enter the current
    incident-analysis pipeline.
    """
    groups = _normalize_groups(alert.rule_groups)

    if groups & EXCLUDED_GROUPS:
        return True

    description = (
        alert.rule_description
        or ""
    ).strip().lower()

    return any(
        pattern in description
        for pattern in EXCLUDED_DESCRIPTION_PATTERNS
    )


def get_candidate_reasons(
    alert: AlertInput,
) -> list[str]:
    """
    Return the reasons why an alert should enter the
    multi-agent SOC analysis pipeline.

    Accepts either:
    - raw Wazuh alert dict
    - NormalizedAlert

    An empty list means the alert should be skipped.

    Selection order:
    1. Normalize the input.
    2. Exclude known SCA/compliance/noisy system alerts.
    3. Accept security-relevant Wazuh groups.
    4. Accept alerts with MITRE ATT&CK mapping.
    5. Accept very high-severity alerts as a fallback.
    """
    normalized_alert = _to_normalized_alert(alert)

    if _is_excluded_alert(normalized_alert):
        return []

    reasons: list[str] = []

    groups = _normalize_groups(
        normalized_alert.rule_groups
    )

    matched_security_groups = sorted(
        groups & SECURITY_RELEVANT_GROUPS
    )

    for group in matched_security_groups:
        reasons.append(
            f"Security-relevant Wazuh group: {group}"
        )

    if normalized_alert.mitre_ids:
        reasons.append(
            "Wazuh rule contains MITRE ATT&CK mapping"
        )

    if (
        normalized_alert.rule_level
        >= MIN_HIGH_PRIORITY_LEVEL
    ):
        reasons.append(
            "Wazuh rule level "
            f"{normalized_alert.rule_level} >= "
            f"{MIN_HIGH_PRIORITY_LEVEL}"
        )

    return reasons


def is_candidate_alert(
    alert: AlertInput,
) -> tuple[bool, list[str]]:
    """
    Return whether an alert is a candidate together with
    the reasons for the decision.

    Supports both raw Wazuh alert dictionaries and
    NormalizedAlert objects.
    """
    reasons = get_candidate_reasons(alert)

    return bool(reasons), reasons