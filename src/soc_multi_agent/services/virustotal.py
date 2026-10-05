import base64
import logging

import httpx

from soc_multi_agent.config import settings
from soc_multi_agent.schemas.enrichment import (
    EntityType,
    ThreatIntelFinding,
)
from soc_multi_agent.services.entity_validator import (
    is_http_url,
    is_public_ip,
    is_sha256,
    is_valid_domain,
)


logger = logging.getLogger(__name__)


def _api_key() -> str | None:
    value = settings.virustotal_api_key

    if value is None:
        return None

    value = value.strip()

    return value or None


def _get_attributes(
    path: str,
) -> tuple[bool, dict] | None:
    """
    Return:
      (True, attributes)  -> VirusTotal knows the object.
      (False, {})         -> VirusTotal returned 404 / object unknown.
      None                -> Lookup unavailable or failed.

    Lookup failures deliberately fail open so an external TI outage,
    missing API key, quota error, or timeout cannot break the SOC flow.
    """
    key = _api_key()

    if key is None:
        logger.warning(
            "VirusTotal lookup skipped because no API key is configured."
        )
        return None

    headers = {
        "x-apikey": key,
    }

    try:
        with httpx.Client(
            base_url=settings.virustotal_base_url,
            headers=headers,
            timeout=15.0,
        ) as client:
            response = client.get(path)

            if response.status_code == 404:
                return False, {}

            response.raise_for_status()

            payload = response.json()
            data = payload.get("data", {})

            if not isinstance(data, dict):
                return None

            attributes = data.get(
                "attributes",
                {},
            )

            if not isinstance(
                attributes,
                dict,
            ):
                attributes = {}

            return True, attributes

    except (
        httpx.HTTPError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        logger.warning(
            "VirusTotal lookup failed for %s: %s",
            path,
            exc,
        )
        return None


def _analysis_stats(
    attributes: dict,
) -> dict:
    stats = attributes.get(
        "last_analysis_stats",
        {},
    )

    return (
        stats
        if isinstance(stats, dict)
        else {}
    )


def _categories(
    attributes: dict,
) -> list[str]:
    raw = attributes.get(
        "categories",
        {},
    )

    if isinstance(raw, dict):
        values = raw.values()
    elif isinstance(raw, list):
        values = raw
    else:
        return []

    result: list[str] = []

    for value in values:
        text = str(value).strip()

        if (
            text
            and text not in result
        ):
            result.append(text)

    return result


def _build_finding(
    *,
    entity_type: EntityType,
    value: str,
    known: bool,
    attributes: dict | None = None,
) -> ThreatIntelFinding:
    attributes = attributes or {}
    stats = _analysis_stats(
        attributes
    )

    return ThreatIntelFinding(
        provider="VirusTotal",
        entity_type=entity_type,
        value=value,
        known=known,
        malicious=stats.get(
            "malicious",
            0,
        ),
        suspicious=stats.get(
            "suspicious",
            0,
        ),
        harmless=stats.get(
            "harmless",
            0,
        ),
        undetected=stats.get(
            "undetected",
            0,
        ),
        reputation=attributes.get(
            "reputation"
        ),
        categories=_categories(
            attributes
        ),
        file_type=attributes.get(
            "type_description"
        ),
        country=attributes.get(
            "country"
        ),
        as_owner=attributes.get(
            "as_owner"
        ),
    )


def lookup_ip(
    ip: str,
) -> ThreatIntelFinding | None:
    if not is_public_ip(ip):
        return None

    result = _get_attributes(
        f"/ip_addresses/{ip}"
    )

    if result is None:
        return None

    known, attributes = result

    return _build_finding(
        entity_type=EntityType.IP,
        value=ip,
        known=known,
        attributes=attributes,
    )


def lookup_domain(
    domain: str,
) -> ThreatIntelFinding | None:
    normalized = (
        domain.strip()
        .lower()
        .rstrip(".")
    )

    if not is_valid_domain(
        normalized
    ):
        return None

    result = _get_attributes(
        f"/domains/{normalized}"
    )

    if result is None:
        return None

    known, attributes = result

    return _build_finding(
        entity_type=EntityType.DOMAIN,
        value=normalized,
        known=known,
        attributes=attributes,
    )


def lookup_url(
    url: str,
) -> ThreatIntelFinding | None:
    normalized = url.strip()

    if not is_http_url(
        normalized
    ):
        return None

    url_id = (
        base64.urlsafe_b64encode(
            normalized.encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )

    result = _get_attributes(
        f"/urls/{url_id}"
    )

    if result is None:
        return None

    known, attributes = result

    return _build_finding(
        entity_type=EntityType.URL,
        value=normalized,
        known=known,
        attributes=attributes,
    )


def lookup_hash(
    value: str,
) -> ThreatIntelFinding | None:
    normalized = (
        value.strip()
        .lower()
    )

    if not is_sha256(
        normalized
    ):
        return None

    result = _get_attributes(
        f"/files/{normalized}"
    )

    if result is None:
        return None

    known, attributes = result

    return _build_finding(
        entity_type=EntityType.HASH,
        value=normalized,
        known=known,
        attributes=attributes,
    )
