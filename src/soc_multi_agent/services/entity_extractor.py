from urllib.parse import urlparse

from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EntityType,
    SecurityEntity,
)
from soc_multi_agent.services.entity_validator import (
    is_http_url,
    is_sha256,
    is_valid_domain,
)


def _append_unique(
    entities: list[SecurityEntity],
    *,
    entity_type: EntityType,
    value: str,
    source_field: str,
) -> None:
    normalized_value = value.strip()

    if not normalized_value:
        return

    for entity in entities:
        if (
            entity.entity_type == entity_type
            and entity.value == normalized_value
        ):
            return

    entities.append(
        SecurityEntity(
            entity_type=entity_type,
            value=normalized_value,
            source_field=source_field,
        )
    )


def extract_entities(
    alert: NormalizedAlert,
) -> list[SecurityEntity]:
    entities: list[SecurityEntity] = []

    # Lay cac entity co ban tu alert Windows/generic
    if alert.source_ip:
        _append_unique(
            entities,
            entity_type=EntityType.IP,
            value=alert.source_ip,
            source_field="source_ip",
        )

    if alert.target_user:
        _append_unique(
            entities,
            entity_type=EntityType.USER,
            value=alert.target_user,
            source_field="target_user",
        )

    if alert.computer:
        _append_unique(
            entities,
            entity_type=EntityType.HOST,
            value=alert.computer,
            source_field="computer",
        )

    # Lay URL IOC tu email
    for url in alert.email_urls:
        if not is_http_url(url):
            continue

        _append_unique(
            entities,
            entity_type=EntityType.URL,
            value=url,
            source_field="email_urls",
        )

    # Uu tien domain co san trong structured telemetry thay vi de LLM tu suy dien
    for domain in alert.email_domains:
        normalized_domain = (
            domain.strip()
            .lower()
            .rstrip(".")
        )

        if not is_valid_domain(
            normalized_domain
        ):
            continue

        _append_unique(
            entities,
            entity_type=EntityType.DOMAIN,
            value=normalized_domain,
            source_field="email_domains",
        )

    # Neu email chi co URL, lay hostname tu URL theo cach deterministic
    for url in alert.email_urls:
        if not is_http_url(url):
            continue

        hostname = urlparse(url).hostname

        if (
            hostname
            and is_valid_domain(hostname)
        ):
            _append_unique(
                entities,
                entity_type=EntityType.DOMAIN,
                value=hostname.lower(),
                source_field="email_urls.hostname",
            )

    # Attachment hash van la IOC ngay ca khi VirusTotal chua tung thay
    if (
        alert.email_attachment_sha256
        and is_sha256(
            alert.email_attachment_sha256
        )
    ):
        _append_unique(
            entities,
            entity_type=EntityType.HASH,
            value=alert.email_attachment_sha256.lower(),
            source_field="email_attachment_sha256",
        )

    return entities
