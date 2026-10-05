from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.enrichment import (
    EnrichmentResult,
    EntityType,
)
from soc_multi_agent.services.entity_extractor import (
    extract_entities,
)
from soc_multi_agent.services.mitre_attack import (
    get_mitre_techniques,
)
from soc_multi_agent.services.virustotal import (
    lookup_domain,
    lookup_hash,
    lookup_ip,
    lookup_url,
)


def enrich_alert(
    alert: NormalizedAlert,
) -> EnrichmentResult:
    entities = extract_entities(alert)

    mitre_techniques = get_mitre_techniques(
        alert.mitre_ids
    )

    threat_intel = []

    for entity in entities:
        finding = None

        if entity.entity_type == EntityType.IP:
            finding = lookup_ip(
                entity.value
            )

        elif entity.entity_type == EntityType.DOMAIN:
            finding = lookup_domain(
                entity.value
            )

        elif entity.entity_type == EntityType.URL:
            finding = lookup_url(
                entity.value
            )

        elif entity.entity_type == EntityType.HASH:
            finding = lookup_hash(
                entity.value
            )

        if finding is not None:
            threat_intel.append(
                finding
            )

    return EnrichmentResult(
        alert_id=alert.alert_id,
        entities=entities,
        mitre_techniques=mitre_techniques,
        threat_intel=threat_intel,
    )
