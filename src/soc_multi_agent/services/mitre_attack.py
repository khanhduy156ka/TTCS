import json
from functools import lru_cache
from pathlib import Path

from soc_multi_agent.schemas.enrichment import (
    MitreTechniqueContext,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MITRE_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "mitre"
    / "enterprise-attack.json"
)


@lru_cache(maxsize=1)
def load_mitre_attack_data() -> dict:
    if not MITRE_DATA_PATH.exists():
        raise FileNotFoundError(
            f"MITRE ATT&CK dataset not found: "
            f"{MITRE_DATA_PATH}"
        )

    with MITRE_DATA_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def _get_mitre_reference(
    stix_object: dict,
) -> dict | None:
    for reference in stix_object.get(
        "external_references",
        [],
    ):
        if reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")

            if external_id and external_id.startswith("T"):
                return reference

    return None


@lru_cache(maxsize=1)
def build_mitre_technique_index(
) -> dict[str, MitreTechniqueContext]:
    data = load_mitre_attack_data()

    index: dict[str, MitreTechniqueContext] = {}

    for stix_object in data.get("objects", []):
        if stix_object.get("type") != "attack-pattern":
            continue

        reference = _get_mitre_reference(
            stix_object
        )

        if reference is None:
            continue

        technique_id = reference["external_id"]

        tactics = [
            phase["phase_name"]
            for phase in stix_object.get(
                "kill_chain_phases",
                [],
            )
            if "phase_name" in phase
        ]

        index[technique_id] = MitreTechniqueContext(
            technique_id=technique_id,
            name=stix_object.get(
                "name",
                "Unknown",
            ),
            tactics=tactics,
            platforms=stix_object.get(
                "x_mitre_platforms",
                [],
            ),
            revoked=stix_object.get(
                "revoked",
                False,
            ),
            deprecated=stix_object.get(
                "x_mitre_deprecated",
                False,
            ),
            source_url=reference.get("url"),
        )

    return index


def get_mitre_technique(
    technique_id: str,
) -> MitreTechniqueContext | None:
    index = build_mitre_technique_index()

    return index.get(technique_id)


def get_mitre_techniques(
    technique_ids: list[str],
) -> list[MitreTechniqueContext]:
    index = build_mitre_technique_index()

    results: list[MitreTechniqueContext] = []

    for technique_id in technique_ids:
        technique = index.get(technique_id)

        if technique is not None:
            results.append(technique)

    return results