"""Download public MITRE ATT&CK STIX Enterprise dataset for local enrichment.

Supply a pinned raw GitHub URL in MITRE_ATTACK_URL for reproducible versions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "mitre" / "enterprise-attack.json"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def main() -> None:
    url = os.environ.get("MITRE_ATTACK_URL", DEFAULT_URL)
    if not url.startswith("https://"):
        raise ValueError("MITRE_ATTACK_URL must be an HTTPS URL")
    print(f"Downloading MITRE Enterprise ATT&CK STIX from {url}")
    with urlopen(url, timeout=120) as response:
        raw = response.read()
    dataset = json.loads(raw)
    if not isinstance(dataset, dict) or not isinstance(dataset.get("objects"), list):
        raise ValueError("Downloaded content is not an ATT&CK STIX bundle")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(raw)
    print(f"Saved: {OUT}")
    print(f"Objects: {len(dataset['objects'])}")
    print(f"SHA-256: {hashlib.sha256(raw).hexdigest()}")


if __name__ == "__main__":
    main()
