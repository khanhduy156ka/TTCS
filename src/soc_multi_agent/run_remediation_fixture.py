import sys
from pathlib import Path

from soc_multi_agent.agents.remediation import run_remediation
from soc_multi_agent.schemas.alert import NormalizedAlert
from soc_multi_agent.schemas.investigation import (
    InvestigationResult,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_fixture(path: Path, model_class):
    return model_class.model_validate_json(
        path.read_text(encoding="utf-8")
    )


def main() -> None:
    fixture_name = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "suspicious_powershell"
    )

    fixture_dir = (
        PROJECT_ROOT
        / "tests"
        / "fixtures"
        / fixture_name
    )

    alert = load_fixture(
        fixture_dir / "alert.json",
        NormalizedAlert,
    )

    investigation = load_fixture(
        fixture_dir / "investigation.json",
        InvestigationResult,
    )

    print("===== FIXTURES LOADED =====")
    print(f"Fixture: {fixture_name}")
    print(f"Alert: {alert.alert_id}")
    print(
        "Investigation verdict:",
        investigation.verdict,
    )
    print(
        "Requires remediation:",
        investigation.requires_remediation,
    )

    print("\n===== REMEDIATION =====")

    remediation = run_remediation(
        alert,
        investigation,
    )

    print(
        remediation.model_dump_json(
            indent=2
        )
    )


if __name__ == "__main__":
    main()
