import sys
from pathlib import Path

from soc_multi_agent.flows.soc_flow import (
    SOCSupervisorFlow,
)
from soc_multi_agent.schemas.alert import (
    NormalizedAlert,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


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

    alert_path = fixture_dir / "alert.json"

    if not alert_path.exists():
        raise FileNotFoundError(
            f"Fixture alert not found: {alert_path}"
        )

    alert = NormalizedAlert.model_validate_json(
        alert_path.read_text(
            encoding="utf-8"
        )
    )

    print("===== FLOW INPUT =====")
    print(f"Fixture: {fixture_name}")
    print(f"Alert: {alert.alert_id}")

    flow = SOCSupervisorFlow()

    result = flow.kickoff(
        inputs={
            "case_id": f"case-{fixture_name}",
            "alert": alert.model_dump(
                mode="json"
            ),
        }
    )

    print("\n===== FLOW RESULT =====")
    print(result)

    print("\n===== FINAL STATE =====")
    print(
        flow.state.model_dump_json(
            indent=2
        )
    )


if __name__ == "__main__":
    main()
