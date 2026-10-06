"""Deterministic contracts with simulated transactions; no live DB/LLM/Wazuh."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import importlib
import json
from threading import Barrier, Event, RLock

from fastapi.testclient import TestClient
import httpx
import pytest

from soc_multi_agent import wazuh_ingestion as ingestion
from soc_multi_agent.schemas.remediation import RemediationPlan
from soc_multi_agent.schemas.state import CaseStatus, SOCSharedState
from soc_multi_agent.services import case_repository as repository
from soc_multi_agent.services import human_review
from soc_multi_agent.services.normalizer import normalize_wazuh_alert

api = importlib.import_module("soc_multi_agent.api.app")
HANDOFF = [
    "monitoring", "remediation_proposed", "pending_human_approval",
    "remediation_approved", "remediation_rejected",
]
INCOMPLETE = ["new", "triaged", "enriched", "investigated", "failed", "closed"]


def raw_alert(alert_id="hardening-1"):
    return {
        "id": alert_id,
        "timestamp": "2026-10-06T01:00:01Z",
        "agent": {"id": "001", "name": "test-host"},
        "rule": {"id": "100", "level": 10, "description": "Test alert"},
    }


def case(status="new"):
    alert = normalize_wazuh_alert(raw_alert())
    return SOCSharedState(
        case_id=ingestion.build_case_id(alert.alert_id),
        alert=alert,
        status=CaseStatus(status),
    )


class SimulatedDatabase:
    """Models serial transactions; SQL assertions guard the production contract.

    This is not a PostgreSQL concurrency test. Each connection owns its lock
    until commit/rollback, so tests also catch review writes on a new connection.
    """

    def __init__(self):
        self.rows = {}
        self.lock = RLock()
        self.statements = []
        self.rollbacks = 0
        self.fail_update = False

    def connect(self):
        database = self

        class Connection:
            def __enter__(self):
                database.lock.acquire()
                self.before = deepcopy(database.rows)
                self.selected_for_update = False
                return self

            def __exit__(self, kind, value, traceback):
                if kind:
                    database.rows = self.before
                    database.rollbacks += 1
                database.lock.release()

            def cursor(self):
                return self

            def execute(self, query, parameters):
                sql = " ".join(query.split())
                database.statements.append(sql)
                self.result = None
                self.rowcount = 0
                if sql.startswith("INSERT"):
                    key, status, alert_id, payload = parameters
                    assert payload.obj["status"] == status
                    assert payload.obj["alert"]["alert_id"] == alert_id
                    previous = database.rows.get(key)
                    if "DO NOTHING" in sql:
                        assert "ON CONFLICT (case_id) DO NOTHING RETURNING case_id" in sql
                        if previous is not None:
                            return
                        self.result = (key,)
                    else:
                        assert "COALESCE(soc_cases.state->'human_decision'" in sql
                        assert "COALESCE(EXCLUDED.state->'human_decision'" in sql
                        if previous and previous.get("human_decision") != payload.obj.get("human_decision"):
                            return
                    database.rows[key] = deepcopy(payload.obj)
                    self.rowcount = 1
                elif sql.startswith("SELECT state"):
                    self.selected_for_update = sql.endswith("FOR UPDATE")
                    row = database.rows.get(parameters[0])
                    self.result = (deepcopy(row),) if row is not None else None
                elif sql.startswith("UPDATE"):
                    assert self.selected_for_update, "Review write must use its locked connection"
                    if database.fail_update:
                        raise RuntimeError("simulated persistence failure")
                    status, payload, key = parameters
                    assert payload.obj["status"] == status
                    database.rows[key] = deepcopy(payload.obj)
                    self.rowcount = 1
                else:
                    raise AssertionError(sql)

            def fetchone(self):
                return self.result

        connection = Connection()

        # Cursor context must not commit/release the connection's transaction.
        class CursorContext:
            def __enter__(self):
                return connection

            def __exit__(self, *args):
                return False

        connection.cursor = CursorContext
        return connection


@pytest.fixture
def database(monkeypatch):
    db = SimulatedDatabase()
    monkeypatch.setattr(repository, "get_connection", db.connect)
    return db


@pytest.fixture
def fake_flow(monkeypatch):
    class FakeFlow:
        calls = 0
        status = CaseStatus.MONITORING
        fail = False

        def __init__(self):
            self.state = SOCSharedState()

        def kickoff(self):
            type(self).calls += 1
            repository.save_case(self.state)
            if self.fail:
                raise RuntimeError("stage failed after persistence")
            self.state.status = self.status
            repository.save_case(self.state)
            return {"route": "test"}

    monkeypatch.setattr(api, "SOCSupervisorFlow", FakeFlow)
    return FakeFlow


def payload():
    state = case()
    return {"case_id": state.case_id, "alert": state.alert.model_dump(mode="json")}


@pytest.mark.parametrize("status", HANDOFF + INCOMPLETE)
def test_existing_case_contract(database, fake_flow, status):
    state = case(status)
    repository.save_case(state)
    before = deepcopy(database.rows)
    with TestClient(api.app) as client:
        response = client.post("/alerts", json=payload())
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "duplicate_completed" if status in HANDOFF else "case_incomplete_or_failed",
        "case_id": state.case_id,
        "status": status,
    }
    assert fake_flow.calls == 0
    assert database.rows == before


@pytest.mark.parametrize("status", HANDOFF + INCOMPLETE)
def test_new_case_response_status(database, fake_flow, status):
    fake_flow.status = CaseStatus(status)
    with TestClient(api.app) as client:
        response = client.post("/alerts", json=payload())
    assert response.status_code == (200 if status in HANDOFF else 500)
    assert fake_flow.calls == 1
    if status == "pending_human_approval":
        assert repository.load_case(case().case_id).human_decision is None


def test_retry_after_persist_then_exception_is_not_acknowledged(database, fake_flow):
    fake_flow.fail = True
    with TestClient(api.app) as client:
        first = client.post("/alerts", json=payload())
        retry = client.post("/alerts", json=payload())
    assert first.status_code == 500
    assert retry.status_code == 409
    assert retry.json()["detail"]["code"] == "case_incomplete_or_failed"
    assert fake_flow.calls == 1
    assert repository.load_case(case().case_id).status == CaseStatus.NEW


def test_reserve_is_insert_only(database):
    state = case()
    assert repository.reserve_case(state)
    before = deepcopy(database.rows)
    state.status = CaseStatus.FAILED
    assert not repository.reserve_case(state)
    assert database.rows == before
    assert len(database.statements) == 2  # No load-then-insert race window.


def test_two_new_requests_only_one_kickoff(database, monkeypatch):
    started, release = Event(), Event()

    class BlockingFlow:
        calls = 0

        def __init__(self):
            self.state = SOCSharedState()

        def kickoff(self):
            type(self).calls += 1
            started.set()
            assert release.wait(5)
            self.state.status = CaseStatus.MONITORING
            repository.save_case(self.state)

    monkeypatch.setattr(api, "SOCSupervisorFlow", BlockingFlow)

    def post():
        with TestClient(api.app) as client:
            return client.post("/alerts", json=payload())

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(post)
        try:
            assert started.wait(5)
            second = executor.submit(post).result(timeout=5)
            assert second.status_code == 409
            assert second.json()["detail"]["code"] == "case_incomplete_or_failed"
        finally:
            release.set()
        assert first.result(timeout=5).status_code == 200
    assert BlockingFlow.calls == 1


@pytest.mark.parametrize("status", HANDOFF)
@pytest.mark.parametrize("http_status", [200, 409])
def test_ingestion_accepts_only_explicit_handoff(status, http_status):
    body = {"case_id": case().case_id, "status": status}
    if http_status == 409:
        body = {"detail": {**body, "code": "duplicate_completed"}}
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(http_status, json=body)
    )) as client:
        result = ingestion.submit_alert(client, "http://testserver", raw_alert())
    assert result == ("duplicate" if http_status == 409 else "processed")


BAD_RESPONSES = [
    (200, {"case_id": case().case_id, "status": status}) for status in INCOMPLETE
] + [
    (409, {"detail": {"code": "case_incomplete_or_failed", "case_id": case().case_id, "status": status}})
    for status in INCOMPLETE
] + [
    (409, {"detail": "Case already exists"}),
    (409, {"detail": {"code": "duplicate_completed"}}),
    (409, {"detail": {"code": "duplicate_completed", "case_id": case().case_id, "status": "failed"}}),
    (200, []), (200, None), (200, {}),
    (200, {"case_id": "wrong-case", "status": "monitoring"}),
    (200, {"case_id": case().case_id, "status": []}),
    (200, {"case_id": case().case_id, "status": "future-status"}),
    (503, {"detail": "unavailable"}),
]


@pytest.mark.parametrize("http_status,body", BAD_RESPONSES)
def test_failed_or_invalid_response_cannot_advance_checkpoint(monkeypatch, tmp_path, http_status, body):
    client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(http_status, json=body)
    ))
    monkeypatch.setattr(ingestion.httpx, "Client", lambda **kwargs: client)
    monkeypatch.setattr(ingestion, "get_candidate_reasons", lambda raw: ["test"])
    checkpoint = {"timestamp": "2026-10-06T01:00:00Z", "alert_ids_at_timestamp": []}
    before = deepcopy(checkpoint)
    path = tmp_path / "checkpoint.json"
    path.write_text(json.dumps(checkpoint))
    original = path.read_bytes()
    summary = ingestion.process_alerts(
        raw_alerts=[raw_alert(), raw_alert("later")], api_url="http://testserver",
        dry_run=False, checkpoint=checkpoint, state_file=path, persist_checkpoint=True,
    )
    assert summary["failed"] == 1
    assert summary["processed"] == summary["duplicates"] == 0
    assert checkpoint == before
    assert path.read_bytes() == original


def test_non_json_success_is_not_acknowledged():
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, text="not json")
    )) as client:
        with pytest.raises(ValueError):
            ingestion.submit_alert(client, "http://testserver", raw_alert())


def reviewable_case():
    state = case("pending_human_approval")
    state.human_approval_required = True
    state.remediation = RemediationPlan(
        alert_id=state.alert.alert_id, required=True, priority="medium",
        actions=[{"action": "Restore configuration", "rationale": "Observed change",
                  "impact": "Changes file", "approval_required": True, "verification": "Check hash"}],
        summary="Review restoration", recommended_next_step="Analyst review",
    )
    return state


@pytest.mark.parametrize("approved", [True, False])
def test_human_review_transaction_and_stale_flow_save(database, approved):
    state = reviewable_case()
    repository.save_case(state)
    reviewed = human_review.review_case(state.case_id, approved, " analyst ", " reason ")
    assert reviewed.human_decision.analyst == "analyst"
    assert reviewed.human_decision.reason == "reason"
    assert reviewed.human_approved is approved
    assert reviewed.status.value == ("remediation_approved" if approved else "remediation_rejected")
    with pytest.raises(ValueError, match="stale save"):
        repository.save_case(state)
    persisted = repository.load_case(state.case_id)
    assert persisted == reviewed
    assert len(persisted.audit_trail) == 1


def test_concurrent_approve_reject_preserves_first_decision(database):
    state = reviewable_case()
    repository.save_case(state)
    barrier = Barrier(2)

    def review(approved):
        barrier.wait(timeout=5)
        try:
            return human_review.review_case(state.case_id, approved, str(approved))
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(review, [True, False]))
    winners = [result for result in results if isinstance(result, SOCSharedState)]
    assert len(winners) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 1
    assert repository.load_case(state.case_id) == winners[0]
    assert len(winners[0].audit_trail) == 1


def test_review_persistence_failure_rolls_back(database):
    state = reviewable_case()
    repository.save_case(state)
    database.fail_update = True
    with pytest.raises(RuntimeError, match="persistence failure"):
        human_review.approve_case(state.case_id, "analyst")
    assert repository.load_case(state.case_id) == state
    assert database.rollbacks == 1


def test_invalid_review_does_not_write(database):
    state = case("monitoring")
    repository.save_case(state)
    with pytest.raises(ValueError, match="no remediation"):
        human_review.approve_case(state.case_id, "analyst")
    assert repository.load_case(state.case_id) == state
    assert not any(sql.startswith("UPDATE") for sql in database.statements)


@pytest.mark.parametrize("contents", ["{broken", "[]", '{"timestamp": "invalid"}'])
def test_corrupt_checkpoint_never_rebaselines(tmp_path, monkeypatch, contents):
    path = tmp_path / "checkpoint.json"
    path.write_text(contents)
    monkeypatch.setattr(ingestion, "initialize_checkpoint", lambda **kwargs: pytest.fail("Must not rebaseline"))
    with pytest.raises(ValueError, match="refusing to create"):
        ingestion.run_watch_loop(
            size=10, min_rule_level=5, agent_name=None, api_url="http://testserver",
            poll_interval=15, dry_run=False, state_file=path, reset_watermark=False,
        )
    assert path.read_text() == contents


def test_stream_mismatch_does_not_reset_checkpoint(tmp_path):
    path = tmp_path / "checkpoint.json"
    contents = json.dumps({"timestamp": "2026-10-06T01:00:00Z", "agent_name": "other", "min_rule_level": 5})
    path.write_text(contents)
    with pytest.raises(ValueError, match="stream settings differ"):
        ingestion.load_checkpoint(state_file=path, agent_name=None, min_rule_level=5)
    assert path.read_text() == contents


def test_dry_run_reset_rejected_before_any_checkpoint_io(tmp_path, monkeypatch):
    path = tmp_path / "checkpoint.json"
    path.write_text("preserve exactly")
    monkeypatch.setattr(ingestion, "load_checkpoint", lambda **kwargs: pytest.fail("Must not load"))
    with pytest.raises(ValueError, match="dry-run"):
        ingestion.run_watch_loop(
            size=10, min_rule_level=5, agent_name=None, api_url="http://testserver",
            poll_interval=15, dry_run=True, state_file=path, reset_watermark=True,
        )
    assert path.read_text() == "preserve exactly"
