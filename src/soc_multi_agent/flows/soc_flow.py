from typing import ClassVar

from time import perf_counter

from crewai.flow.flow import (
    Flow,
    listen,
    router,
    start,
)

from soc_multi_agent.agents.enrichment import (
    run_enrichment_analysis,
)
from soc_multi_agent.agents.investigation import (
    run_investigation,
)
from soc_multi_agent.agents.remediation import (
    run_remediation,
)
from soc_multi_agent.agents.triage import (
    run_triage,
)
from soc_multi_agent.rag.context import (
    build_investigation_query,
    retrieve_investigation_knowledge,
)
from soc_multi_agent.schemas.state import (
    AuditEvent,
    CaseStatus,
    SOCSharedState,
)
from soc_multi_agent.services.case_repository import (
    save_case,
)
from soc_multi_agent.services.enrichment import (
    enrich_alert,
)


class SOCSupervisorFlow(Flow[SOCSharedState]):
    _skip_auto_memory: ClassVar[bool] = True

    def _persist_state(self) -> None:
        """
        Persist the latest validated shared state.

        PostgreSQL is the durable case store for the SOC
        workflow. Persistence is performed after meaningful
        state or routing changes.
        """

        save_case(self.state)

    def _performance_summary(self) -> dict:
        durations = self.state.stage_durations

        total = round(
            sum(durations.values()),
            6,
        )

        return {
            "stages": durations,
            "total_measured_seconds": total,
        }

    @start()
    def run_triage_stage(self):
        if not self.state.case_id:
            raise ValueError(
                "case_id is required to start the SOC flow"
            )

        if self.state.alert is None:
            raise ValueError(
                "alert is required to start the SOC flow"
            )

        alert = self.state.alert

        self.state.audit_trail.append(
            AuditEvent(
                stage="supervisor",
                action="case_started",
                detail=(
                    f"Started processing alert "
                    f"{alert.alert_id}"
                ),
            )
        )

        # Luu case truoc stage LLM dau tien de alert khong bi mat neu xu ly sau do loi
        self._persist_state()

        started = perf_counter()

        triage = run_triage(alert)

        duration = perf_counter() - started

        self.state.stage_durations["triage"] = round(
            duration,
            6,
        )

        self.state.triage = triage
        self.state.status = CaseStatus.TRIAGED

        self.state.audit_trail.append(
            AuditEvent(
                stage="triage",
                action="triage_completed",
                detail=(
                    f"priority={triage.priority.value}, "
                    f"suspicious={triage.suspicious}, "
                    f"requires_enrichment="
                    f"{triage.requires_enrichment}, "
                    f"requires_investigation="
                    f"{triage.requires_investigation}, "
                    f"duration_seconds="
                    f"{duration:.6f}"
                ),
            )
        )

        self._persist_state()

        return triage

    @router(run_triage_stage)
    def route_after_triage(self):
        triage = self.state.triage

        if triage is None:
            self.state.status = CaseStatus.FAILED

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="routing_failed",
                    detail="Triage result is missing",
                )
            )

            self._persist_state()

            return "failed"

        if (
            not triage.requires_enrichment
            and not triage.requires_investigation
        ):
            self.state.status = CaseStatus.MONITORING

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="route_to_monitoring",
                    detail=(
                        "Triage found no need for enrichment "
                        "or investigation"
                    ),
                )
            )

            self._persist_state()

            return "monitor"

        self.state.audit_trail.append(
            AuditEvent(
                stage="supervisor",
                action="route_to_enrichment",
                detail=(
                    "Triage requires deeper security analysis"
                ),
            )
        )

        self._persist_state()

        return "deeper_analysis"

    @listen("deeper_analysis")
    def run_enrichment_stage(self):
        if self.state.alert is None:
            raise ValueError(
                "Alert is missing before enrichment"
            )

        alert = self.state.alert

        started = perf_counter()

        enrichment = enrich_alert(alert)

        self.state.enrichment = enrichment

        assessment = run_enrichment_analysis(
            alert,
            enrichment,
        )

        duration = perf_counter() - started

        self.state.stage_durations["enrichment"] = round(
            duration,
            6,
        )

        self.state.enrichment_assessment = assessment
        self.state.status = CaseStatus.ENRICHED

        self.state.audit_trail.append(
            AuditEvent(
                stage="enrichment",
                action="enrichment_completed",
                detail=(
                    f"entities="
                    f"{len(enrichment.entities)}, "
                    f"mitre_techniques="
                    f"{len(enrichment.mitre_techniques)}, "
                    f"threat_intel="
                    f"{len(enrichment.threat_intel)}, "
                    f"requires_investigation="
                    f"{assessment.requires_investigation}, "
                    f"duration_seconds="
                    f"{duration:.6f}"
                ),
            )
        )

        self._persist_state()

        return assessment

    @router(run_enrichment_stage)
    def route_after_enrichment(self):
        triage = self.state.triage
        assessment = (
            self.state.enrichment_assessment
        )

        if triage is None or assessment is None:
            self.state.status = CaseStatus.FAILED

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="routing_failed",
                    detail=(
                        "Triage or enrichment assessment "
                        "is missing"
                    ),
                )
            )

            self._persist_state()

            return "failed"

        requires_investigation = (
            triage.requires_investigation
            or assessment.requires_investigation
        )

        if not requires_investigation:
            self.state.status = CaseStatus.MONITORING

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="route_to_monitoring",
                    detail=(
                        "No deeper investigation is required "
                        "after enrichment"
                    ),
                )
            )

            self._persist_state()

            return "monitor"

        self.state.audit_trail.append(
            AuditEvent(
                stage="supervisor",
                action="route_to_investigation",
                detail=(
                    "Investigation is required after "
                    "triage/enrichment correlation"
                ),
            )
        )

        self._persist_state()

        return "investigate"

    @listen("investigate")
    def run_investigation_stage(self):
        if self.state.alert is None:
            raise ValueError(
                "Alert is missing before investigation"
            )

        if self.state.triage is None:
            raise ValueError(
                "Triage result is missing before investigation"
            )

        if self.state.enrichment is None:
            raise ValueError(
                "Enrichment result is missing "
                "before investigation"
            )

        if self.state.enrichment_assessment is None:
            raise ValueError(
                "Enrichment assessment is missing "
                "before investigation"
            )

        rag_started = perf_counter()

        try:
            rag_query = build_investigation_query(
                self.state.alert,
                self.state.triage,
                self.state.enrichment,
                self.state.enrichment_assessment,
            )

            self.state.rag_query = rag_query

            retrieved_knowledge = (
                retrieve_investigation_knowledge(
                    rag_query
                )
            )

            self.state.retrieved_knowledge = (
                retrieved_knowledge
            )

            rag_duration = (
                perf_counter() - rag_started
            )

            self.state.stage_durations["rag"] = round(
                rag_duration,
                6,
            )

            sources = sorted(
                {
                    item.source
                    for item in retrieved_knowledge
                }
            )

            source_detail = (
                ",".join(sources)
                if sources
                else "none"
            )

            self.state.audit_trail.append(
                AuditEvent(
                    stage="rag",
                    action="knowledge_retrieved",
                    detail=(
                        f"chunks="
                        f"{len(retrieved_knowledge)}, "
                        f"sources={source_detail}, "
                        f"duration_seconds="
                        f"{rag_duration:.6f}"
                    ),
                )
            )

        except Exception as exc:
            rag_duration = (
                perf_counter() - rag_started
            )

            self.state.stage_durations["rag"] = round(
                rag_duration,
                6,
            )

            self.state.retrieved_knowledge = []

            error_text = (
                str(exc)
                .replace("\r", " ")
                .replace("\n", " ")
            )[:180]

            self.state.audit_trail.append(
                AuditEvent(
                    stage="rag",
                    action="knowledge_retrieval_failed",
                    detail=(
                        f"error="
                        f"{type(exc).__name__}, "
                        f"message={error_text!r}, "
                        f"duration_seconds="
                        f"{rag_duration:.6f}; "
                        "investigation continues "
                        "without RAG context"
                    ),
                )
            )

        # Luu ket qua RAG hoac loi truoc Investigation de dam bao audit va fail-open
        self._persist_state()

        started = perf_counter()

        investigation = run_investigation(
            self.state.alert,
            self.state.triage,
            self.state.enrichment,
            self.state.enrichment_assessment,
            self.state.retrieved_knowledge,
        )

        duration = perf_counter() - started

        self.state.stage_durations[
            "investigation"
        ] = round(
            duration,
            6,
        )

        self.state.investigation = investigation
        self.state.status = CaseStatus.INVESTIGATED

        self.state.audit_trail.append(
            AuditEvent(
                stage="investigation",
                action="investigation_completed",
                detail=(
                    f"verdict="
                    f"{investigation.verdict.value}, "
                    f"confidence="
                    f"{investigation.confidence}, "
                    f"requires_remediation="
                    f"{investigation.requires_remediation}, "
                    f"rag_chunks="
                    f"{len(self.state.retrieved_knowledge)}, "
                    f"duration_seconds="
                    f"{duration:.6f}"
                ),
            )
        )

        self._persist_state()

        return investigation

    @router(run_investigation_stage)
    def route_after_investigation(self):
        investigation = self.state.investigation

        if investigation is None:
            self.state.status = CaseStatus.FAILED

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="routing_failed",
                    detail=(
                        "Investigation result is missing"
                    ),
                )
            )

            self._persist_state()

            return "failed"

        if not investigation.requires_remediation:
            self.state.status = CaseStatus.MONITORING

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="route_to_monitoring",
                    detail=(
                        "Investigation found no active "
                        "remediation requirement"
                    ),
                )
            )

            self._persist_state()

            return "monitor"

        self.state.audit_trail.append(
            AuditEvent(
                stage="supervisor",
                action="route_to_remediation",
                detail=(
                    "Investigation requires "
                    "remediation planning"
                ),
            )
        )

        self._persist_state()

        return "remediate"

    @listen("remediate")
    def run_remediation_stage(self):
        if self.state.alert is None:
            raise ValueError(
                "Alert is missing before remediation"
            )

        if self.state.investigation is None:
            raise ValueError(
                "Investigation result is missing "
                "before remediation"
            )

        started = perf_counter()

        remediation = run_remediation(
            self.state.alert,
            self.state.investigation,
        )

        duration = perf_counter() - started

        self.state.stage_durations[
            "remediation"
        ] = round(
            duration,
            6,
        )

        self.state.remediation = remediation

        self.state.status = (
            CaseStatus.REMEDIATION_PROPOSED
        )

        self.state.human_approval_required = any(
            action.approval_required
            for action in remediation.actions
        )

        self.state.human_approved = None

        if self.state.human_approval_required:
            self.state.status = (
                CaseStatus.PENDING_HUMAN_APPROVAL
            )

        self.state.audit_trail.append(
            AuditEvent(
                stage="remediation",
                action="remediation_plan_created",
                detail=(
                    f"required={remediation.required}, "
                    f"priority="
                    f"{remediation.priority.value}, "
                    f"actions="
                    f"{len(remediation.actions)}, "
                    f"human_approval_required="
                    f"{self.state.human_approval_required}, "
                    f"duration_seconds="
                    f"{duration:.6f}"
                ),
            )
        )

        self._persist_state()

        return remediation

    @router(run_remediation_stage)
    def route_after_remediation(self):
        if self.state.remediation is None:
            self.state.status = CaseStatus.FAILED

            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="routing_failed",
                    detail=(
                        "Remediation plan is missing"
                    ),
                )
            )

            self._persist_state()

            return "failed"

        if self.state.human_approval_required:
            self.state.audit_trail.append(
                AuditEvent(
                    stage="supervisor",
                    action="route_to_human_approval",
                    detail=(
                        "Remediation actions require "
                        "SOC analyst approval"
                    ),
                )
            )

            self._persist_state()

            return "pending_approval"

        self._persist_state()

        return "remediation_proposed"

    @listen("monitor")
    def finish_monitoring_path(self):
        return {
            "case_id": self.state.case_id,
            "status": self.state.status.value,
            "route": "monitor",
            "performance": (
                self._performance_summary()
            ),
        }

    @listen("pending_approval")
    def finish_pending_approval_path(self):
        return {
            "case_id": self.state.case_id,
            "status": self.state.status.value,
            "route": "human_approval",
            "approval_required": True,
            "performance": (
                self._performance_summary()
            ),
        }

    @listen("remediation_proposed")
    def finish_remediation_path(self):
        return {
            "case_id": self.state.case_id,
            "status": self.state.status.value,
            "route": "remediation_proposed",
            "approval_required": False,
            "performance": (
                self._performance_summary()
            ),
        }

    @listen("failed")
    def finish_failed_path(self):
        return {
            "case_id": self.state.case_id,
            "status": self.state.status.value,
            "route": "failed",
            "performance": (
                self._performance_summary()
            ),
        }
