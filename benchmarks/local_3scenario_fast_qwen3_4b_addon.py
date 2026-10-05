from __future__ import annotations

import csv
import json
import os
import re
import statistics
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from soc_multi_agent.schemas.enrichment import EnrichmentAssessment
from soc_multi_agent.schemas.investigation import InvestigationResult
from soc_multi_agent.schemas.triage import TriageResult

OLLAMA = "http://127.0.0.1:11434"
OUT_DIR = Path.home() / "Downloads"
JSON_OUT = OUT_DIR / "local_3scenario_fast_qwen3_4b_addon.json"
CSV_OUT = OUT_DIR / "local_3scenario_fast_qwen3_4b_addon.csv"
TXT_OUT = OUT_DIR / "local_3scenario_fast_qwen3_4b_addon.txt"

NUM_CTX = 8192
NUM_PREDICT = 1536
TIMEOUT_SECONDS = 240
REPEATS = 3
KEEP_ALIVE = "30m"

FAST_CANDIDATES = [
    {"candidate": "qwen3_4b_instruct_no_think", "model": "qwen3:4b-instruct", "think": False},
]

REASONING_CANDIDATES = []

SCENARIOS: dict[str, dict[str, Any]] = {
    "powershell": {
        "alert": {
            "alert_id": "bench-ps-001",
            "source": "wazuh",
            "agent": {"id": "001", "name": "WIN-11", "ip": "10.10.10.20"},
            "rule_id": "100110",
            "rule_level": 10,
            "rule_description": "PowerShell script block with encoded content",
            "event_id": "4104",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider_name": "Microsoft-Windows-PowerShell",
            "mitre_ids": ["T1059.001", "T1027"],
            "script_block_text": '[Convert]::FromBase64String("U09DLUxBQi1QUy1FMkUtUkFHLTE=")',
            "base64_decodings": {
                "U09DLUxBQi1QUy1FMkUtUkFHLTE=": "SOC-LAB-PS-E2E-RAG-1"
            },
            "correlated_events": [],
            "observed_limitations": [
                "No supplied evidence establishes malware execution.",
                "No supplied evidence establishes persistence.",
                "No supplied evidence establishes credential theft.",
            ],
        },
        "enrichment": {
            "mitre": [
                {"technique_id": "T1059.001", "name": "PowerShell", "behaviorally_supported": True},
                {"technique_id": "T1027", "name": "Obfuscated Files or Information", "behaviorally_supported": True},
            ],
            "threat_intel": [],
            "deterministic_findings": [
                "The supplied Base64 value deterministically decodes to SOC-LAB-PS-E2E-RAG-1.",
                "Encoded PowerShell behavior supports investigation but does not by itself prove compromise.",
            ],
        },
        "triage_reference": {
            "alert_id": "bench-ps-001",
            "category": "PowerShell Obfuscation",
            "priority": "high",
            "confidence": 0.95,
            "suspicious": True,
            "requires_enrichment": True,
            "requires_investigation": True,
            "summary": "Encoded PowerShell requires investigation; supplied evidence does not prove compromise.",
            "evidence": ["Event 4104", "T1059.001", "T1027", "Deterministic Base64 decoding is available."],
            "recommended_next_step": "Correlate process, network, and endpoint telemetry.",
        },
        "enrichment_assessment_reference": {
            "alert_id": "bench-ps-001",
            "risk_level": "high",
            "confidence": 0.95,
            "relevant_findings": [
                "T1059.001 is supported by PowerShell execution.",
                "T1027 is supported by deterministic Base64 decoding.",
                "Decoded value: SOC-LAB-PS-E2E-RAG-1.",
            ],
            "inconsistencies": [],
            "requires_investigation": True,
            "summary": "Observed behavior justifies investigation without establishing compromise.",
            "recommended_next_step": "Correlate endpoint and network evidence.",
        },
        "knowledge": [
            {
                "title": "Suspicious PowerShell",
                "source": "knowledge/playbooks/suspicious_powershell.md",
                "content": (
                    "Encoded or obfuscated PowerShell is suspicious context, not standalone proof of compromise. "
                    "Use deterministic decoded values and correlate process, network, and endpoint evidence."
                ),
            }
        ],
    },
    "fim": {
        "alert": {
            "alert_id": "bench-fim-001",
            "source": "wazuh",
            "agent": {"id": "001", "name": "WIN-11", "ip": "10.10.10.20"},
            "rule_id": "550",
            "rule_level": 7,
            "rule_description": "Integrity checksum changed",
            "mitre_ids": ["T1565.001"],
            "fim_event": "modified",
            "fim_path": r"C:\SOC-Lab\Protected\config.txt",
            "fim_diff": "< mode=secure\n> mode=disabled",
            "fim_sha256_before": "956FEEB2D83C599D3EDBAC02A3B80D61C8209B5F5EB6B2C9049C40D404009299",
            "fim_sha256_after": "4DA9620F7AB16F7AD1A8F61B403D335C2143C2B6919CE50BF26CC647D0DE3FBE",
            "authorization_evidence": None,
            "actor_identity": None,
            "process_identity": None,
            "correlated_events": [],
        },
        "enrichment": {
            "mitre": [
                {"technique_id": "T1565.001", "name": "Stored Data Manipulation", "behaviorally_supported": True}
            ],
            "threat_intel": [],
            "deterministic_findings": [
                "Wazuh FIM records mode=secure changing to mode=disabled.",
                "Before and after SHA-256 hashes differ.",
                "No supplied evidence identifies the actor or process.",
            ],
        },
        "triage_reference": {
            "alert_id": "bench-fim-001",
            "category": "File Integrity Monitoring",
            "priority": "high",
            "confidence": 0.95,
            "suspicious": True,
            "requires_enrichment": True,
            "requires_investigation": True,
            "summary": "Protected configuration changed from secure to disabled without supplied authorization evidence.",
            "evidence": [r"C:\SOC-Lab\Protected\config.txt", "mode=secure -> mode=disabled", "SHA-256 changed"],
            "recommended_next_step": "Investigate authorization and actor/process telemetry.",
        },
        "enrichment_assessment_reference": {
            "alert_id": "bench-fim-001",
            "risk_level": "high",
            "confidence": 0.95,
            "relevant_findings": ["mode=secure changed to mode=disabled", "T1565.001 is behaviorally supported"],
            "inconsistencies": [],
            "requires_investigation": True,
            "summary": "The protected file changed to a weaker security state; actor identity and intent remain unknown.",
            "recommended_next_step": "Verify authorization and correlate access/process telemetry.",
        },
        "knowledge": [
            {
                "title": "File Integrity Change",
                "source": "knowledge/playbooks/file_integrity_change.md",
                "content": (
                    "Use FIM diff and before/after hashes as authoritative change evidence. "
                    "A security-weakening change requires investigation. Do not infer actor or malicious intent."
                ),
            },
            {
                "title": "Remediation Approval",
                "source": "knowledge/procedures/remediation_approval.md",
                "content": "System-changing restoration remains subject to human approval.",
            },
        ],
    },
    "phishing": {
        "alert": {
            "alert_id": "bench-phish-001",
            "source": "wazuh",
            "rule_id": "100120",
            "rule_level": 10,
            "rule_description": "Structured email-security observation",
            "rule_groups": ["phishing"],
            "email_event_type": "email_security_observation",
            "email_sender": "billing@microsoft-support.example",
            "email_reply_to": "account-review@billing-verification.example",
            "email_recipient": "employee@company.test",
            "email_subject": "Action Required: Invoice Payment Verification",
            "email_urls": ["https://onmicrosoftonline-mmscrmcustomers.mm.am/login?method=signin&mode=secure"],
            "email_domains": ["onmicrosoftonline-mmscrmcustomers.mm.am"],
            "email_attachment_name": "Invoice_2026.pdf",
            "email_attachment_content_type": "application/pdf",
            "email_attachment_size": 910,
            "email_attachment_sha256": "e9a6d4e48e39d61be53adffc66131882f84d44d512925e595da5c48609cfe53e",
            "email_user_clicked": None,
            "email_attachment_executed": None,
            "correlated_events": [],
        },
        "enrichment": {
            "threat_intel": [
                {
                    "entity_type": "url",
                    "value": "https://onmicrosoftonline-mmscrmcustomers.mm.am/login?method=signin&mode=secure",
                    "known": True,
                    "malicious": 9,
                    "suspicious": 2,
                    "harmless": 49,
                    "undetected": 32,
                    "categories": ["phishing", "fraud"],
                },
                {
                    "entity_type": "domain",
                    "value": "onmicrosoftonline-mmscrmcustomers.mm.am",
                    "known": True,
                    "malicious": 10,
                    "suspicious": 0,
                    "harmless": 49,
                    "undetected": 32,
                    "categories": ["phishing", "fraud"],
                },
                {
                    "entity_type": "hash",
                    "value": "e9a6d4e48e39d61be53adffc66131882f84d44d512925e595da5c48609cfe53e",
                    "known": False,
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                    "categories": [],
                },
            ],
            "deterministic_findings": [
                "Exact URL and domain have multiple malicious VirusTotal detections.",
                "Attachment hash is unknown to VirusTotal; unknown does not mean benign.",
                "User click and attachment execution are unknown.",
            ],
        },
        "triage_reference": {
            "alert_id": "bench-phish-001",
            "category": "phishing",
            "priority": "medium",
            "confidence": 0.95,
            "suspicious": True,
            "requires_enrichment": True,
            "requires_investigation": True,
            "summary": "Suspicious structured email observation; click, execution, credential theft, and compromise are not established.",
            "evidence": ["Sender and Reply-To differ", "URL IOC present", "Attachment hash present", "Click/execution unknown"],
            "recommended_next_step": "Enrich exact IOCs and correlate email/browser/proxy/DNS/endpoint/authentication telemetry.",
        },
        "enrichment_assessment_reference": {
            "alert_id": "bench-phish-001",
            "risk_level": "high",
            "confidence": 0.95,
            "relevant_findings": [
                "Exact URL: 9 malicious, 2 suspicious.",
                "Exact domain: 10 malicious.",
                "Attachment hash unknown to VirusTotal; unknown is not benign.",
                "Click and execution remain unknown.",
            ],
            "inconsistencies": [],
            "requires_investigation": True,
            "summary": "TI strongly supports phishing while endpoint execution, credential theft, and compromise remain unestablished.",
            "recommended_next_step": "Correlate user interaction and endpoint evidence; do not infer host compromise from IOC reputation.",
        },
        "knowledge": [
            {
                "title": "Phishing Email",
                "source": "knowledge/playbooks/phishing_email.md",
                "content": (
                    "Separate message/IOC assessment from user impact. Unknown provider status is not benign. "
                    "Malicious URL/domain reputation does not prove click, credential submission, execution, or compromise."
                ),
            }
        ],
    },
}

TRIAGE_SYSTEM = (
    "You are a SOC triage analyst. Evaluate security alerts conservatively, use only supplied evidence, "
    "distinguish facts from assumptions, and avoid escalating events without sufficient evidence."
)
ENRICHMENT_SYSTEM = (
    "You are a SOC enrichment analyst. Analyze structured evidence from trusted tools. Do not invent missing "
    "evidence and do not treat a single reputation signal or MITRE mapping as definitive proof."
)
INVESTIGATION_SYSTEM = (
    "You are a SOC investigation analyst. Correlate evidence across stages, distinguish facts from assumptions, "
    "identify missing evidence, and never claim malicious activity without sufficient support."
)

def triage_prompt(s: dict[str, Any]) -> str:
    return f"""
Analyze the following normalized security alert.

Alert:
{json.dumps(s["alert"], indent=2, ensure_ascii=False)}

Requirements:
- Use only supplied evidence.
- Classify the alert; assign priority low/medium/high/critical; estimate confidence 0.0-1.0.
- Decide suspicious, requires_enrichment, and requires_investigation.
- PowerShell alone is not proof of malicious activity.
- base64_decodings is deterministic tool output; use supplied decoded values exactly.
- For FIM, fim_diff and before/after hashes are authoritative change evidence.
- A FIM change does not identify the actor or prove malicious intent.
- A security-enabling -> security-disabling change without authorization evidence is suspicious and requires investigation.
- Email rule/group metadata is routing metadata, not standalone proof.
- Sender/Reply-To mismatch does not by itself prove spoofing.
- IOC presence alone does not prove an IOC malicious before enrichment.
- Null email_user_clicked or email_attachment_executed means unknown.
- Do not infer compromise, persistence, credential theft, or an actor without evidence.
- Separate facts from assumptions and give concise evidence and a safe next step.

Return only JSON matching the supplied schema.
""".strip()

def enrichment_prompt(s: dict[str, Any]) -> str:
    return f"""
Analyze the following security alert and enrichment evidence.

Normalized alert:
{json.dumps(s["alert"], indent=2, ensure_ascii=False)}

Enrichment evidence:
{json.dumps(s["enrichment"], indent=2, ensure_ascii=False)}

Requirements:
- Evaluate only supplied evidence and identify relevant findings and genuine inconsistencies.
- Scope each TI finding to its exact entity/value; never transfer categories or counts between IOCs.
- VirusTotal known=false means no object/report was returned; it does not mean clean, benign, safe, or zero detections.
- TI counts/categories do not by themselves prove click, execution, credential theft, compromise, or intrusion.
- Null email_user_clicked/email_attachment_executed remains unknown.
- base64_decodings is deterministic; use supplied values exactly and never guess replacements.
- Validate MITRE IDs against observed behavior.
- For FIM, fim_diff and hashes are authoritative; the change does not identify actor or malicious intent.
- A security-weakening FIM change without authorization evidence requires deeper investigation.
- Estimate confidence, decide requires_investigation, summarize concisely, and recommend the next SOC step.

Return only JSON matching the supplied schema.
""".strip()

def investigation_prompt(s: dict[str, Any]) -> str:
    return f"""
Investigate the following security case.

Normalized alert:
{json.dumps(s["alert"], indent=2, ensure_ascii=False)}

Triage result:
{json.dumps(s["triage_reference"], indent=2, ensure_ascii=False)}

Enrichment data:
{json.dumps(s["enrichment"], indent=2, ensure_ascii=False)}

Enrichment assessment:
{json.dumps(s["enrichment_assessment_reference"], indent=2, ensure_ascii=False)}

Retrieved SOC knowledge:
{json.dumps(s["knowledge"], indent=2, ensure_ascii=False)}

Requirements:
- Correlate all supplied evidence; separate facts from assumptions.
- Identify strongest evidence, genuine contradictions, and important missing evidence.
- Retrieved SOC knowledge is guidance, not incident evidence and never overrides telemetry.
- base64_decodings is deterministic; use supplied decoded values exactly.
- Validate MITRE mappings against observed behavior; use canonical technique IDs only.
- T1059.001 is supported by mapped PowerShell execution; T1027 by mapped deterministic Base64 decoding.
- T1565.001 is supported by mapped direct FIM modification; behavioral support does not prove malicious intent.
- FIM diff/hashes are deterministic; FIM does not identify actor or prove compromise.
- A security-enabling -> security-disabling FIM change without authorization evidence warrants remediation planning,
  but system-changing action remains subject to human approval.
- For email, separate message/IOC verdict from user impact.
- Malicious/phishing TI can support a phishing-message assessment without proving click, credential submission,
  execution, persistence, or endpoint compromise.
- VirusTotal known=false for a hash is unknown, not clean/benign/safe/zero detections.
- Null email action fields remain unknown.
- Decide whether remediation is actually required; avoid disruptive remediation without evidence.
- Provide a concise SOC summary and next step.

Return only JSON matching the supplied schema.
""".strip()

TASKS = {
    "triage": {"schema_model": TriageResult, "system": TRIAGE_SYSTEM, "prompt_builder": triage_prompt},
    "enrichment": {"schema_model": EnrichmentAssessment, "system": ENRICHMENT_SYSTEM, "prompt_builder": enrichment_prompt},
    "investigation": {"schema_model": InvestigationResult, "system": INVESTIGATION_SYSTEM, "prompt_builder": investigation_prompt},
}

EXPECTED = {
    "triage": {
        "powershell": {"suspicious": True, "requires_enrichment": True, "requires_investigation": True},
        "fim": {"suspicious": True, "requires_enrichment": True, "requires_investigation": True},
        "phishing": {"suspicious": True, "requires_enrichment": True, "requires_investigation": True},
    },
    "enrichment": {
        "powershell": {"requires_investigation": True},
        "fim": {"requires_investigation": True},
        "phishing": {"requires_investigation": True},
    },
    "investigation": {
        "powershell": {"verdict": "suspicious", "requires_remediation": False},
        "fim": {"verdict": "suspicious", "requires_remediation": True},
        "phishing": {"verdict": "likely_malicious", "requires_remediation": False},
    },
}

def normalize_scalar(v: Any) -> Any:
    return v.value if hasattr(v, "value") else v

def flatten_text(v: Any) -> str:
    out: list[str] = []
    def walk(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            for y in x.values():
                walk(y)
        elif isinstance(x, (list, tuple, set)):
            for y in x:
                walk(y)
    walk(v)
    return "\n".join(out)

def extract_mitre_ids(values: Any) -> set[str]:
    out: set[str] = set()
    if not isinstance(values, list):
        return out
    for value in values:
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(value), flags=re.I)
        if m:
            out.add(m.group(0).upper())
    return out

def semantic_checks(task: str, scenario: str, parsed: dict[str, Any]) -> tuple[list[str], list[str]]:
    critical: list[str] = []
    notes: list[str] = []
    text = flatten_text(parsed).lower()

    strong_bad = [
        "endpoint is compromised",
        "host is compromised",
        "confirmed endpoint compromise",
        "confirmed host compromise",
        "credential theft confirmed",
        "credentials were stolen",
        "persistence is confirmed",
    ]
    for phrase in strong_bad:
        if phrase in text:
            critical.append(f"unsupported_positive_claim:{phrase}")

    if scenario == "powershell":
        if task in {"enrichment", "investigation"} and "soc-lab-ps-e2e-rag-1" not in text:
            notes.append("deterministic decoded value not surfaced")
        if task == "investigation":
            valid = extract_mitre_ids(parsed.get("validated_mitre_techniques", []))
            reject = extract_mitre_ids(parsed.get("rejected_mitre_techniques", []))
            for tid in {"T1059.001", "T1027"}:
                if tid not in valid:
                    critical.append(f"missing_validated_mitre:{tid}")
                if tid in reject:
                    critical.append(f"supported_mitre_rejected:{tid}")

    elif scenario == "fim":
        if "secure" not in text or "disabled" not in text:
            notes.append("FIM secure->disabled state not clearly surfaced")
        for phrase in (
            "mode=disabled to mode=secure",
            "from 'mode=disabled' to 'mode=secure'",
            'from "mode=disabled" to "mode=secure"',
            "disabled -> secure",
        ):
            if phrase in text:
                critical.append("reversed_fim_direction")
                break
        for phrase in ("attacker changed", "attacker modified", "malicious actor changed", "malicious actor modified"):
            if phrase in text:
                critical.append(f"unsupported_actor_attribution:{phrase}")
        if task == "investigation":
            valid = extract_mitre_ids(parsed.get("validated_mitre_techniques", []))
            reject = extract_mitre_ids(parsed.get("rejected_mitre_techniques", []))
            if "T1565.001" not in valid:
                critical.append("missing_validated_mitre:T1565.001")
            if "T1565.001" in reject:
                critical.append("supported_mitre_rejected:T1565.001")

    elif scenario == "phishing":
        for phrase in (
            "hash is benign",
            "hash is clean",
            "hash is safe",
            "attachment hash is benign",
            "attachment hash is clean",
            "sender is spoofed",
            "confirmed spoofing",
        ):
            if phrase in text:
                critical.append(f"unsupported_email_claim:{phrase}")
        if task in {"enrichment", "investigation"}:
            if not any(
                term in text
                for term in ("unknown", "not established", "no evidence", "not supplied", "not confirm", "does not prove")
            ):
                notes.append("email uncertainty not clearly preserved")
            if task == "enrichment":
                if "9 malicious" not in text:
                    notes.append("exact URL malicious count not surfaced")
                if "10 malicious" not in text:
                    notes.append("exact domain malicious count not surfaced")

    return critical, notes

def score_run(task: str, scenario: str, parsed: dict[str, Any]) -> tuple[int, list[str], list[str]]:
    expected = EXPECTED[task][scenario]
    critical: list[str] = []
    score = 20
    per_field = 60 / len(expected)
    for field, exp in expected.items():
        actual = normalize_scalar(parsed.get(field))
        if actual == exp:
            score += per_field
        else:
            critical.append(f"{field}: expected={exp!r}, actual={actual!r}")
    sem_critical, notes = semantic_checks(task, scenario, parsed)
    critical.extend(sem_critical)
    score += 20 if not sem_critical else max(0, 20 - 10 * len(sem_critical))
    return int(round(min(100, score))), critical, notes

def critical_signature(task: str, parsed: dict[str, Any]) -> dict[str, Any]:
    if task == "triage":
        keys = ["priority", "suspicious", "requires_enrichment", "requires_investigation"]
        return {k: normalize_scalar(parsed.get(k)) for k in keys}
    if task == "enrichment":
        keys = ["risk_level", "requires_investigation"]
        return {k: normalize_scalar(parsed.get(k)) for k in keys}
    return {
        "verdict": normalize_scalar(parsed.get("verdict")),
        "requires_remediation": normalize_scalar(parsed.get("requires_remediation")),
        "validated_mitre_techniques": sorted(extract_mitre_ids(parsed.get("validated_mitre_techniques", []))),
        "rejected_mitre_techniques": sorted(extract_mitre_ids(parsed.get("rejected_mitre_techniques", []))),
    }

def ns_to_seconds(v: Any) -> float:
    return float(v or 0) / 1_000_000_000

def p95(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=20, method="inclusive")[18]

def unload(model: str) -> None:
    try:
        httpx.post(
            f"{OLLAMA}/api/generate",
            json={"model": model, "prompt": "", "stream": False, "keep_alive": 0},
            timeout=30,
        )
    except Exception:
        pass

def unload_all() -> None:
    for model in sorted({x["model"] for x in FAST_CANDIDATES + REASONING_CANDIDATES}):
        unload(model)

def warm_model(client: httpx.Client, candidate: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    r = client.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": candidate["model"],
            "prompt": "",
            "stream": False,
            "keep_alive": KEEP_ALIVE,
            "options": {"num_predict": 1, "num_ctx": NUM_CTX},
        },
        timeout=TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    data = r.json()
    return {
        "wall_seconds": round(time.perf_counter() - started, 3),
        "load_seconds": round(ns_to_seconds(data.get("load_duration")), 3),
    }

def run_chat(
    client: httpx.Client,
    candidate: dict[str, Any],
    task_name: str,
    scenario_name: str,
) -> dict[str, Any]:
    cfg = TASKS[task_name]
    model_cls = cfg["schema_model"]
    scenario = SCENARIOS[scenario_name]
    started = time.perf_counter()
    r = client.post(
        f"{OLLAMA}/api/chat",
        json={
            "model": candidate["model"],
            "messages": [
                {"role": "system", "content": cfg["system"]},
                {"role": "user", "content": cfg["prompt_builder"](scenario)},
            ],
            "stream": False,
            "think": candidate["think"],
            "format": model_cls.model_json_schema(),
            "keep_alive": KEEP_ALIVE,
            "options": {
                "temperature": 0,
                "num_ctx": NUM_CTX,
                "num_predict": NUM_PREDICT,
            },
        },
        timeout=TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    wall = time.perf_counter() - started
    data = r.json()
    msg = data.get("message") or {}
    content = (msg.get("content") or "").strip()
    thinking = msg.get("thinking") or ""

    parsed = None
    parse_error = None
    try:
        obj = model_cls.model_validate_json(content)
        parsed = obj.model_dump(mode="json")
    except Exception as exc:
        parse_error = repr(exc)

    if parsed is None:
        score, critical, notes, signature = 0, ["schema_or_parse_failure"], [], None
    else:
        score, critical, notes = score_run(task_name, scenario_name, parsed)
        signature = critical_signature(task_name, parsed)

    eval_count = int(data.get("eval_count") or 0)
    eval_duration = int(data.get("eval_duration") or 0)
    tps = eval_count / (eval_duration / 1e9) if eval_count and eval_duration else None

    return {
        "status": "ok",
        "candidate": candidate["candidate"],
        "model": candidate["model"],
        "think": candidate["think"],
        "profile": "fast" if task_name in {"triage", "enrichment"} else "reasoning",
        "task": task_name,
        "scenario": scenario_name,
        "schema_ok": parsed is not None,
        "score": score,
        "critical_errors": critical,
        "notes": notes,
        "decision_signature": signature,
        "wall_seconds": round(wall, 3),
        "load_seconds": round(ns_to_seconds(data.get("load_duration")), 3),
        "prompt_tokens": int(data.get("prompt_eval_count") or 0),
        "output_tokens": eval_count,
        "thinking_chars": len(thinking),
        "generation_tps": round(tps, 2) if tps is not None else None,
        "done_reason": data.get("done_reason"),
        "parse_error": parse_error,
        "response": content,
    }

ORDERS = [
    ["powershell", "fim", "phishing"],
    ["fim", "phishing", "powershell"],
    ["phishing", "powershell", "fim"],
]

def execute_profile(
    profile: str,
    candidates: list[dict[str, Any]],
    tasks: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    warmups: list[dict[str, Any]] = []
    print("\n" + "=" * 88)
    print(f"{profile.upper()} PROFILE")
    print("=" * 88)

    for idx, candidate in enumerate(candidates, 1):
        print("\n" + "-" * 88)
        print(
            f"[{idx}/{len(candidates)}] {candidate['candidate']} | "
            f"{candidate['model']} | think={candidate['think']}"
        )
        print("-" * 88)
        unload_all()
        time.sleep(1)

        with httpx.Client() as client:
            try:
                warm = warm_model(client, candidate)
                warmups.append({"profile": profile, **candidate, **warm})
                print(
                    f"Warm-up excluded: wall={warm['wall_seconds']:.2f}s | "
                    f"load={warm['load_seconds']:.2f}s"
                )
            except Exception as exc:
                print(f"WARM-UP ERROR: {exc!r}")
                continue

            for repeat in range(1, REPEATS + 1):
                order = ORDERS[(repeat - 1) % len(ORDERS)]
                for task in tasks:
                    for scenario in order:
                        print(f"[R{repeat}] {task:<13} {scenario:<10} ... ", end="", flush=True)
                        try:
                            row = run_chat(client, candidate, task, scenario)
                            row["repeat"] = repeat
                            rows.append(row)
                            print(
                                f"{row['score']:>3}/100 | {row['wall_seconds']:.2f}s | "
                                f"schema={row['schema_ok']} | critical={len(row['critical_errors'])}"
                            )
                        except Exception as exc:
                            row = {
                                "status": "error",
                                "candidate": candidate["candidate"],
                                "model": candidate["model"],
                                "think": candidate["think"],
                                "profile": profile,
                                "task": task,
                                "scenario": scenario,
                                "repeat": repeat,
                                "schema_ok": False,
                                "score": 0,
                                "critical_errors": ["request_error"],
                                "notes": [],
                                "decision_signature": None,
                                "error": repr(exc),
                            }
                            rows.append(row)
                            print(f"ERROR: {exc!r}")

        unload(candidate["model"])

    return rows, warmups

def summarize(rows: list[dict[str, Any]], candidate: str, profile: str) -> dict[str, Any]:
    selected = [r for r in rows if r["candidate"] == candidate and r["profile"] == profile]
    ok = [r for r in selected if r["status"] == "ok"]
    scores = [int(r["score"]) for r in selected]
    walls = [float(r["wall_seconds"]) for r in ok if r.get("wall_seconds") is not None]
    schema_rate = 100 * sum(bool(r.get("schema_ok")) for r in selected) / len(selected) if selected else 0
    critical_rows = [r for r in selected if r.get("critical_errors")]

    groups: dict[tuple[str, str], list[str]] = {}
    for r in ok:
        sig = r.get("decision_signature")
        if sig is None:
            continue
        groups.setdefault((r["task"], r["scenario"]), []).append(
            json.dumps(sig, sort_keys=True, ensure_ascii=False)
        )

    stable = 0
    detail = []
    for key, sigs in sorted(groups.items()):
        is_stable = len(sigs) == REPEATS and len(set(sigs)) == 1
        stable += int(is_stable)
        detail.append(
            {"task": key[0], "scenario": key[1], "stable": is_stable, "unique_signatures": len(set(sigs))}
        )
    stability_rate = 100 * stable / len(groups) if groups else 0
    mean_score = statistics.mean(scores) if scores else 0
    min_score = min(scores) if scores else 0

    gate = (
        bool(selected)
        and len(ok) == len(selected)
        and schema_rate == 100
        and len(critical_rows) == 0
        and mean_score >= 90
        and min_score >= 80
        and stability_rate == 100
    )

    return {
        "candidate": candidate,
        "profile": profile,
        "runs_ok": len(ok),
        "runs_total": len(selected),
        "mean_score": round(mean_score, 2),
        "min_score": min_score,
        "schema_rate": round(schema_rate, 2),
        "critical_failure_runs": len(critical_rows),
        "decision_stability_rate": round(stability_rate, 2),
        "median_latency_seconds": round(statistics.median(walls), 2) if walls else None,
        "p95_latency_seconds": round(p95(walls), 2) if walls else None,
        "quality_gate": gate,
        "stability_detail": detail,
        "critical_failure_detail": [
            {
                "task": r["task"],
                "scenario": r["scenario"],
                "repeat": r["repeat"],
                "errors": r["critical_errors"],
            }
            for r in critical_rows
        ],
    }

print("=" * 88)
print("LOCAL 3-SCENARIO FAST QWEN3:4B-INSTRUCT ADD-ON")
print("=" * 88)
print("Scenarios: PowerShell | FIM | Phishing")
print(f"Repeats: {REPEATS}")
print("Measured endpoint: /api/chat")
print("Schemas: actual project Pydantic schemas")
print("Purpose: one final FAST-only challenger check; same prompts/rubric as prior benchmark")

unload_all()

fast_rows, fast_warmups = execute_profile(
    "fast",
    FAST_CANDIDATES,
    ["triage", "enrichment"],
)

all_rows = fast_rows
warmups = fast_warmups

summaries = [
    summarize(
        all_rows,
        FAST_CANDIDATES[0]["candidate"],
        "fast",
    )
]

fast_pass = [
    x
    for x in summaries
    if x["profile"] == "fast" and x["quality_gate"]
]

recommendation = {
    "fast": (
        fast_pass[0]["candidate"]
        if fast_pass
        else None
    ),
    "reasoning": None,
}

payload = {
    "generated_at": datetime.now().isoformat(timespec="seconds"),
    "benchmark": {
        "name": "local_3scenario_fast_qwen3_4b_addon",
        "endpoint": "/api/chat",
        "scenarios": list(SCENARIOS.keys()),
        "repeats": REPEATS,
        "num_ctx": NUM_CTX,
        "num_predict": NUM_PREDICT,
        "temperature": 0,
        "timeout_seconds": TIMEOUT_SECONDS,
        "fast_tasks": ["triage", "enrichment"],
        "candidate": FAST_CANDIDATES[0],
        "note": (
            "FAST-only add-on using the same three scenarios, prompts, schemas, "
            "scoring, semantic checks, and quality gate as the previous final "
            "3-scenario benchmark. It exists only to test qwen3:4b-instruct as "
            "the last FAST challenger without rerunning eliminated models."
        ),
    },
    "schemas": {
        "triage": TriageResult.model_json_schema(),
        "enrichment": EnrichmentAssessment.model_json_schema(),
    },
    "warmups": warmups,
    "summary": summaries,
    "recommendation": recommendation,
    "results": all_rows,
}

JSON_OUT.write_text(
    json.dumps(payload, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

csv_fields = [
    "profile", "candidate", "model", "think", "task", "scenario", "repeat", "status",
    "schema_ok", "score", "wall_seconds", "load_seconds", "prompt_tokens", "output_tokens",
    "thinking_chars", "generation_tps", "done_reason", "critical_errors", "notes",
    "decision_signature", "parse_error", "response", "error",
]

with CSV_OUT.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=csv_fields,
        extrasaction="ignore",
    )
    writer.writeheader()

    for row in all_rows:
        r = dict(row)
        for field in (
            "critical_errors",
            "notes",
            "decision_signature",
        ):
            r[field] = json.dumps(
                r.get(field),
                ensure_ascii=False,
                sort_keys=True,
            )
        writer.writerow(r)

item = summaries[0]

lines = [
    "=" * 88,
    "LOCAL 3-SCENARIO FAST QWEN3:4B-INSTRUCT ADD-ON",
    "=" * 88,
    "",
    "SCENARIOS: PowerShell | FIM | Phishing",
    "FAST TASKS: Triage + Enrichment",
    f"REPEATS: {REPEATS}",
    "",
    f"FAST | {item['candidate']}",
    f"  runs              : {item['runs_ok']}/{item['runs_total']}",
    f"  mean score        : {item['mean_score']}",
    f"  minimum           : {item['min_score']}",
    f"  schema            : {item['schema_rate']}%",
    f"  critical failures : {item['critical_failure_runs']}",
    f"  decision stability: {item['decision_stability_rate']}%",
    f"  median latency    : {item['median_latency_seconds']}s",
    f"  p95 latency       : {item['p95_latency_seconds']}s",
    f"  QUALITY GATE      : {item['quality_gate']}",
]

if item["critical_failure_detail"]:
    lines.append("  critical detail:")
    for failure in item["critical_failure_detail"]:
        lines.append(
            "    - "
            + json.dumps(
                failure,
                ensure_ascii=False,
            )
        )

lines += [
    "",
    "=" * 88,
    "ADD-ON RESULT",
    "=" * 88,
    f"FAST      : {recommendation['fast']}",
]

TXT_OUT.write_text(
    "\n".join(lines),
    encoding="utf-8",
)

now = time.time()
for path in (
    JSON_OUT,
    CSV_OUT,
    TXT_OUT,
):
    os.utime(
        path,
        (now, now),
    )

print()
print("=" * 88)
print("FINAL ADD-ON SUMMARY")
print("=" * 88)
print(f"FAST | {item['candidate']}")
print(f"  runs              : {item['runs_ok']}/{item['runs_total']}")
print(f"  mean score        : {item['mean_score']}")
print(f"  minimum           : {item['min_score']}")
print(f"  schema            : {item['schema_rate']}%")
print(f"  critical failures : {item['critical_failure_runs']}")
print(f"  decision stability: {item['decision_stability_rate']}%")
print(f"  median latency    : {item['median_latency_seconds']}s")
print(f"  p95 latency       : {item['p95_latency_seconds']}s")
print(f"  QUALITY GATE      : {item['quality_gate']}")

print()
print("=" * 88)
print("FILES")
print("=" * 88)
print(TXT_OUT)
print(CSV_OUT)
print(JSON_OUT)

unload_all()
