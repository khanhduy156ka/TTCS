import csv
import json
import os
import statistics
import time
from datetime import datetime
from pathlib import Path

import httpx


OLLAMA = "http://127.0.0.1:11434"

OUT_DIR = Path.home() / "Downloads"

JSON_OUT = OUT_DIR / "local_decisive_final.json"
CSV_OUT = OUT_DIR / "local_decisive_final.csv"
TXT_OUT = OUT_DIR / "local_decisive_final.txt"

NUM_CTX = 8192
NUM_PREDICT = 1024
TIMEOUT = 180

RETEST_THRESHOLD = 90

ANCHOR_CASES = {
    "phishing_unknown_execution",
    "confirmed_persistence",
}


SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "confidence",
        "requires_investigation",
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
        "reason",
        "next_action",
    ],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": [
                "benign",
                "suspicious",
                "likely_malicious",
            ],
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "requires_investigation": {
            "type": "boolean",
        },
        "compromise_confirmed": {
            "type": "boolean",
        },
        "persistence_confirmed": {
            "type": "boolean",
        },
        "credential_theft_confirmed": {
            "type": "boolean",
        },
        "unknown_is_benign": {
            "type": "boolean",
        },
        "reason": {
            "type": "string",
        },
        "next_action": {
            "type": "string",
        },
    },
}


CANDIDATES = [
    {
        "name": "qwen3_4b_instruct",
        "model": "qwen3:4b-instruct",
        "think": False,
        "roles": ["fast"],
    },
    {
        "name": "qwen3_5_4b_no_think",
        "model": "qwen3.5:4b",
        "think": False,
        "roles": ["fast"],
    },
    {
        "name": "qwen3_8b_no_think",
        "model": "qwen3:8b",
        "think": False,
        "roles": ["fast"],
    },
    {
        "name": "qwen3_5_9b_no_think",
        "model": "qwen3.5:9b",
        "think": False,
        "roles": [
            "fast",
            "reasoning",
        ],
    },
    {
        "name": "gpt_oss_20b_low",
        "model": "gpt-oss:20b",
        "think": "low",
        "roles": ["reasoning"],
    },
    {
        "name": "gpt_oss_20b_medium",
        "model": "gpt-oss:20b",
        "think": "medium",
        "roles": ["reasoning"],
    },
]


CASES = [
    {
        "id": "powershell_obfuscation",
        "evidence": """
Windows PowerShell Event ID 4104 was recorded.
The script contains Base64 decoding using FromBase64String.
There is no evidence that malware executed.
There is no evidence of persistence.
There is no evidence of credential theft.
The decoded content has not yet been independently classified.
""".strip(),
        "expected": {
            "verdict": "suspicious",
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
    },
    {
        "id": "approved_powershell",
        "evidence": """
Windows PowerShell Event ID 4104 was recorded.
The script uses Base64 decoding to decode the text HELLO.
The script is digitally signed by the organization's trusted
administration certificate.
Change ticket CHG-2026-1042 explicitly authorizes this script
during the observed maintenance window.
No suspicious child process or network connection was observed.
There is no evidence of persistence or credential theft.
""".strip(),
        "expected": {
            "verdict": "benign",
            "requires_investigation": False,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "verdict": "benign",
            "requires_investigation": False,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
        },
    },
    {
        "id": "fim_security_tamper",
        "evidence": """
File integrity monitoring recorded an unauthorized change to
C:\\SOC-Lab\\Protected\\config.txt.
The value changed from mode=secure to mode=disabled.
No approved change ticket exists for this modification.
There is no evidence showing malware execution.
There is no evidence of persistence.
There is no evidence of credential theft.
""".strip(),
        "expected": {
            "verdict": "suspicious",
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "verdict": "suspicious",
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
        },
    },
    {
        "id": "phishing_unknown_execution",
        "evidence": """
An email impersonates a Microsoft billing notification.
The embedded URL domain has multiple malicious detections from
a threat-intelligence service.
The attachment SHA256 is unknown to the reputation service.
Whether the recipient clicked the URL is unknown.
Whether the attachment executed is unknown.
There is no endpoint telemetry confirming compromise,
persistence, or credential theft.
""".strip(),
        "expected": {
            "verdict": "likely_malicious",
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
    },
    {
        "id": "confirmed_persistence",
        "evidence": """
Endpoint telemetry records schtasks.exe creating a previously
unknown scheduled task that launches PowerShell with an encoded
command at user logon.
The scheduled task was successfully created and subsequently ran.
The resulting PowerShell process connected to a domain confirmed
malicious by threat intelligence.
This activity was not authorized by any change ticket.
No evidence of credential theft was observed.
""".strip(),
        "expected": {
            "verdict": "likely_malicious",
            "requires_investigation": True,
            "compromise_confirmed": True,
            "persistence_confirmed": True,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "requires_investigation": True,
            "compromise_confirmed": True,
            "persistence_confirmed": True,
            "credential_theft_confirmed": False,
        },
    },

    # Case moi 1, kiem tra false positive voi scheduled task hop le
    {
        "id": "authorized_backup_task",
        "evidence": """
Endpoint telemetry shows BackupAgent.exe creating a scheduled task
named CorporateBackup at 02:00 every day.
BackupAgent.exe is digitally signed by the organization's approved
backup-software vendor.
Change ticket CHG-2026-2204 explicitly authorizes deployment of
this task to the endpoint.
The task subsequently executed and connected only to the
organization's documented internal backup server.
No suspicious child process, credential access, or external
network connection was observed.
""".strip(),
        "expected": {
            "verdict": "benign",
            "requires_investigation": False,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "verdict": "benign",
            "requires_investigation": False,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
        },
    },

    # Case moi 2, co bang chung credential access ro rang
    {
        "id": "confirmed_credential_dumping",
        "evidence": """
Endpoint telemetry records an unsigned executable launched from
the user's temporary directory.
The process opened LSASS with memory-read access and created
C:\\Users\\Public\\lsass.dmp.
The command line explicitly invoked a credential-dumping routine.
There is no approved administrative or diagnostic ticket for
this activity.
The dump file was successfully created.
No persistence mechanism has been observed.
""".strip(),
        "expected": {
            "verdict": "likely_malicious",
            "requires_investigation": True,
            "compromise_confirmed": True,
            "persistence_confirmed": False,
            "credential_theft_confirmed": True,
            "unknown_is_benign": False,
        },
        "critical": {
            "verdict": "likely_malicious",
            "requires_investigation": True,
            "compromise_confirmed": True,
            "persistence_confirmed": False,
            "credential_theft_confirmed": True,
        },
    },

    # Case moi 3, authentication dang ngo nhung chua co bang chung compromise
    {
        "id": "failed_login_burst_no_success",
        "evidence": """
Authentication telemetry records 42 failed login attempts against
one employee account from the same external IP address during a
three-minute period.
All attempts failed.
No successful login from that IP address was recorded.
No session token was issued.
No endpoint activity, persistence, or credential-dumping activity
was observed.
The source IP has no confirmed malicious reputation.
""".strip(),
        "expected": {
            "verdict": "suspicious",
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
            "unknown_is_benign": False,
        },
        "critical": {
            "requires_investigation": True,
            "compromise_confirmed": False,
            "persistence_confirmed": False,
            "credential_theft_confirmed": False,
        },
    },
]


DECISION_FIELDS = [
    "verdict",
    "requires_investigation",
    "compromise_confirmed",
    "persistence_confirmed",
    "credential_theft_confirmed",
    "unknown_is_benign",
]


def make_prompt(evidence):
    return f"""
You are a security operations center analyst.

Analyze only the supplied evidence.

Do not invent observations or indicators.
Distinguish observed facts from inference and unknown facts.

Decision definitions:

benign:
Evidence clearly supports authorized or non-malicious activity.

suspicious:
Evidence shows unauthorized, unexplained, or suspicious behavior
requiring investigation, but does not provide strong evidence
of malicious activity.

likely_malicious:
Evidence contains strong malicious indicators or explicitly
observed malicious behavior.

Rules:

- Unknown evidence is never automatically benign.
- A malicious IOC alone does not prove endpoint compromise.
- Set compromise_confirmed=true only when endpoint evidence
  explicitly demonstrates successful malicious execution or
  established malicious activity.
- Set persistence_confirmed=true only when the evidence explicitly
  demonstrates an unauthorized persistence mechanism that has
  been successfully established.
- Legitimate scheduled tasks explicitly authorized by change
  control are not malicious persistence.
- Set credential_theft_confirmed=true only when supplied evidence
  explicitly demonstrates credential dumping, theft, or successful
  credential access.
- requires_investigation=false only when evidence clearly supports
  benign authorized activity.

Evidence:
{evidence}

Return only the structured result required by the schema.
Keep reason and next_action concise.
""".strip()


def schema_ok(obj):
    if not isinstance(obj, dict):
        return False

    if set(obj.keys()) != set(SCHEMA["required"]):
        return False

    if obj["verdict"] not in {
        "benign",
        "suspicious",
        "likely_malicious",
    }:
        return False

    confidence = obj["confidence"]

    if not isinstance(confidence, (int, float)):
        return False

    if not 0 <= confidence <= 1:
        return False

    for key in DECISION_FIELDS[1:]:
        if not isinstance(obj[key], bool):
            return False

    return (
        isinstance(obj["reason"], str)
        and isinstance(obj["next_action"], str)
    )


def score(obj, expected):
    if not schema_ok(obj):
        return 0, {}

    # Tong diem = 100
    value = 10

    checks = {}

    for key, expected_value in expected.items():
        checks[key] = (
            obj.get(key) == expected_value
        )

    if checks["verdict"]:
        value += 20

    if checks["requires_investigation"]:
        value += 10

    if checks["compromise_confirmed"]:
        value += 15

    if checks["persistence_confirmed"]:
        value += 15

    if checks["credential_theft_confirmed"]:
        value += 15

    if checks["unknown_is_benign"]:
        value += 15

    return value, checks


def critical_errors(obj, critical):
    if not schema_ok(obj):
        return ["schema"]

    errors = []

    for key, expected_value in critical.items():
        if obj.get(key) != expected_value:
            errors.append(
                f"{key}: "
                f"expected={expected_value!r}, "
                f"actual={obj.get(key)!r}"
            )

    return errors


def unload(model):
    try:
        httpx.post(
            f"{OLLAMA}/api/generate",
            json={
                "model": model,
                "prompt": "",
                "stream": False,
                "keep_alive": 0,
            },
            timeout=30,
        )
    except Exception:
        pass


def unload_all():
    models = sorted({
        candidate["model"]
        for candidate in CANDIDATES
    })

    for model in models:
        unload(model)


def ns_to_seconds(value):
    if not value:
        return 0.0

    return value / 1_000_000_000


def warm_up(client, candidate):
    prompt = make_prompt("""
A signed endpoint-management utility executed an authorized
inventory command during a documented maintenance window.
No suspicious child process or network activity was observed.
""".strip())

    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/chat",
        json={
            "model": candidate["model"],
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "stream": False,
            "think": candidate["think"],
            "format": SCHEMA,
            "keep_alive": "15m",
            "options": {
                "temperature": 0,
                "num_predict": NUM_PREDICT,
                "num_ctx": NUM_CTX,
            },
        },
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    data = response.json()

    return {
        "wall_seconds": (
            time.perf_counter()
            - started
        ),
        "load_seconds": ns_to_seconds(
            data.get("load_duration")
        ),
    }


def run_call(
    client,
    candidate,
    case,
    phase,
):
    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/chat",
        json={
            "model": candidate["model"],
            "messages": [
                {
                    "role": "user",
                    "content": make_prompt(
                        case["evidence"]
                    ),
                }
            ],
            "stream": False,
            "think": candidate["think"],
            "format": SCHEMA,
            "keep_alive": "15m",
            "options": {
                "temperature": 0,
                "num_predict": NUM_PREDICT,
                "num_ctx": NUM_CTX,
            },
        },
        timeout=TIMEOUT,
    )

    response.raise_for_status()

    wall_seconds = (
        time.perf_counter()
        - started
    )

    data = response.json()

    message = (
        data.get("message")
        or {}
    )

    content = (
        message.get("content")
        or ""
    ).strip()

    thinking = (
        message.get("thinking")
        or ""
    )

    try:
        obj = json.loads(content)
    except Exception:
        obj = None

    result_score, checks = score(
        obj,
        case["expected"],
    )

    critical = critical_errors(
        obj,
        case["critical"],
    )

    eval_count = (
        data.get("eval_count")
        or 0
    )

    eval_duration = (
        data.get("eval_duration")
        or 0
    )

    generation_tps = None

    if eval_count and eval_duration:
        generation_tps = (
            eval_count
            / (eval_duration / 1e9)
        )

    return {
        "candidate": candidate["name"],
        "model": candidate["model"],
        "think": candidate["think"],
        "roles": candidate["roles"],
        "case": case["id"],
        "phase": phase,
        "status": "ok",
        "score": result_score,
        "schema_ok": schema_ok(obj),
        "critical_errors": critical,
        "wall_seconds": round(
            wall_seconds,
            3,
        ),
        "load_seconds": round(
            ns_to_seconds(
                data.get("load_duration")
            ),
            3,
        ),
        "prompt_tokens": (
            data.get("prompt_eval_count")
            or 0
        ),
        "output_tokens": eval_count,
        "thinking_chars": len(thinking),
        "generation_tps": (
            round(
                generation_tps,
                2,
            )
            if generation_tps
            else None
        ),
        "done_reason": data.get(
            "done_reason"
        ),
        "checks": checks,
        "decision": {
            key: (
                obj.get(key)
                if isinstance(obj, dict)
                else None
            )
            for key in DECISION_FIELDS
        },
        "response": content,
    }


def p95(values):
    if not values:
        return None

    if len(values) == 1:
        return values[0]

    return statistics.quantiles(
        values,
        n=20,
        method="inclusive",
    )[18]


results = []


print("=" * 78, flush=True)
print("LOCAL DECISIVE FINAL BENCHMARK", flush=True)
print("=" * 78, flush=True)
print(
    f"{len(CANDIDATES)} configs | "
    f"{len(CASES)} cases | "
    "/api/chat | structured output",
    flush=True,
)


for candidate_index, candidate in enumerate(
    CANDIDATES,
    start=1,
):
    print()
    print("=" * 78, flush=True)

    print(
        f"[{candidate_index}/{len(CANDIDATES)}] "
        f"{candidate['name']}",
        flush=True,
    )

    print(
        f"model={candidate['model']} "
        f"think={candidate['think']} "
        f"roles={','.join(candidate['roles'])}",
        flush=True,
    )

    print("=" * 78, flush=True)

    # Khoi dong lai moi candidate tu dau
    unload_all()
    time.sleep(1)

    with httpx.Client() as client:

        try:
            warm = warm_up(
                client,
                candidate,
            )

            print(
                f"Warm-up: "
                f"wall={warm['wall_seconds']:.2f}s | "
                f"load={warm['load_seconds']:.2f}s",
                flush=True,
            )

        except Exception as exc:
            print(
                f"WARM-UP ERROR: {exc!r}",
                flush=True,
            )
            continue

        base_by_case = {}

        # ----------------------------------------------------------
        # Chay moi case mot lan
        # ----------------------------------------------------------

        for case_index, case in enumerate(
            CASES,
            start=1,
        ):
            print(
                f"[BASE {case_index}/{len(CASES)}] "
                f"{case['id']} ... ",
                end="",
                flush=True,
            )

            try:
                row = run_call(
                    client,
                    candidate,
                    case,
                    "base",
                )

                results.append(row)

                base_by_case[
                    case["id"]
                ] = row

                print(
                    f"{row['score']}/100 | "
                    f"{row['wall_seconds']:.2f}s | "
                    f"schema={row['schema_ok']} | "
                    f"critical={len(row['critical_errors'])}",
                    flush=True,
                )

            except Exception as exc:
                row = {
                    "candidate":
                        candidate["name"],
                    "model":
                        candidate["model"],
                    "think":
                        candidate["think"],
                    "roles":
                        candidate["roles"],
                    "case":
                        case["id"],
                    "phase":
                        "base",
                    "status":
                        "error",
                    "score":
                        0,
                    "schema_ok":
                        False,
                    "critical_errors":
                        ["request_error"],
                    "error":
                        repr(exc),
                }

                results.append(row)

                base_by_case[
                    case["id"]
                ] = row

                print(
                    f"ERROR: {exc!r}",
                    flush=True,
                )

        # ----------------------------------------------------------
        # Retest 2 case kho, cac case diem < 90 va moi loi schema/critical
        # ----------------------------------------------------------

        retest_ids = set(
            ANCHOR_CASES
        )

        for case in CASES:
            row = base_by_case[
                case["id"]
            ]

            if (
                row.get("score", 0)
                < RETEST_THRESHOLD
                or not row.get(
                    "schema_ok",
                    False,
                )
                or bool(
                    row.get(
                        "critical_errors"
                    )
                )
            ):
                retest_ids.add(
                    case["id"]
                )

        print()
        print(
            "Retest cases: "
            + ", ".join(
                sorted(retest_ids)
            ),
            flush=True,
        )

        for case in CASES:

            if case["id"] not in retest_ids:
                continue

            print(
                f"[RETEST] "
                f"{case['id']} ... ",
                end="",
                flush=True,
            )

            try:
                row = run_call(
                    client,
                    candidate,
                    case,
                    "retest",
                )

                results.append(row)

                print(
                    f"{row['score']}/100 | "
                    f"{row['wall_seconds']:.2f}s | "
                    f"schema={row['schema_ok']} | "
                    f"critical={len(row['critical_errors'])}",
                    flush=True,
                )

            except Exception as exc:
                row = {
                    "candidate":
                        candidate["name"],
                    "model":
                        candidate["model"],
                    "think":
                        candidate["think"],
                    "roles":
                        candidate["roles"],
                    "case":
                        case["id"],
                    "phase":
                        "retest",
                    "status":
                        "error",
                    "score":
                        0,
                    "schema_ok":
                        False,
                    "critical_errors":
                        ["request_error"],
                    "error":
                        repr(exc),
                }

                results.append(row)

                print(
                    f"ERROR: {exc!r}",
                    flush=True,
                )

    unload(candidate["model"])


# --------------------------------------------------------------
# Tao tong hop ket qua
# --------------------------------------------------------------

summaries = []


for candidate in CANDIDATES:

    rows = [
        row
        for row in results
        if row["candidate"]
        == candidate["name"]
    ]

    base = [
        row
        for row in rows
        if row["phase"] == "base"
    ]

    retests = [
        row
        for row in rows
        if row["phase"] == "retest"
    ]

    valid_base = [
        row
        for row in base
        if row["status"] == "ok"
    ]

    base_scores = [
        row["score"]
        for row in base
    ]

    base_latencies = [
        row["wall_seconds"]
        for row in valid_base
        if row.get("wall_seconds")
        is not None
    ]

    schema_rate = (
        100
        * sum(
            bool(row.get("schema_ok"))
            for row in base
        )
        / len(base)
        if base
        else 0
    )

    critical_error_count = sum(
        len(
            row.get(
                "critical_errors"
            )
            or []
        )
        for row in base
    )

    confirmed_issue_cases = []

    # Chi tinh loi da xac nhan neu no lap lai
    for case in CASES:

        case_base = next(
            (
                row
                for row in base
                if row["case"]
                == case["id"]
            ),
            None,
        )

        case_retest = next(
            (
                row
                for row in retests
                if row["case"]
                == case["id"]
            ),
            None,
        )

        if not case_base or not case_retest:
            continue

        base_problem = (
            case_base.get("score", 0)
            < RETEST_THRESHOLD
            or not case_base.get(
                "schema_ok",
                False,
            )
            or bool(
                case_base.get(
                    "critical_errors"
                )
            )
        )

        retest_problem = (
            case_retest.get("score", 0)
            < RETEST_THRESHOLD
            or not case_retest.get(
                "schema_ok",
                False,
            )
            or bool(
                case_retest.get(
                    "critical_errors"
                )
            )
        )

        if (
            base_problem
            and retest_problem
        ):
            confirmed_issue_cases.append(
                case["id"]
            )

    # Kiem tra do on dinh cua anchor decision
    stable_anchors = 0

    for anchor in ANCHOR_CASES:

        b = next(
            (
                row
                for row in base
                if row["case"]
                == anchor
            ),
            None,
        )

        r = next(
            (
                row
                for row in retests
                if row["case"]
                == anchor
            ),
            None,
        )

        if (
            b
            and r
            and b.get("schema_ok")
            and r.get("schema_ok")
            and b.get("decision")
            == r.get("decision")
        ):
            stable_anchors += 1

    anchor_stability = (
        100
        * stable_anchors
        / len(ANCHOR_CASES)
    )

    mean_score = (
        statistics.mean(
            base_scores
        )
        if base_scores
        else 0
    )

    min_score = (
        min(base_scores)
        if base_scores
        else 0
    )

    quality_gate = (
        len(base)
        == len(CASES)
        and schema_rate == 100
        and mean_score >= 90
        and min_score >= 75
        and critical_error_count == 0
        and anchor_stability == 100
    )

    summaries.append({
        "candidate":
            candidate["name"],
        "model":
            candidate["model"],
        "think":
            candidate["think"],
        "roles":
            candidate["roles"],
        "base_mean_score":
            round(
                mean_score,
                2,
            ),
        "base_min_score":
            min_score,
        "base_schema_rate":
            round(
                schema_rate,
                2,
            ),
        "critical_error_count":
            critical_error_count,
        "anchor_stability_rate":
            round(
                anchor_stability,
                2,
            ),
        "confirmed_issue_cases":
            confirmed_issue_cases,
        "median_latency_seconds":
            round(
                statistics.median(
                    base_latencies
                ),
                2,
            )
            if base_latencies
            else None,
        "p95_latency_seconds":
            round(
                p95(
                    base_latencies
                ),
                2,
            )
            if base_latencies
            else None,
        "quality_gate":
            quality_gate,
    })


# --------------------------------------------------------------
# Chon cau hinh cuoi theo tung role
# --------------------------------------------------------------

fast_pass = [
    item
    for item in summaries
    if (
        "fast"
        in item["roles"]
        and item["quality_gate"]
    )
]

reasoning_pass = [
    item
    for item in summaries
    if (
        "reasoning"
        in item["roles"]
        and item["quality_gate"]
    )
]


# FAST, qua quality gate truoc roi chon model nhanh nhat
fast_ranked = sorted(
    fast_pass,
    key=lambda item: (
        item[
            "median_latency_seconds"
        ]
        if item[
            "median_latency_seconds"
        ] is not None
        else float("inf")
    ),
)


# REASONING, uu tien chat luong roi moi so latency
reasoning_ranked = sorted(
    reasoning_pass,
    key=lambda item: (
        -item["base_mean_score"],
        item[
            "median_latency_seconds"
        ]
        if item[
            "median_latency_seconds"
        ] is not None
        else float("inf"),
    ),
)


recommendation = {
    "fast": (
        fast_ranked[0][
            "candidate"
        ]
        if fast_ranked
        else None
    ),
    "reasoning": (
        reasoning_ranked[0][
            "candidate"
        ]
        if reasoning_ranked
        else None
    ),
}


# --------------------------------------------------------------
# Luu ket qua
# --------------------------------------------------------------

payload = {
    "generated_at":
        datetime.now().isoformat(
            timespec="seconds"
        ),
    "benchmark": {
        "endpoint":
            "/api/chat",
        "cases":
            len(CASES),
        "candidates":
            len(CANDIDATES),
        "num_ctx":
            NUM_CTX,
        "num_predict":
            NUM_PREDICT,
        "temperature":
            0,
        "retest_threshold":
            RETEST_THRESHOLD,
        "anchor_cases":
            sorted(
                ANCHOR_CASES
            ),
    },
    "summary":
        summaries,
    "recommendation":
        recommendation,
    "results":
        results,
}


JSON_OUT.write_text(
    json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)


csv_fields = [
    "candidate",
    "model",
    "think",
    "case",
    "phase",
    "status",
    "score",
    "schema_ok",
    "wall_seconds",
    "load_seconds",
    "prompt_tokens",
    "output_tokens",
    "thinking_chars",
    "generation_tps",
    "done_reason",
    "response",
    "error",
]


with CSV_OUT.open(
    "w",
    newline="",
    encoding="utf-8-sig",
) as handle:

    writer = csv.DictWriter(
        handle,
        fieldnames=csv_fields,
        extrasaction="ignore",
    )

    writer.writeheader()

    for row in results:
        writer.writerow(row)


lines = [
    "=" * 78,
    "LOCAL DECISIVE FINAL BENCHMARK",
    "=" * 78,
    "",
    "SUMMARY",
    "",
]


for item in summaries:

    lines.extend([
        item["candidate"],
        (
            f"  roles           : "
            f"{','.join(item['roles'])}"
        ),
        (
            f"  mean            : "
            f"{item['base_mean_score']}"
        ),
        (
            f"  minimum         : "
            f"{item['base_min_score']}"
        ),
        (
            f"  schema          : "
            f"{item['base_schema_rate']}%"
        ),
        (
            f"  critical errors : "
            f"{item['critical_error_count']}"
        ),
        (
            f"  anchor stability: "
            f"{item['anchor_stability_rate']}%"
        ),
        (
            f"  median latency  : "
            f"{item['median_latency_seconds']}s"
        ),
        (
            f"  p95 latency     : "
            f"{item['p95_latency_seconds']}s"
        ),
        (
            f"  confirmed issues: "
            f"{item['confirmed_issue_cases']}"
        ),
        (
            f"  QUALITY GATE    : "
            f"{item['quality_gate']}"
        ),
        "",
    ])


lines.extend([
    "=" * 78,
    "FINAL RECOMMENDATION",
    "=" * 78,
    (
        f"FAST      : "
        f"{recommendation['fast']}"
    ),
    (
        f"REASONING : "
        f"{recommendation['reasoning']}"
    ),
])


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


# --------------------------------------------------------------
# In tong hop ra console
# --------------------------------------------------------------

print()
print("=" * 78)
print("FINAL SUMMARY")
print("=" * 78)


for item in summaries:

    print()
    print(item["candidate"])

    print(
        f"  roles            : "
        f"{','.join(item['roles'])}"
    )

    print(
        f"  mean score       : "
        f"{item['base_mean_score']}"
    )

    print(
        f"  minimum          : "
        f"{item['base_min_score']}"
    )

    print(
        f"  schema           : "
        f"{item['base_schema_rate']}%"
    )

    print(
        f"  critical errors  : "
        f"{item['critical_error_count']}"
    )

    print(
        f"  anchor stability : "
        f"{item['anchor_stability_rate']}%"
    )

    print(
        f"  median latency   : "
        f"{item['median_latency_seconds']}s"
    )

    print(
        f"  p95 latency      : "
        f"{item['p95_latency_seconds']}s"
    )

    print(
        f"  confirmed issues : "
        f"{item['confirmed_issue_cases']}"
    )

    print(
        f"  QUALITY GATE     : "
        f"{item['quality_gate']}"
    )


print()
print("=" * 78)
print("AUTOMATIC FINAL RECOMMENDATION")
print("=" * 78)

print(
    f"FAST      : "
    f"{recommendation['fast']}"
)

print(
    f"REASONING : "
    f"{recommendation['reasoning']}"
)


print()
print("=" * 78)
print("FILES")
print("=" * 78)

print(TXT_OUT)
print(CSV_OUT)
print(JSON_OUT)


unload_all()
