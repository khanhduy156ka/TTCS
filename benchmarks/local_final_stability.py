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

REPEATS = 3
NUM_CTX = 8192
NUM_PREDICT = 1024
TIMEOUT = 180


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
    },
]


CANDIDATES = [
    {
        "name": "qwen3_4b_instruct",
        "model": "qwen3:4b-instruct",
        "think": False,
        "roles": ["fast"],
    },
    {
        "name": "qwen3_5_9b_no_think",
        "model": "qwen3.5:9b",
        "think": False,
        "roles": ["fast", "reasoning"],
    },
    {
        "name": "gpt_oss_20b_low",
        "model": "gpt-oss:20b",
        "think": "low",
        "roles": ["reasoning"],
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

- benign:
  Evidence clearly supports authorized or non-malicious activity.

- suspicious:
  Evidence shows unauthorized, unexplained, or suspicious behavior
  requiring investigation, but does not provide strong evidence
  of malicious activity.

- likely_malicious:
  Evidence contains strong malicious indicators or explicitly
  observed malicious behavior.

Rules:

- Unknown evidence is never automatically benign.
- A malicious IOC alone does not prove endpoint compromise.
- Set compromise_confirmed=true only when endpoint evidence
  explicitly demonstrates successful malicious execution or
  established malicious activity.
- Set persistence_confirmed=true when a persistence mechanism
  is explicitly established, such as a scheduled task that was
  successfully created and executed.
- Set credential_theft_confirmed=true only when the supplied
  evidence explicitly confirms credential theft.
- requires_investigation=false only when evidence clearly
  supports benign authorized activity.

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

    if not isinstance(
        obj["confidence"],
        (int, float),
    ):
        return False

    if not 0 <= obj["confidence"] <= 1:
        return False

    for key in DECISION_FIELDS[1:]:
        if not isinstance(obj[key], bool):
            return False

    return (
        isinstance(obj["reason"], str)
        and isinstance(obj["next_action"], str)
    )


def score(obj, expected):
    if obj is None:
        return 0, {}

    value = 10

    if schema_ok(obj):
        value += 15

    checks = {}

    for key, expected_value in expected.items():
        checks[key] = (
            obj.get(key) == expected_value
        )

    if checks["verdict"]:
        value += 25

    if checks["requires_investigation"]:
        value += 10

    for key in (
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
    ):
        if checks[key]:
            value += 10

    return value, checks


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


def cold_load(client, candidate):
    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": candidate["model"],
            "prompt": "",
            "stream": False,
            "keep_alive": "15m",
            "options": {
                "num_ctx": NUM_CTX,
            },
        },
        timeout=180,
    )

    response.raise_for_status()

    return time.perf_counter() - started


def warm_up(client, candidate):
    prompt = make_prompt("""
An administrator executed an authorized maintenance command.
A valid change ticket covers the activity.
No suspicious or malicious behavior was observed.
""".strip())

    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": candidate["model"],
            "prompt": prompt,
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

    return time.perf_counter() - started


def run_once(
    client,
    candidate,
    case,
    repeat,
    cold_seconds,
    warmup_seconds,
):
    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": candidate["model"],
            "prompt": make_prompt(
                case["evidence"]
            ),
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

    elapsed = (
        time.perf_counter()
        - started
    )

    data = response.json()

    text = (
        data.get("response")
        or ""
    ).strip()

    try:
        obj = json.loads(text)
        parsed_json = True
    except Exception:
        obj = None
        parsed_json = False

    result_score, checks = score(
        obj,
        case["expected"],
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

    decision = {
        key: (
            obj.get(key)
            if isinstance(obj, dict)
            else None
        )
        for key in DECISION_FIELDS
    }

    return {
        "candidate": candidate["name"],
        "model": candidate["model"],
        "think": candidate["think"],
        "roles": candidate["roles"],
        "case": case["id"],
        "repeat": repeat,
        "status": "ok",
        "score": result_score,
        "parsed_json": parsed_json,
        "schema_ok": schema_ok(obj),
        "wall_seconds": round(
            elapsed,
            3,
        ),
        "cold_load_seconds": round(
            cold_seconds,
            3,
        ),
        "warmup_seconds": round(
            warmup_seconds,
            3,
        ),
        "prompt_tokens": (
            data.get("prompt_eval_count")
            or 0
        ),
        "output_tokens": eval_count,
        "thinking_chars": len(
            data.get("thinking")
            or ""
        ),
        "generation_tps": (
            round(generation_tps, 2)
            if generation_tps
            else None
        ),
        "done_reason": data.get(
            "done_reason"
        ),
        "checks": checks,
        "decision": decision,
        "response": text,
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


def summarize(results):
    summaries = []

    for candidate in CANDIDATES:
        rows = [
            row
            for row in results
            if row["candidate"]
            == candidate["name"]
        ]

        ok = [
            row
            for row in rows
            if row["status"] == "ok"
        ]

        scores = [
            row["score"]
            for row in ok
        ]

        latencies = [
            row["wall_seconds"]
            for row in ok
        ]

        tps_values = [
            row["generation_tps"]
            for row in ok
            if row.get("generation_tps")
            is not None
        ]

        success_rate = (
            100 * len(ok) / len(rows)
            if rows
            else 0
        )

        schema_rate = (
            100
            * sum(
                bool(row.get("schema_ok"))
                for row in ok
            )
            / len(rows)
            if rows
            else 0
        )

        stable_cases = 0

        case_summaries = []

        for case in CASES:
            case_rows = [
                row
                for row in ok
                if row["case"] == case["id"]
            ]

            signatures = [
                json.dumps(
                    row["decision"],
                    sort_keys=True,
                )
                for row in case_rows
            ]

            stable = (
                len(signatures) == REPEATS
                and len(set(signatures)) == 1
            )

            if stable:
                stable_cases += 1

            case_scores = [
                row["score"]
                for row in case_rows
            ]

            case_summaries.append({
                "case": case["id"],
                "mean_score": (
                    round(
                        statistics.mean(
                            case_scores
                        ),
                        2,
                    )
                    if case_scores
                    else 0
                ),
                "min_score": (
                    min(case_scores)
                    if case_scores
                    else 0
                ),
                "decision_stable": stable,
            })

        stability_rate = (
            100
            * stable_cases
            / len(CASES)
        )

        item = {
            "candidate": candidate["name"],
            "model": candidate["model"],
            "think": candidate["think"],
            "roles": candidate["roles"],
            "runs_ok": len(ok),
            "runs_total": len(rows),
            "success_rate": round(
                success_rate,
                2,
            ),
            "schema_rate": round(
                schema_rate,
                2,
            ),
            "mean_score": round(
                statistics.mean(scores),
                2,
            ) if scores else 0,
            "min_score": (
                min(scores)
                if scores
                else 0
            ),
            "median_latency_seconds": (
                round(
                    statistics.median(
                        latencies
                    ),
                    2,
                )
                if latencies
                else None
            ),
            "p95_latency_seconds": (
                round(
                    p95(latencies),
                    2,
                )
                if latencies
                else None
            ),
            "median_generation_tps": (
                round(
                    statistics.median(
                        tps_values
                    ),
                    2,
                )
                if tps_values
                else None
            ),
            "decision_stability_rate": round(
                stability_rate,
                2,
            ),
            "case_summary": case_summaries,
        }

        item["quality_gate"] = (
            item["success_rate"] == 100
            and item["schema_rate"] == 100
            and item["mean_score"] >= 90
            and item["min_score"] >= 75
            and item[
                "decision_stability_rate"
            ] >= 80
        )

        summaries.append(item)

    return summaries


print("=" * 78, flush=True)
print("LOCAL FINAL STABILITY BENCHMARK", flush=True)
print("=" * 78, flush=True)
print(
    f"3 candidates | "
    f"{len(CASES)} cases | "
    f"{REPEATS} repeats/case",
    flush=True,
)

results = []


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

    unload(candidate["model"])

    with httpx.Client() as client:
        try:
            cold_seconds = cold_load(
                client,
                candidate,
            )

            print(
                f"Cold load: "
                f"{cold_seconds:.2f}s",
                flush=True,
            )

            warmup_seconds = warm_up(
                client,
                candidate,
            )

            print(
                f"Warm-up: "
                f"{warmup_seconds:.2f}s",
                flush=True,
            )

        except Exception as exc:
            print(
                f"MODEL LOAD/WARMUP ERROR: "
                f"{exc!r}",
                flush=True,
            )

            for case in CASES:
                for repeat in range(
                    1,
                    REPEATS + 1,
                ):
                    results.append({
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
                        "repeat":
                            repeat,
                        "status":
                            "load_error",
                        "score":
                            0,
                        "schema_ok":
                            False,
                        "error":
                            repr(exc),
                    })

            unload(candidate["model"])
            continue

        for case_index, case in enumerate(
            CASES,
            start=1,
        ):
            for repeat in range(
                1,
                REPEATS + 1,
            ):
                print(
                    f"[{case_index}/{len(CASES)}] "
                    f"{case['id']} "
                    f"run {repeat}/{REPEATS} ... ",
                    end="",
                    flush=True,
                )

                try:
                    row = run_once(
                        client,
                        candidate,
                        case,
                        repeat,
                        cold_seconds,
                        warmup_seconds,
                    )

                    results.append(row)

                    print(
                        f"{row['score']}/100 | "
                        f"{row['wall_seconds']:.2f}s | "
                        f"schema={row['schema_ok']} | "
                        f"done={row['done_reason']}",
                        flush=True,
                    )

                except httpx.TimeoutException:
                    results.append({
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
                        "repeat":
                            repeat,
                        "status":
                            "timeout",
                        "score":
                            0,
                        "schema_ok":
                            False,
                    })

                    print(
                        "TIMEOUT",
                        flush=True,
                    )

                except Exception as exc:
                    results.append({
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
                        "repeat":
                            repeat,
                        "status":
                            "error",
                        "score":
                            0,
                        "schema_ok":
                            False,
                        "error":
                            repr(exc),
                    })

                    print(
                        f"ERROR: {exc!r}",
                        flush=True,
                    )

    unload(candidate["model"])


summary = summarize(results)


print()
print("=" * 78)
print("FINAL SUMMARY")
print("=" * 78)

for item in summary:
    print()
    print(item["candidate"])
    print(
        f"  roles        : "
        f"{','.join(item['roles'])}"
    )
    print(
        f"  mean score   : "
        f"{item['mean_score']}"
    )
    print(
        f"  minimum      : "
        f"{item['min_score']}"
    )
    print(
        f"  median       : "
        f"{item['median_latency_seconds']}s"
    )
    print(
        f"  p95          : "
        f"{item['p95_latency_seconds']}s"
    )
    print(
        f"  schema       : "
        f"{item['schema_rate']}%"
    )
    print(
        f"  stability    : "
        f"{item['decision_stability_rate']}%"
    )
    print(
        f"  quality gate : "
        f"{item['quality_gate']}"
    )

    for case in item["case_summary"]:
        print(
            f"    {case['case']:<30} "
            f"mean={case['mean_score']:<6} "
            f"min={case['min_score']:<3} "
            f"stable={case['decision_stable']}"
        )


payload = {
    "generated_at": datetime.now().isoformat(
        timespec="seconds"
    ),
    "benchmark": {
        "repeats_per_case": REPEATS,
        "num_ctx": NUM_CTX,
        "num_predict": NUM_PREDICT,
        "temperature": 0,
        "structured_output": True,
        "candidates": len(CANDIDATES),
        "cases": len(CASES),
    },
    "summary": summary,
    "results": results,
}


json_path = (
    OUT_DIR
    / "local_final_stability.json"
)

csv_path = (
    OUT_DIR
    / "local_final_stability.csv"
)

txt_path = (
    OUT_DIR
    / "local_final_stability.txt"
)


json_path.write_text(
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
    "repeat",
    "status",
    "score",
    "parsed_json",
    "schema_ok",
    "wall_seconds",
    "cold_load_seconds",
    "warmup_seconds",
    "prompt_tokens",
    "output_tokens",
    "thinking_chars",
    "generation_tps",
    "done_reason",
    "response",
    "error",
]

with csv_path.open(
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
    "LOCAL FINAL STABILITY BENCHMARK",
    "=" * 78,
    "",
    "SUMMARY",
    "",
]

for item in summary:
    lines.append(
        json.dumps(
            item,
            ensure_ascii=False,
        )
    )

lines.extend([
    "",
    "=" * 78,
    "RAW RESPONSES",
    "=" * 78,
])

for row in results:
    lines.extend([
        "",
        (
            f"{row['candidate']} | "
            f"{row['case']} | "
            f"run={row['repeat']}"
        ),
        (
            f"status={row['status']} "
            f"score={row['score']} "
            f"time={row.get('wall_seconds')} "
            f"schema={row.get('schema_ok')} "
            f"done={row.get('done_reason')}"
        ),
        row.get(
            "response",
            row.get(
                "error",
                "<no output>",
            ),
        ),
    ])

txt_path.write_text(
    "\n".join(lines),
    encoding="utf-8",
)


now = time.time()

for path in (
    json_path,
    csv_path,
    txt_path,
):
    os.utime(
        path,
        (now, now),
    )


print()
print("=" * 78)
print("FILES")
print("=" * 78)
print(txt_path)
print(csv_path)
print(json_path)
