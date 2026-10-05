import json
import os
import statistics
import time
from datetime import datetime
from pathlib import Path

import httpx


OLLAMA = "http://127.0.0.1:11434"
MODEL = "qwen3.5:4b"
OUT_DIR = Path.home() / "Downloads"
REPEATS = 2


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


def make_prompt(evidence):
    return f"""
You are a SOC triage analyst.

Use only the supplied evidence.

Rules:
- Do not invent evidence.
- Do not treat unknown information as benign evidence.
- A malicious IOC does not by itself prove endpoint compromise.
- Confirm persistence only when persistence behavior is explicitly
  observed and successfully established.
- Confirm compromise only when supplied endpoint evidence explicitly
  demonstrates successful malicious execution or established
  malicious activity.

Evidence:
{evidence}

Return the structured result requested by the schema.
Keep reason and next_action concise.
""".strip()


def valid_schema(obj):
    if not isinstance(obj, dict):
        return False

    if set(obj.keys()) != set(
        SCHEMA["required"]
    ):
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

    for key in (
        "requires_investigation",
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
    ):
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

    if valid_schema(obj):
        value += 15

    checks = {
        "verdict":
            obj.get("verdict")
            == expected["verdict"],

        "requires_investigation":
            obj.get("requires_investigation")
            == expected["requires_investigation"],

        "compromise_confirmed":
            obj.get("compromise_confirmed")
            == expected["compromise_confirmed"],

        "persistence_confirmed":
            obj.get("persistence_confirmed")
            == expected["persistence_confirmed"],

        "credential_theft_confirmed":
            obj.get("credential_theft_confirmed")
            == expected["credential_theft_confirmed"],

        "unknown_is_benign":
            obj.get("unknown_is_benign")
            == expected["unknown_is_benign"],
    }

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


print("=" * 78, flush=True)
print("QWEN3.5 4B STRUCTURED OUTPUT VERIFICATION", flush=True)
print("=" * 78, flush=True)

results = []

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

        started = time.perf_counter()

        try:
            response = httpx.post(
                f"{OLLAMA}/api/generate",
                json={
                    "model": MODEL,
                    "prompt": make_prompt(
                        case["evidence"]
                    ),
                    "stream": False,
                    "think": False,

                    # Dung structured output goc cua Ollama
                    "format": SCHEMA,

                    "keep_alive": "10m",
                    "options": {
                        "temperature": 0,
                        "num_predict": 256,
                        "num_ctx": 8192,
                    },
                },
                timeout=90,
            )

            response.raise_for_status()
            data = response.json()

            elapsed = (
                time.perf_counter()
                - started
            )

            text = (
                data.get("response")
                or ""
            ).strip()

            try:
                obj = json.loads(text)
                parsed = True
            except Exception:
                obj = None
                parsed = False

            result_score, checks = score(
                obj,
                case["expected"],
            )

            row = {
                "case": case["id"],
                "repeat": repeat,
                "status": "ok",
                "parsed_json": parsed,
                "schema_ok": valid_schema(obj),
                "score": result_score,
                "wall_seconds": round(
                    elapsed,
                    3,
                ),
                "output_tokens": (
                    data.get("eval_count")
                    or 0
                ),
                "done_reason": data.get(
                    "done_reason"
                ),
                "checks": checks,
                "response": text,
            }

            results.append(row)

            print(
                f"{result_score}/100 | "
                f"{elapsed:.2f}s | "
                f"json={parsed} | "
                f"schema={row['schema_ok']} | "
                f"done={row['done_reason']}",
                flush=True,
            )

        except Exception as exc:
            results.append({
                "case": case["id"],
                "repeat": repeat,
                "status": "error",
                "parsed_json": False,
                "schema_ok": False,
                "score": 0,
                "error": repr(exc),
            })

            print(
                f"ERROR: {exc!r}",
                flush=True,
            )


scores = [
    row["score"]
    for row in results
    if row["status"] == "ok"
]

latencies = [
    row["wall_seconds"]
    for row in results
    if row["status"] == "ok"
]

json_rate = (
    100
    * sum(
        bool(row.get("parsed_json"))
        for row in results
    )
    / len(results)
)

schema_rate = (
    100
    * sum(
        bool(row.get("schema_ok"))
        for row in results
    )
    / len(results)
)


summary = {
    "model": MODEL,
    "mode": "think_false_native_json_schema",
    "runs": len(results),
    "mean_score": round(
        statistics.mean(scores),
        2,
    ) if scores else 0,
    "min_score": min(scores) if scores else 0,
    "median_latency_seconds": round(
        statistics.median(latencies),
        2,
    ) if latencies else None,
    "json_parse_rate": round(
        json_rate,
        2,
    ),
    "schema_rate": round(
        schema_rate,
        2,
    ),
}


print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
print(
    json.dumps(
        summary,
        indent=2,
    )
)


payload = {
    "generated_at": datetime.now().isoformat(
        timespec="seconds"
    ),
    "summary": summary,
    "results": results,
}

json_path = (
    OUT_DIR
    / "qwen35_4b_structured_verify.json"
)

txt_path = (
    OUT_DIR
    / "qwen35_4b_structured_verify.txt"
)

json_path.write_text(
    json.dumps(
        payload,
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)

lines = [
    "=" * 78,
    "QWEN3.5 4B STRUCTURED OUTPUT VERIFICATION",
    "=" * 78,
    "",
    json.dumps(
        summary,
        indent=2,
        ensure_ascii=False,
    ),
    "",
    "=" * 78,
    "RESULTS",
    "=" * 78,
]

for row in results:
    lines.extend([
        "",
        (
            f"{row['case']} | "
            f"run={row['repeat']}"
        ),
        (
            f"score={row['score']} "
            f"json={row.get('parsed_json')} "
            f"schema={row.get('schema_ok')} "
            f"time={row.get('wall_seconds')} "
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
    txt_path,
):
    os.utime(
        path,
        (now, now),
    )

# Giai phong model sau khi test
try:
    httpx.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": MODEL,
            "prompt": "",
            "stream": False,
            "keep_alive": 0,
        },
        timeout=30,
    )
except Exception:
    pass

print()
print("FILES:")
print(txt_path)
print(json_path)
