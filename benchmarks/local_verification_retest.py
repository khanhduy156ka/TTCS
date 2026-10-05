import json
import os
import statistics
import time
from datetime import datetime
from pathlib import Path

import httpx


OLLAMA = "http://127.0.0.1:11434"
OUT_DIR = Path.home() / "Downloads"

# Giu cung logic quyet dinh voi benchmark screening
CASES = {
    "approved_powershell": {
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

    "fim_security_tamper": {
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

    "phishing_unknown_execution": {
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

    "confirmed_persistence": {
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
}


# Chi kiem tra lai candidate co ket qua screening chua ro rang
TESTS = [
    # Kiem tra lai FAST
    {
        "profile": "fast",
        "name": "qwen3_5_4b_no_think",
        "model": "qwen3.5:4b",
        "think": False,
        "cases": [
            "fim_security_tamper",
            "phishing_unknown_execution",
            "confirmed_persistence",
        ],
        "repeats": 2,
        "num_predict": 256,
        "timeout": 90,
    },
    {
        "profile": "fast",
        "name": "qwen3_8b_no_think",
        "model": "qwen3:8b",
        "think": False,
        "cases": [
            "phishing_unknown_execution",
            "confirmed_persistence",
        ],
        "repeats": 2,
        "num_predict": 256,
        "timeout": 90,
    },

    # Kiem tra lai REASONING
    {
        "profile": "reasoning",
        "name": "qwen3_8b_think",
        "model": "qwen3:8b",
        "think": True,
        "cases": [
            "approved_powershell",
            "confirmed_persistence",
        ],
        "repeats": 2,
        "num_predict": 1024,
        "timeout": 180,
    },
    {
        "profile": "reasoning",
        "name": "qwen3_5_4b_think",
        "model": "qwen3.5:4b",
        "think": True,
        "cases": [
            "approved_powershell",
            "confirmed_persistence",
        ],
        "repeats": 2,
        # Tang hon muc 512 token cu de thinking khong chiem het output budget
        "num_predict": 1536,
        "timeout": 180,
    },
]


def make_prompt(profile, evidence):
    if profile == "fast":
        instructions = """
Make a fast SOC triage decision.
Use only the supplied evidence.
Do not invent evidence.
Do not treat unknown information as benign evidence.
Do not confirm compromise unless explicitly supported.
""".strip()
    else:
        instructions = """
Perform careful SOC investigation reasoning.
Distinguish observed evidence from inference and unknown facts.
Do not invent evidence.
Do not treat unknown information as benign evidence.
Only confirm compromise, persistence, or credential theft
when explicitly supported by the supplied evidence.
""".strip()

    return f"""
You are a security operations center analyst.

{instructions}

Evidence:
{evidence}

Return exactly one JSON object and nothing else.
Do not use Markdown or code fences.

{{
  "verdict": "benign|suspicious|likely_malicious",
  "confidence": 0.0,
  "requires_investigation": true,
  "compromise_confirmed": false,
  "persistence_confirmed": false,
  "credential_theft_confirmed": false,
  "unknown_is_benign": false,
  "reason": "one or two concise sentences",
  "next_action": "one concise sentence"
}}
""".strip()


def parse_json(text):
    text = text.strip()

    try:
        return json.loads(text), True
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")

    if start == -1 or end <= start:
        return None, False

    try:
        return json.loads(text[start:end + 1]), False
    except Exception:
        return None, False


def schema_ok(obj):
    if not isinstance(obj, dict):
        return False

    required = {
        "verdict",
        "confidence",
        "requires_investigation",
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
        "reason",
        "next_action",
    }

    if not required.issubset(obj):
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

    for key in (
        "requires_investigation",
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
    ):
        if not isinstance(obj[key], bool):
            return False

    return True


def score(obj, expected):
    if obj is None:
        return 0, {}

    value = 10

    if schema_ok(obj):
        value += 15

    checks = {
        "verdict":
            obj.get("verdict") == expected["verdict"],

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


results = []

print("=" * 78, flush=True)
print("LOCAL TARGETED VERIFICATION RETEST", flush=True)
print("=" * 78, flush=True)

for test in TESTS:
    print("", flush=True)
    print("-" * 78, flush=True)
    print(
        f"{test['profile'].upper()} | {test['name']}",
        flush=True,
    )
    print(
        f"model={test['model']} "
        f"think={test['think']} "
        f"budget={test['num_predict']}",
        flush=True,
    )
    print("-" * 78, flush=True)

    for case_id in test["cases"]:
        case = CASES[case_id]

        for repeat in range(1, test["repeats"] + 1):
            print(
                f"{case_id} "
                f"run {repeat}/{test['repeats']} ... ",
                end="",
                flush=True,
            )

            started = time.perf_counter()

            try:
                response = httpx.post(
                    f"{OLLAMA}/api/generate",
                    json={
                        "model": test["model"],
                        "prompt": make_prompt(
                            test["profile"],
                            case["evidence"],
                        ),
                        "stream": False,
                        "think": test["think"],
                        "keep_alive": "10m",
                        "options": {
                            "temperature": 0,
                            "num_predict": test["num_predict"],
                            "num_ctx": 8192,
                        },
                    },
                    timeout=test["timeout"],
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

                obj, strict_json = parse_json(text)

                result_score, checks = score(
                    obj,
                    case["expected"],
                )

                row = {
                    "profile": test["profile"],
                    "candidate": test["name"],
                    "model": test["model"],
                    "think": test["think"],
                    "case": case_id,
                    "repeat": repeat,
                    "status": "ok",
                    "score": result_score,
                    "schema_ok": schema_ok(obj),
                    "strict_json": strict_json,
                    "wall_seconds": round(
                        elapsed,
                        3,
                    ),
                    "output_tokens": (
                        data.get("eval_count")
                        or 0
                    ),
                    "thinking_chars": len(
                        data.get("thinking")
                        or ""
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
                    f"tokens={row['output_tokens']} | "
                    f"done={row['done_reason']}",
                    flush=True,
                )

            except httpx.TimeoutException:
                results.append({
                    "profile": test["profile"],
                    "candidate": test["name"],
                    "model": test["model"],
                    "think": test["think"],
                    "case": case_id,
                    "repeat": repeat,
                    "status": "timeout",
                    "score": 0,
                })

                print(
                    "TIMEOUT",
                    flush=True,
                )

            except Exception as exc:
                results.append({
                    "profile": test["profile"],
                    "candidate": test["name"],
                    "model": test["model"],
                    "think": test["think"],
                    "case": case_id,
                    "repeat": repeat,
                    "status": "error",
                    "score": 0,
                    "error": repr(exc),
                })

                print(
                    f"ERROR: {exc!r}",
                    flush=True,
                )

    unload(test["model"])


print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)

candidate_names = sorted({
    row["candidate"]
    for row in results
})

summary = []

for name in candidate_names:
    rows = [
        row
        for row in results
        if row["candidate"] == name
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

    item = {
        "candidate": name,
        "runs_ok": len(ok),
        "runs_total": len(rows),
        "mean_score": round(
            statistics.mean(scores),
            2,
        ) if scores else 0,
        "min_score": min(scores) if scores else 0,
        "median_latency_seconds": round(
            statistics.median(latencies),
            2,
        ) if latencies else None,
        "schema_rate": round(
            100
            * sum(
                bool(row.get("schema_ok"))
                for row in ok
            )
            / len(rows),
            2,
        ) if rows else 0,
    }

    summary.append(item)

    print(item)


payload = {
    "generated_at": datetime.now().isoformat(
        timespec="seconds"
    ),
    "purpose": (
        "Targeted verification of questionable "
        "screening results before elimination."
    ),
    "summary": summary,
    "results": results,
}

json_path = (
    OUT_DIR
    / "local_verification_retest.json"
)

txt_path = (
    OUT_DIR
    / "local_verification_retest.txt"
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
    "LOCAL TARGETED VERIFICATION RETEST",
    "=" * 78,
    "",
    "SUMMARY",
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
    "DETAILED RESULTS",
    "=" * 78,
])

for row in results:
    lines.extend([
        "",
        (
            f"{row['candidate']} | "
            f"{row['case']} | "
            f"run {row['repeat']}"
        ),
        (
            f"status={row['status']} "
            f"score={row['score']} "
            f"time={row.get('wall_seconds')} "
            f"tokens={row.get('output_tokens')} "
            f"thinking_chars={row.get('thinking_chars')} "
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

for path in (json_path, txt_path):
    os.utime(path, (now, now))

print()
print("FILES:")
print(txt_path)
print(json_path)
