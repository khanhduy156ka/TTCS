import json
import statistics
import time
from pathlib import Path

import httpx


OLLAMA = "http://127.0.0.1:11434"
MODEL = "gpt-oss:20b"

REPEATS = 3
NUM_CTX = 8192
NUM_PREDICT = 1024
TIMEOUT = 180

OUT = Path.home() / "Downloads" / "gpt_oss_chat_final.json"


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
        "requires_investigation": {"type": "boolean"},
        "compromise_confirmed": {"type": "boolean"},
        "persistence_confirmed": {"type": "boolean"},
        "credential_theft_confirmed": {"type": "boolean"},
        "unknown_is_benign": {"type": "boolean"},
        "reason": {"type": "string"},
        "next_action": {"type": "string"},
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

    if set(obj) != set(SCHEMA["required"]):
        return False

    if obj["verdict"] not in {
        "benign",
        "suspicious",
        "likely_malicious",
    }:
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
    if not schema_ok(obj):
        return 0

    value = 25  # Parse va kiem tra schema

    if obj["verdict"] == expected["verdict"]:
        value += 25

    if (
        obj["requires_investigation"]
        == expected["requires_investigation"]
    ):
        value += 10

    for key in (
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
    ):
        if obj[key] == expected[key]:
            value += 10

    return value


results = []

print("=" * 78, flush=True)
print("GPT-OSS 20B LOW - /API/CHAT FINAL RETEST", flush=True)
print("=" * 78, flush=True)

for ci, case in enumerate(CASES, 1):
    for repeat in range(1, REPEATS + 1):

        print(
            f"[{ci}/5] {case['id']} "
            f"run {repeat}/3 ... ",
            end="",
            flush=True,
        )

        started = time.perf_counter()

        try:
            r = httpx.post(
                f"{OLLAMA}/api/chat",
                json={
                    "model": MODEL,
                    "messages": [
                        {
                            "role": "user",
                            "content": make_prompt(
                                case["evidence"]
                            ),
                        }
                    ],
                    "stream": False,
                    "think": "low",
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

            r.raise_for_status()
            data = r.json()

            elapsed = time.perf_counter() - started

            message = data.get("message") or {}

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

            s = score(
                obj,
                case["expected"],
            )

            row = {
                "case": case["id"],
                "repeat": repeat,
                "score": s,
                "schema_ok": schema_ok(obj),
                "wall_seconds": round(elapsed, 3),
                "prompt_tokens":
                    data.get("prompt_eval_count"),
                "output_tokens":
                    data.get("eval_count"),
                "thinking_chars": len(thinking),
                "done_reason":
                    data.get("done_reason"),
                "response": content,
            }

            results.append(row)

            print(
                f"{s}/100 | "
                f"{elapsed:.2f}s | "
                f"schema={row['schema_ok']} | "
                f"thinking={len(thinking)}",
                flush=True,
            )

        except Exception as exc:
            results.append({
                "case": case["id"],
                "repeat": repeat,
                "score": 0,
                "schema_ok": False,
                "error": repr(exc),
            })

            print(
                f"ERROR: {exc!r}",
                flush=True,
            )


scores = [x["score"] for x in results]
latencies = [
    x["wall_seconds"]
    for x in results
    if "wall_seconds" in x
]

summary = {
    "model": MODEL,
    "endpoint": "/api/chat",
    "think": "low",
    "runs": len(results),
    "mean_score": round(
        statistics.mean(scores),
        2,
    ),
    "min_score": min(scores),
    "schema_rate": round(
        100
        * sum(
            bool(x.get("schema_ok"))
            for x in results
        )
        / len(results),
        2,
    ),
    "median_latency_seconds": round(
        statistics.median(latencies),
        2,
    ),
}


print()
print("=" * 78)
print("SUMMARY")
print("=" * 78)
print(json.dumps(summary, indent=2))


OUT.write_text(
    json.dumps(
        {
            "summary": summary,
            "results": results,
        },
        indent=2,
        ensure_ascii=False,
    ),
    encoding="utf-8",
)

print()
print(f"OUTPUT: {OUT}")


# Giai phong model
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
