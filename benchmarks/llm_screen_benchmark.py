import argparse
import csv
import json
import statistics
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from soc_multi_agent.config import settings


OLLAMA = "http://127.0.0.1:11434"
DOWNLOADS = Path.home() / "Downloads"

FAST_TIMEOUT = 60.0
REASONING_TIMEOUT = 180.0

FAST_NUM_PREDICT = 220
REASONING_NUM_PREDICT = 512


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


FAST_CANDIDATES = [
    {
        "name": "qwen3_4b_instruct",
        "provider": "ollama",
        "model": "qwen3:4b-instruct",
        "think": False,
    },
    {
        "name": "qwen3_5_4b_no_think",
        "provider": "ollama",
        "model": "qwen3.5:4b",
        "think": False,
    },
    {
        "name": "qwen3_8b_no_think",
        "provider": "ollama",
        "model": "qwen3:8b",
        "think": False,
    },
    {
        "name": "qwen3_5_9b_no_think",
        "provider": "ollama",
        "model": "qwen3.5:9b",
        "think": False,
    },
    {
        "name": "gemini_3_8_flash_low",
        "provider": "gemini",
        "model": "gemini-3.8-flash",
        "think": "low",
    },
]


REASONING_CANDIDATES = [
    # Cau hinh baseline hien tai
    {
        "name": "qwen3_4b_instruct_baseline",
        "provider": "ollama",
        "model": "qwen3:4b-instruct",
        "think": False,
    },
    {
        "name": "qwen3_5_4b_think",
        "provider": "ollama",
        "model": "qwen3.5:4b",
        "think": True,
    },
    {
        "name": "qwen3_8b_think",
        "provider": "ollama",
        "model": "qwen3:8b",
        "think": True,
    },
    {
        "name": "qwen3_5_9b_think",
        "provider": "ollama",
        "model": "qwen3.5:9b",
        "think": True,
    },
    {
        "name": "gpt_oss_20b_low",
        "provider": "ollama",
        "model": "gpt-oss:20b",
        "think": "low",
    },
    {
        "name": "gpt_oss_20b_medium",
        "provider": "ollama",
        "model": "gpt-oss:20b",
        "think": "medium",
    },
    {
        "name": "gemini_3_8_flash_medium",
        "provider": "gemini",
        "model": "gemini-3.8-flash",
        "think": "medium",
    },
]


REQUIRED_FIELDS = {
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


def make_prompt(
    profile: str,
    evidence: str,
) -> str:
    if profile == "fast":
        role_instruction = """
Make a fast SOC triage decision.
Do not invent evidence.
Do not treat missing or unknown evidence as benign evidence.
Do not claim compromise unless it is explicitly supported.
""".strip()
    else:
        role_instruction = """
Perform careful SOC investigation reasoning.
Distinguish observed evidence from inference and unknown facts.
Do not invent evidence.
Do not treat missing or unknown evidence as benign evidence.
Do not claim compromise, persistence, or credential theft unless
the supplied evidence explicitly supports that conclusion.
""".strip()

    return f"""
You are a security operations center analyst.

{role_instruction}

Evidence:
{evidence}

Return one JSON object only.
Do not use Markdown or code fences.

Required schema:
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


def parse_json_response(
    text: str,
) -> tuple[dict[str, Any] | None, bool]:
    stripped = text.strip()

    try:
        obj = json.loads(stripped)
        return obj, True
    except Exception:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")

    if start == -1 or end == -1 or end <= start:
        return None, False

    try:
        return json.loads(
            stripped[start : end + 1]
        ), False
    except Exception:
        return None, False


def schema_ok(
    obj: dict[str, Any] | None,
) -> bool:
    if not isinstance(obj, dict):
        return False

    if not REQUIRED_FIELDS.issubset(
        obj.keys()
    ):
        return False

    if obj.get("verdict") not in {
        "benign",
        "suspicious",
        "likely_malicious",
    }:
        return False

    confidence = obj.get("confidence")

    if not isinstance(
        confidence,
        (int, float),
    ):
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
        if not isinstance(
            obj.get(key),
            bool,
        ):
            return False

    if not isinstance(
        obj.get("reason"),
        str,
    ):
        return False

    if not isinstance(
        obj.get("next_action"),
        str,
    ):
        return False

    return True


def score_result(
    obj: dict[str, Any] | None,
    expected: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    if obj is None:
        return 0, {
            "parse": False,
            "schema": False,
        }

    score = 10

    valid_schema = schema_ok(obj)

    if valid_schema:
        score += 15

    checks = {
        "verdict": (
            obj.get("verdict")
            == expected["verdict"]
        ),
        "requires_investigation": (
            obj.get("requires_investigation")
            == expected["requires_investigation"]
        ),
        "compromise_confirmed": (
            obj.get("compromise_confirmed")
            == expected["compromise_confirmed"]
        ),
        "persistence_confirmed": (
            obj.get("persistence_confirmed")
            == expected["persistence_confirmed"]
        ),
        "credential_theft_confirmed": (
            obj.get("credential_theft_confirmed")
            == expected[
                "credential_theft_confirmed"
            ]
        ),
        "unknown_is_benign": (
            obj.get("unknown_is_benign")
            == expected["unknown_is_benign"]
        ),
    }

    if checks["verdict"]:
        score += 25

    if checks["requires_investigation"]:
        score += 10

    for key in (
        "compromise_confirmed",
        "persistence_confirmed",
        "credential_theft_confirmed",
        "unknown_is_benign",
    ):
        if checks[key]:
            score += 10

    return score, {
        "parse": True,
        "schema": valid_schema,
        **checks,
    }


def ollama_show(
    client: httpx.Client,
    model: str,
) -> dict[str, Any]:
    response = client.post(
        f"{OLLAMA}/api/show",
        json={"model": model},
    )
    response.raise_for_status()
    return response.json()


def load_ollama_model(
    client: httpx.Client,
    model: str,
) -> float:
    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/generate",
        json={
            "model": model,
            "prompt": "",
            "stream": False,
            "keep_alive": "10m",
        },
        timeout=180.0,
    )

    response.raise_for_status()

    return (
        time.perf_counter()
        - started
    )


def unload_ollama_model(
    model: str,
) -> None:
    try:
        with httpx.Client(
            timeout=30.0,
        ) as client:
            client.post(
                f"{OLLAMA}/api/generate",
                json={
                    "model": model,
                    "prompt": "",
                    "stream": False,
                    "keep_alive": 0,
                },
            )
    except Exception:
        pass


def run_ollama(
    client: httpx.Client,
    candidate: dict[str, Any],
    prompt: str,
    profile: str,
) -> dict[str, Any]:
    num_predict = (
        FAST_NUM_PREDICT
        if profile == "fast"
        else REASONING_NUM_PREDICT
    )

    timeout = (
        FAST_TIMEOUT
        if profile == "fast"
        else REASONING_TIMEOUT
    )

    payload = {
        "model": candidate["model"],
        "prompt": prompt,
        "stream": False,
        "think": candidate["think"],
        "keep_alive": "10m",
        "options": {
            "temperature": 0,
            "num_predict": num_predict,
        },
    }

    started = time.perf_counter()

    response = client.post(
        f"{OLLAMA}/api/generate",
        json=payload,
        timeout=timeout,
    )

    response.raise_for_status()

    wall_seconds = (
        time.perf_counter()
        - started
    )

    data = response.json()

    eval_count = (
        data.get("eval_count")
        or 0
    )

    eval_ns = (
        data.get("eval_duration")
        or 0
    )

    generation_tps = None

    if eval_count and eval_ns:
        generation_tps = (
            eval_count
            / (eval_ns / 1e9)
        )

    return {
        "text": (
            data.get("response")
            or ""
        ).strip(),
        "thinking": (
            data.get("thinking")
            or ""
        ),
        "wall_seconds": wall_seconds,
        "load_seconds": (
            (data.get("load_duration") or 0)
            / 1e9
        ),
        "prompt_tokens": (
            data.get("prompt_eval_count")
            or 0
        ),
        "output_tokens": eval_count,
        "generation_tps": generation_tps,
        "done_reason": data.get(
            "done_reason"
        ),
    }


def run_gemini(
    candidate: dict[str, Any],
    prompt: str,
    profile: str,
) -> dict[str, Any]:
    if not settings.gemini_api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=settings.gemini_api_key
    )

    level_map = {
        "low": types.ThinkingLevel.LOW,
        "medium": types.ThinkingLevel.MEDIUM,
        "high": types.ThinkingLevel.HIGH,
    }

    max_tokens = (
        FAST_NUM_PREDICT
        if profile == "fast"
        else REASONING_NUM_PREDICT
    )

    config = types.GenerateContentConfig(
        temperature=0,
        max_output_tokens=max_tokens,
        thinking_config=types.ThinkingConfig(
            thinking_level=level_map[
                candidate["think"]
            ],
        ),
    )

    started = time.perf_counter()

    response = client.models.generate_content(
        model=candidate["model"],
        contents=prompt,
        config=config,
    )

    wall_seconds = (
        time.perf_counter()
        - started
    )

    usage = getattr(
        response,
        "usage_metadata",
        None,
    )

    return {
        "text": (
            response.text
            if response.text
            else ""
        ).strip(),
        "thinking": "",
        "wall_seconds": wall_seconds,
        "load_seconds": 0.0,
        "prompt_tokens": getattr(
            usage,
            "prompt_token_count",
            None,
        ),
        "output_tokens": getattr(
            usage,
            "candidates_token_count",
            None,
        ),
        "thinking_tokens": getattr(
            usage,
            "thoughts_token_count",
            None,
        ),
        "generation_tps": None,
        "done_reason": None,
    }


def run_candidate(
    profile: str,
    candidate: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []

    print()
    print("=" * 72)
    print(
        f"{profile.upper()} | "
        f"{candidate['name']}"
    )
    print("=" * 72)

    if candidate["provider"] == "ollama":
        with httpx.Client() as client:
            show = ollama_show(
                client,
                candidate["model"],
            )

            thinking_meta = show.get(
                "thinking"
            )

            print(
                "Thinking support:",
                thinking_meta,
            )
            print(
                "Requested thinking:",
                candidate["think"],
            )

            load_seconds = load_ollama_model(
                client,
                candidate["model"],
            )

            print(
                f"Cold load: "
                f"{load_seconds:.2f}s"
            )

            for case in CASES:
                prompt = make_prompt(
                    profile,
                    case["evidence"],
                )

                print(
                    f"  {case['id']}: ",
                    end="",
                    flush=True,
                )

                try:
                    result = run_ollama(
                        client,
                        candidate,
                        prompt,
                        profile,
                    )

                except (
                    httpx.TimeoutException,
                    KeyboardInterrupt,
                ):
                    print("TIMEOUT / INTERRUPTED")

                    rows.append({
                        "profile": profile,
                        "candidate": candidate["name"],
                        "provider": "ollama",
                        "model": candidate["model"],
                        "think": candidate["think"],
                        "case": case["id"],
                        "status": "timeout",
                        "score": 0,
                        "cold_load_seconds": load_seconds,
                    })

                    # Mot lan timeout la du de loai cau hinh nay
                    break

                except Exception as exc:
                    print(
                        f"ERROR: {exc!r}"
                    )

                    rows.append({
                        "profile": profile,
                        "candidate": candidate["name"],
                        "provider": "ollama",
                        "model": candidate["model"],
                        "think": candidate["think"],
                        "case": case["id"],
                        "status": "error",
                        "score": 0,
                        "error": repr(exc),
                        "cold_load_seconds": load_seconds,
                    })
                    break

                obj, strict_json = (
                    parse_json_response(
                        result["text"]
                    )
                )

                score, checks = (
                    score_result(
                        obj,
                        case["expected"],
                    )
                )

                print(
                    f"{score}/100 | "
                    f"{result['wall_seconds']:.2f}s"
                )

                rows.append({
                    "profile": profile,
                    "candidate": candidate["name"],
                    "provider": "ollama",
                    "model": candidate["model"],
                    "think": candidate["think"],
                    "case": case["id"],
                    "status": "ok",
                    "score": score,
                    "strict_json": strict_json,
                    "checks": checks,
                    "cold_load_seconds": load_seconds,
                    **result,
                })

        unload_ollama_model(
            candidate["model"]
        )

    else:
        print(
            "Gemini thinking level:",
            candidate["think"],
        )

        for case in CASES:
            prompt = make_prompt(
                profile,
                case["evidence"],
            )

            print(
                f"  {case['id']}: ",
                end="",
                flush=True,
            )

            try:
                result = run_gemini(
                    candidate,
                    prompt,
                    profile,
                )

            except KeyboardInterrupt:
                print("INTERRUPTED")
                break

            except Exception as exc:
                print(
                    f"ERROR: {exc!r}"
                )

                rows.append({
                    "profile": profile,
                    "candidate": candidate["name"],
                    "provider": "gemini",
                    "model": candidate["model"],
                    "think": candidate["think"],
                    "case": case["id"],
                    "status": "error",
                    "score": 0,
                    "error": repr(exc),
                })
                break

            obj, strict_json = (
                parse_json_response(
                    result["text"]
                )
            )

            score, checks = (
                score_result(
                    obj,
                    case["expected"],
                )
            )

            print(
                f"{score}/100 | "
                f"{result['wall_seconds']:.2f}s"
            )

            rows.append({
                "profile": profile,
                "candidate": candidate["name"],
                "provider": "gemini",
                "model": candidate["model"],
                "think": candidate["think"],
                "case": case["id"],
                "status": "ok",
                "score": score,
                "strict_json": strict_json,
                "checks": checks,
                "cold_load_seconds": 0.0,
                **result,
            })

    return rows


def summarize(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    names = sorted({
        row["candidate"]
        for row in rows
    })

    summary = []

    for name in names:
        candidate_rows = [
            row
            for row in rows
            if row["candidate"] == name
        ]

        ok_rows = [
            row
            for row in candidate_rows
            if row.get("status") == "ok"
        ]

        scores = [
            row["score"]
            for row in ok_rows
        ]

        latencies = [
            row["wall_seconds"]
            for row in ok_rows
        ]

        summary.append({
            "candidate": name,
            "cases_completed": len(
                ok_rows
            ),
            "cases_total": len(CASES),
            "mean_score": (
                round(
                    statistics.mean(scores),
                    2,
                )
                if scores
                else 0.0
            ),
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
            "max_latency_seconds": (
                round(
                    max(latencies),
                    2,
                )
                if latencies
                else None
            ),
            "screen_pass": (
                len(ok_rows) == len(CASES)
                and min(scores, default=0) >= 75
                and statistics.mean(
                    scores
                ) >= 85
            ),
        })

    return summary


def save_outputs(
    profile: str,
    rows: list[dict[str, Any]],
    summary: list[dict[str, Any]],
) -> None:
    json_path = (
        DOWNLOADS
        / f"llm_screen_{profile}.json"
    )

    csv_path = (
        DOWNLOADS
        / f"llm_screen_{profile}.csv"
    )

    txt_path = (
        DOWNLOADS
        / f"llm_screen_{profile}.txt"
    )

    payload = {
        "generated_at": (
            datetime.now().isoformat(
                timespec="seconds"
            )
        ),
        "profile": profile,
        "method": {
            "stage": "screening",
            "cases": len(CASES),
            "temperature": 0,
            "fast_timeout_seconds": FAST_TIMEOUT,
            "reasoning_timeout_seconds": (
                REASONING_TIMEOUT
            ),
            "fast_num_predict": FAST_NUM_PREDICT,
            "reasoning_num_predict": (
                REASONING_NUM_PREDICT
            ),
        },
        "summary": summary,
        "results": rows,
    }

    json_path.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    csv_fields = [
        "profile",
        "candidate",
        "provider",
        "model",
        "think",
        "case",
        "status",
        "score",
        "strict_json",
        "wall_seconds",
        "cold_load_seconds",
        "prompt_tokens",
        "output_tokens",
        "thinking_tokens",
        "generation_tps",
        "done_reason",
        "text",
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

        for row in rows:
            writer.writerow(row)

    text_lines = [
        "=" * 72,
        f"SOC LLM SCREENING BENCHMARK - {profile.upper()}",
        "=" * 72,
        "",
        "SUMMARY",
        "",
    ]

    for item in summary:
        text_lines.append(
            (
                f"{item['candidate']:<32} "
                f"score={item['mean_score']:>6} "
                f"min={item['min_score']:>3} "
                f"median={str(item['median_latency_seconds']):>7}s "
                f"max={str(item['max_latency_seconds']):>7}s "
                f"cases={item['cases_completed']}/{item['cases_total']} "
                f"pass={item['screen_pass']}"
            )
        )

    text_lines.extend([
        "",
        "=" * 72,
        "DETAILED RESPONSES",
        "=" * 72,
    ])

    for row in rows:
        text_lines.extend([
            "",
            (
                f"[{row['candidate']}] "
                f"{row['case']}"
            ),
            (
                f"status={row.get('status')} "
                f"score={row.get('score')} "
                f"latency={row.get('wall_seconds')} "
                f"think={row.get('think')}"
            ),
            "",
            row.get(
                "text",
                row.get(
                    "error",
                    "<no response>",
                ),
            ),
        ])

    txt_path.write_text(
        "\n".join(text_lines),
        encoding="utf-8",
    )

    now = time.time()

    for path in (
        json_path,
        csv_path,
        txt_path,
    ):
        Path(path).touch()
        import os
        os.utime(
            path,
            (now, now),
        )

    print()
    print("=" * 72)
    print("FILES")
    print("=" * 72)
    print(txt_path)
    print(csv_path)
    print(json_path)


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        choices=[
            "fast",
            "reasoning",
        ],
        required=True,
    )

    args = parser.parse_args()

    profile = args.profile

    candidates = (
        FAST_CANDIDATES
        if profile == "fast"
        else REASONING_CANDIDATES
    )

    all_rows = []

    print(
        "VMware/FastAPI/watcher should remain OFF."
    )
    print(
        f"Starting {profile.upper()} screening."
    )

    for candidate in candidates:
        rows = run_candidate(
            profile,
            candidate,
        )

        all_rows.extend(rows)

    result_summary = summarize(
        all_rows
    )

    print()
    print("=" * 72)
    print("SCREENING SUMMARY")
    print("=" * 72)

    for item in result_summary:
        print(item)

    save_outputs(
        profile,
        all_rows,
        result_summary,
    )


if __name__ == "__main__":
    main()
