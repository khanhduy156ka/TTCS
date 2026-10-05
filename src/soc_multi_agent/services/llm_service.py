from typing import Literal

from crewai import LLM

from soc_multi_agent.config import settings


LLMProfile = Literal[
    "fast",
    "enrichment",
    "reasoning",
]


# Gioi han output de model khong sinh qua dai
OLLAMA_MAX_TOKENS = {
    "fast": 768,
    "enrichment": 768,
    "reasoning": 1024,
}

# Khong de loi Ollama/OpenAI-compatible giu workflow qua lau hoac tu retry nhieu lan
OLLAMA_TIMEOUT_SECONDS = 120.0
OLLAMA_MAX_RETRIES = 0


def _resolve_provider(
    profile: LLMProfile,
) -> str:
    if profile == "fast":
        provider = (
            settings.llm_fast_provider
            or settings.llm_provider
        )

    elif profile == "enrichment":
        # Enrichment dung reasoning model da kiem chung nhung giu token budget cua FAST de khong doi dieu kien test
        provider = (
            settings.llm_reasoning_provider
            or settings.llm_provider
        )

    elif profile == "reasoning":
        provider = (
            settings.llm_reasoning_provider
            or settings.llm_provider
        )

    else:
        raise ValueError(
            f"Unsupported LLM profile: {profile}"
        )

    provider = provider.strip().lower()

    if provider not in {
        "ollama",
        "gemini",
    }:
        raise ValueError(
            f"Unsupported LLM provider: {provider}"
        )

    return provider


def _resolve_ollama_model(
    profile: LLMProfile,
) -> str:
    if profile == "fast":
        model = (
            settings.ollama_fast_model
            or settings.llm_fast_model
            or settings.ollama_model
        )

    elif profile == "enrichment":
        # Profile reasoning hien dung qwen3:4b-instruct da PASS 3/3 Enrichment, tach profile de khong anh huong Triage
        model = (
            settings.ollama_reasoning_model
            or settings.llm_reasoning_model
            or settings.ollama_model
        )

    elif profile == "reasoning":
        model = (
            settings.ollama_reasoning_model
            or settings.llm_reasoning_model
            or settings.ollama_model
        )

    else:
        raise ValueError(
            f"Unsupported LLM profile: {profile}"
        )

    if not model or not model.strip():
        raise ValueError(
            f"No Ollama model configured "
            f"for profile: {profile}"
        )

    return model.strip()


def _resolve_gemini_model(
    profile: LLMProfile,
) -> str:
    if profile == "fast":
        model = (
            settings.gemini_fast_model
            or settings.gemini_model
        )

    elif profile == "enrichment":
        model = (
            settings.gemini_reasoning_model
            or settings.gemini_model
        )

    elif profile == "reasoning":
        model = (
            settings.gemini_reasoning_model
            or settings.gemini_model
        )

    else:
        raise ValueError(
            f"Unsupported LLM profile: {profile}"
        )

    if not model or not model.strip():
        raise ValueError(
            f"No Gemini model configured "
            f"for profile: {profile}"
        )

    return model.strip()


def _resolve_model(
    profile: LLMProfile,
    provider: str,
) -> str:
    if provider == "ollama":
        return _resolve_ollama_model(
            profile
        )

    if provider == "gemini":
        return _resolve_gemini_model(
            profile
        )

    raise ValueError(
        f"No model resolution rule for "
        f"provider: {provider}"
    )


def get_llm(
    profile: LLMProfile = "reasoning",
) -> LLM:
    """
    Trả về LLM theo workload profile.

    fast:
    - Triage

    enrichment:
    - Enrichment

    reasoning:
    - Investigation
    - Remediation
    """

    provider = _resolve_provider(
        profile
    )

    model = _resolve_model(
        profile,
        provider,
    )

    if provider == "ollama":
        return LLM(
            model=f"ollama/{model}",
            base_url=settings.ollama_base_url,
            temperature=0.0,
            max_tokens=OLLAMA_MAX_TOKENS[
                profile
            ],
            timeout=OLLAMA_TIMEOUT_SECONDS,
            max_retries=OLLAMA_MAX_RETRIES,
            additional_params={
                "reasoning_effort": "none",
            },
        )

    if provider == "gemini":
        if not settings.gemini_api_key:
            raise ValueError(
                "GEMINI_API_KEY is required "
                "when using Gemini."
            )

        return LLM(
            model=f"gemini/{model}",
            api_key=settings.gemini_api_key,
        )

    raise ValueError(
        f"Unsupported LLM provider: {provider}"
    )