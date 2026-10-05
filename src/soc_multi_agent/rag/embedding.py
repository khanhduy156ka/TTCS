from collections.abc import Sequence

import httpx

from soc_multi_agent.rag.database import (
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
)


OLLAMA_BASE_URL = "http://localhost:11434"
EMBED_TIMEOUT_SECONDS = 120.0


def embed_texts(
    texts: Sequence[str],
) -> list[list[float]]:
    """
    Generate embeddings through the local Ollama API.

    RAG v1 deliberately uses the same fixed embedding model and
    dimensionality as the PostgreSQL pgvector schema.
    """

    normalized = [
        text.strip()
        for text in texts
    ]

    if not normalized:
        return []

    if any(not text for text in normalized):
        raise ValueError(
            "Embedding input must not contain empty text."
        )

    payload = {
        "model": EMBEDDING_MODEL,
        "input": normalized,
    }

    try:
        with httpx.Client(
            base_url=OLLAMA_BASE_URL,
            timeout=EMBED_TIMEOUT_SECONDS,
        ) as client:
            response = client.post(
                "/api/embed",
                json=payload,
            )

            response.raise_for_status()

    except httpx.HTTPError as exc:
        raise RuntimeError(
            "Failed to obtain embeddings from Ollama."
        ) from exc

    data = response.json()

    embeddings = data.get("embeddings")

    if not isinstance(embeddings, list):
        raise RuntimeError(
            "Ollama embedding response does not contain "
            "a valid embeddings list."
        )

    if len(embeddings) != len(normalized):
        raise RuntimeError(
            "Ollama returned an unexpected number "
            "of embeddings."
        )

    validated: list[list[float]] = []

    for index, embedding in enumerate(embeddings):
        if not isinstance(embedding, list):
            raise RuntimeError(
                f"Embedding {index} is not a vector."
            )

        if len(embedding) != EMBEDDING_DIMENSIONS:
            raise RuntimeError(
                f"Embedding {index} has dimension "
                f"{len(embedding)}, expected "
                f"{EMBEDDING_DIMENSIONS}."
            )

        validated.append(
            [float(value) for value in embedding]
        )

    return validated


def embed_text(text: str) -> list[float]:
    """
    Generate one embedding vector.
    """

    embeddings = embed_texts([text])

    return embeddings[0]
