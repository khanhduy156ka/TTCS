import argparse

from soc_multi_agent.rag.embedding import (
    embed_text,
)
from soc_multi_agent.rag.repository import (
    retrieve_chunks,
    retrieve_soc_context,
)


def print_result(
    rank: int,
    result,
) -> None:
    print(
        f"\n=== Result {rank} ==="
    )

    print(
        f"Similarity : "
        f"{result.similarity:.6f}"
    )

    print(
        f"Title      : "
        f"{result.title}"
    )

    print(
        f"Section    : "
        f"{result.section or '-'}"
    )

    print(
        f"Source     : "
        f"{result.source}"
    )

    print(
        f"Chunk ID   : "
        f"{result.chunk_id}"
    )

    print(
        f"Version    : "
        f"{result.document_version}"
    )

    print(
        f"Provenance : "
        f"{result.provenance}"
    )

    print(
        "Content:"
    )

    print(
        result.content
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run semantic retrieval against "
            "the SOC knowledge base."
        )
    )

    parser.add_argument(
        "query",
        help=(
            "Natural-language retrieval query."
        ),
    )

    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help=(
            "Number of chunks for raw mode."
        ),
    )

    parser.add_argument(
        "--raw",
        action="store_true",
        help=(
            "Use unrestricted chunk-level "
            "retrieval instead of bounded "
            "SOC document-gated retrieval."
        ),
    )

    args = parser.parse_args()

    query_embedding = embed_text(
        args.query
    )

    if args.raw:
        results = retrieve_chunks(
            query_embedding,
            top_k=args.top_k,
        )
    else:
        results = retrieve_soc_context(
            query_embedding,
            playbook_chunks=2,
            procedure_chunks=1,
        )

    if not results:
        print(
            "No knowledge chunks found."
        )
        return

    for rank, result in enumerate(
        results,
        start=1,
    ):
        print_result(
            rank,
            result,
        )


if __name__ == "__main__":
    main()