import argparse
from pathlib import Path

from soc_multi_agent.rag.embedding import (
    embed_texts,
)
from soc_multi_agent.rag.loader import (
    build_embedding_text,
    chunk_markdown_document,
    load_markdown_document,
)
from soc_multi_agent.rag.repository import (
    count_knowledge,
    get_document_hash,
    replace_document,
)


def ingest_file(
    path: Path,
    knowledge_root: Path,
    force: bool = False,
) -> tuple[str, int]:
    document = load_markdown_document(
        path,
        knowledge_root,
    )

    existing_hash = get_document_hash(
        document.document_id
    )

    if (
        not force
        and existing_hash
        == document.content_hash
    ):
        return "unchanged", 0

    chunks = chunk_markdown_document(
        document
    )

    if not chunks:
        raise RuntimeError(
            f"No chunks generated for {path}"
        )

    embedding_inputs = [
        build_embedding_text(chunk)
        for chunk in chunks
    ]

    embeddings = embed_texts(
        embedding_inputs
    )

    replace_document(
        document_id=document.document_id,
        title=document.title,
        source=document.source,
        content_hash=document.content_hash,
        chunks=chunks,
        embeddings=embeddings,
    )

    return "indexed", len(chunks)


def ingest_directory(
    knowledge_root: Path,
    force: bool = False,
) -> None:
    knowledge_root = (
        knowledge_root.resolve()
    )

    if not knowledge_root.exists():
        raise FileNotFoundError(
            f"Knowledge directory does not exist: "
            f"{knowledge_root}"
        )

    files = sorted(
        knowledge_root.rglob("*.md")
    )

    if not files:
        raise RuntimeError(
            "No Markdown knowledge documents "
            f"found in {knowledge_root}"
        )

    indexed_documents = 0
    unchanged_documents = 0
    generated_chunks = 0

    for path in files:
        status, chunk_count = (
            ingest_file(
                path,
                knowledge_root,
                force=force,
            )
        )

        relative = path.relative_to(
            knowledge_root
        )

        if status == "indexed":
            indexed_documents += 1
            generated_chunks += (
                chunk_count
            )

            print(
                f"INDEXED   {relative} "
                f"({chunk_count} chunks)"
            )
        else:
            unchanged_documents += 1

            print(
                f"UNCHANGED {relative}"
            )

    total_documents, total_chunks = (
        count_knowledge()
    )

    print()
    print(
        "Ingestion complete."
    )
    print(
        "Indexed documents:",
        indexed_documents,
    )
    print(
        "Unchanged documents:",
        unchanged_documents,
    )
    print(
        "Generated chunks:",
        generated_chunks,
    )
    print(
        "Database documents:",
        total_documents,
    )
    print(
        "Database chunks:",
        total_chunks,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest Markdown SOC knowledge "
            "into PostgreSQL pgvector."
        )
    )

    parser.add_argument(
        "--knowledge-dir",
        default="knowledge",
        help=(
            "Root directory containing "
            "Markdown knowledge documents."
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Re-embed documents even when "
            "their SHA-256 content hash "
            "has not changed."
        ),
    )

    args = parser.parse_args()

    ingest_directory(
        Path(args.knowledge_dir),
        force=args.force,
    )


if __name__ == "__main__":
    main()
