from collections.abc import Sequence

from psycopg.types.json import Jsonb

from soc_multi_agent.rag.database import (
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
)
from soc_multi_agent.rag.schemas import (
    KnowledgeChunk,
    RetrievedChunk,
)
from soc_multi_agent.services.case_repository import (
    get_connection,
)


# Nguong collection gating nay duoc tinh chinh theo knowledge base SOC Lab, khong phai nguong similarity dung chung
# Can danh gia lai neu doi embedding model hoac knowledge corpus
PLAYBOOK_MIN_SIMILARITY = 0.65
PROCEDURE_MIN_SIMILARITY = 0.60


def vector_to_pg(
    vector: Sequence[float],
) -> str:
    if len(vector) != EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"Expected vector dimension "
            f"{EMBEDDING_DIMENSIONS}, "
            f"received {len(vector)}."
        )

    return (
        "["
        + ",".join(
            format(
                float(value),
                ".10g",
            )
            for value in vector
        )
        + "]"
    )


def get_document_hash(
    document_id: str,
) -> str | None:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT content_hash
                FROM rag_documents
                WHERE document_id = %s
                """,
                (document_id,),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return row[0]


def replace_document(
    *,
    document_id: str,
    title: str,
    source: str,
    content_hash: str,
    chunks: Sequence[KnowledgeChunk],
    embeddings: Sequence[
        Sequence[float]
    ],
) -> None:
    if len(chunks) != len(embeddings):
        raise ValueError(
            "Chunk and embedding counts differ."
        )

    document_version = content_hash[:12]

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO rag_documents (
                    document_id,
                    title,
                    source,
                    source_type,
                    document_version,
                    content_hash,
                    metadata,
                    created_at,
                    updated_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'markdown',
                    %s,
                    %s,
                    %s,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (document_id)
                DO UPDATE SET
                    title = EXCLUDED.title,
                    source = EXCLUDED.source,
                    source_type =
                        EXCLUDED.source_type,
                    document_version =
                        EXCLUDED.document_version,
                    content_hash =
                        EXCLUDED.content_hash,
                    metadata =
                        EXCLUDED.metadata,
                    updated_at = NOW()
                """,
                (
                    document_id,
                    title,
                    source,
                    document_version,
                    content_hash,
                    Jsonb(
                        {
                            "knowledge_base":
                                "soc_lab",
                            "managed_by":
                                "rag_ingestion",
                        }
                    ),
                ),
            )

            cursor.execute(
                """
                DELETE FROM rag_chunks
                WHERE document_id = %s
                """,
                (document_id,),
            )

            for chunk, embedding in zip(
                chunks,
                embeddings,
                strict=True,
            ):
                cursor.execute(
                    """
                    INSERT INTO rag_chunks (
                        chunk_id,
                        document_id,
                        chunk_index,
                        section,
                        content,
                        content_hash,
                        embedding,
                        embedding_model,
                        embedding_dimensions,
                        metadata
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s::vector,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        chunk.chunk_id,
                        chunk.document_id,
                        chunk.chunk_index,
                        chunk.section,
                        chunk.content,
                        chunk.content_hash,
                        vector_to_pg(
                            embedding
                        ),
                        EMBEDDING_MODEL,
                        EMBEDDING_DIMENSIONS,
                        Jsonb(
                            {
                                "title":
                                    chunk.title,
                                "source":
                                    chunk.source,
                            }
                        ),
                    ),
                )

        connection.commit()


def _rows_to_retrieved_chunks(
    rows: Sequence[Sequence],
) -> list[RetrievedChunk]:
    return [
        RetrievedChunk(
            chunk_id=row[0],
            document_id=row[1],
            title=row[2],
            source=row[3],
            section=row[4],
            content=row[5],
            similarity=float(row[6]),
            document_version=row[7],
        )
        for row in rows
    ]


def retrieve_chunks(
    query_embedding: Sequence[float],
    top_k: int = 5,
    source_prefix: str | None = None,
) -> list[RetrievedChunk]:
    """
    Direct chunk-level vector retrieval.

    This mode is retained for diagnostics. Agent-facing retrieval
    should normally use retrieve_soc_context(), which applies
    document and collection gating.
    """

    if top_k < 1:
        raise ValueError(
            "top_k must be at least 1."
        )

    vector = vector_to_pg(
        query_embedding
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            if source_prefix is None:
                cursor.execute(
                    """
                    WITH query_vector AS (
                        SELECT
                            %s::vector AS embedding
                    )
                    SELECT
                        chunk.chunk_id,
                        chunk.document_id,
                        document.title,
                        document.source,
                        chunk.section,
                        chunk.content,
                        (
                            1 - (
                                chunk.embedding
                                <=>
                                query_vector.embedding
                            )
                        )::double precision
                            AS similarity,
                        document.document_version
                    FROM rag_chunks AS chunk
                    JOIN rag_documents AS document
                        ON document.document_id =
                           chunk.document_id
                    CROSS JOIN query_vector
                    ORDER BY
                        chunk.embedding
                        <=>
                        query_vector.embedding
                    LIMIT %s
                    """,
                    (
                        vector,
                        top_k,
                    ),
                )
            else:
                cursor.execute(
                    """
                    WITH query_vector AS (
                        SELECT
                            %s::vector AS embedding
                    )
                    SELECT
                        chunk.chunk_id,
                        chunk.document_id,
                        document.title,
                        document.source,
                        chunk.section,
                        chunk.content,
                        (
                            1 - (
                                chunk.embedding
                                <=>
                                query_vector.embedding
                            )
                        )::double precision
                            AS similarity,
                        document.document_version
                    FROM rag_chunks AS chunk
                    JOIN rag_documents AS document
                        ON document.document_id =
                           chunk.document_id
                    CROSS JOIN query_vector
                    WHERE
                        document.source LIKE %s
                    ORDER BY
                        chunk.embedding
                        <=>
                        query_vector.embedding
                    LIMIT %s
                    """,
                    (
                        vector,
                        f"{source_prefix}%",
                        top_k,
                    ),
                )

            rows = cursor.fetchall()

    return _rows_to_retrieved_chunks(
        rows
    )


def retrieve_best_document_chunks(
    query_embedding: Sequence[float],
    *,
    source_prefix: str,
    top_k: int = 2,
    min_document_similarity: float = 0.0,
) -> list[RetrievedChunk]:
    """
    Perform two-stage document-gated retrieval.

    Stage 1 selects the strongest document in one knowledge
    collection using its best operational section.

    Stage 2 retrieves the best operational chunks only from that
    selected document.

    Sectionless document preambles are deliberately excluded from
    agent-facing retrieval because they mainly contain titles,
    disclaimers, or other metadata rather than actionable guidance.
    """

    if top_k < 1:
        raise ValueError(
            "top_k must be at least 1."
        )

    if not source_prefix:
        raise ValueError(
            "source_prefix must not be empty."
        )

    vector = vector_to_pg(
        query_embedding
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                WITH query_vector AS (
                    SELECT
                        %s::vector AS embedding
                ),
                document_scores AS (
                    SELECT
                        document.document_id,
                        MAX(
                            1 - (
                                chunk.embedding
                                <=>
                                query_vector.embedding
                            )
                        )::double precision
                            AS best_similarity
                    FROM rag_chunks AS chunk
                    JOIN rag_documents AS document
                        ON document.document_id =
                           chunk.document_id
                    CROSS JOIN query_vector
                    WHERE
                        document.source LIKE %s
                        AND chunk.section IS NOT NULL
                    GROUP BY
                        document.document_id
                )
                SELECT
                    document_id,
                    best_similarity
                FROM document_scores
                ORDER BY
                    best_similarity DESC
                LIMIT 1
                """,
                (
                    vector,
                    f"{source_prefix}%",
                ),
            )

            document_row = cursor.fetchone()

            if document_row is None:
                return []

            best_document_id = document_row[0]
            best_similarity = float(
                document_row[1]
            )

            if (
                best_similarity
                < min_document_similarity
            ):
                return []

            cursor.execute(
                """
                WITH query_vector AS (
                    SELECT
                        %s::vector AS embedding
                )
                SELECT
                    chunk.chunk_id,
                    chunk.document_id,
                    document.title,
                    document.source,
                    chunk.section,
                    chunk.content,
                    (
                        1 - (
                            chunk.embedding
                            <=>
                            query_vector.embedding
                        )
                    )::double precision
                        AS similarity,
                    document.document_version
                FROM rag_chunks AS chunk
                JOIN rag_documents AS document
                    ON document.document_id =
                       chunk.document_id
                CROSS JOIN query_vector
                WHERE
                    chunk.document_id = %s
                    AND chunk.section IS NOT NULL
                ORDER BY
                    chunk.embedding
                    <=>
                    query_vector.embedding
                LIMIT %s
                """,
                (
                    vector,
                    best_document_id,
                    top_k,
                ),
            )

            rows = cursor.fetchall()

    return _rows_to_retrieved_chunks(
        rows
    )


def retrieve_soc_context(
    query_embedding: Sequence[float],
    *,
    playbook_chunks: int = 2,
    procedure_chunks: int = 1,
) -> list[RetrievedChunk]:
    """
    Retrieve bounded, relevance-gated SOC context.

    Playbooks and procedures are evaluated independently.

    A collection is omitted when its strongest matching document
    does not meet the configured similarity threshold. This is
    preferable to injecting weak context merely to satisfy a fixed
    number of retrieved chunks.

    Final results are globally sorted by similarity.
    """

    results: list[RetrievedChunk] = []

    if playbook_chunks > 0:
        results.extend(
            retrieve_best_document_chunks(
                query_embedding,
                source_prefix="playbooks/",
                top_k=playbook_chunks,
                min_document_similarity=(
                    PLAYBOOK_MIN_SIMILARITY
                ),
            )
        )

    if procedure_chunks > 0:
        results.extend(
            retrieve_best_document_chunks(
                query_embedding,
                source_prefix="procedures/",
                top_k=procedure_chunks,
                min_document_similarity=(
                    PROCEDURE_MIN_SIMILARITY
                ),
            )
        )

    results.sort(
        key=lambda result: result.similarity,
        reverse=True,
    )

    return results


def count_knowledge() -> tuple[int, int]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM rag_documents
                """
            )

            documents = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM rag_chunks
                """
            )

            chunks = cursor.fetchone()[0]

    return documents, chunks