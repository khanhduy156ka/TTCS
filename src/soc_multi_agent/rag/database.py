from typing import Any

from soc_multi_agent.services.case_repository import (
    get_connection,
)


EMBEDDING_MODEL = "qwen3-embedding:0.6b"
EMBEDDING_DIMENSIONS = 1024


def initialize_rag_schema() -> None:
    """
    Create the PostgreSQL data layer used by the RAG subsystem.

    This function is intentionally isolated from the existing SOC
    workflow. Initializing the RAG schema must not modify existing
    cases or workflow state.
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT extversion
                FROM pg_extension
                WHERE extname = 'vector'
                """
            )

            extension_row = cursor.fetchone()

            if extension_row is None:
                raise RuntimeError(
                    "pgvector is not enabled in the current "
                    "PostgreSQL database."
                )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS rag_documents (
                    document_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_type TEXT NOT NULL
                        DEFAULT 'markdown',
                    document_version TEXT NOT NULL
                        DEFAULT '1',
                    content_hash TEXT NOT NULL,
                    metadata JSONB NOT NULL
                        DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL
                        DEFAULT NOW()
                )
                """
            )

            cursor.execute(
                f"""
                CREATE TABLE IF NOT EXISTS rag_chunks (
                    chunk_id TEXT PRIMARY KEY,

                    document_id TEXT NOT NULL
                        REFERENCES rag_documents(document_id)
                        ON DELETE CASCADE,

                    chunk_index INTEGER NOT NULL
                        CHECK (chunk_index >= 0),

                    section TEXT,

                    content TEXT NOT NULL,

                    content_hash TEXT NOT NULL,

                    embedding vector(
                        {EMBEDDING_DIMENSIONS}
                    ) NOT NULL,

                    embedding_model TEXT NOT NULL,

                    embedding_dimensions INTEGER NOT NULL
                        CHECK (
                            embedding_dimensions =
                            {EMBEDDING_DIMENSIONS}
                        ),

                    metadata JSONB NOT NULL
                        DEFAULT '{{}}'::jsonb,

                    created_at TIMESTAMPTZ NOT NULL
                        DEFAULT NOW(),

                    UNIQUE (
                        document_id,
                        chunk_index
                    )
                )
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_rag_chunks_document_id
                ON rag_chunks(document_id)
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_rag_documents_source
                ON rag_documents(source)
                """
            )

        connection.commit()


def get_rag_schema_status() -> dict[str, Any]:
    """
    Return basic validation information for the RAG database layer.
    """

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT extversion
                FROM pg_extension
                WHERE extname = 'vector'
                """
            )

            vector_row = cursor.fetchone()

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM rag_documents
                """
            )

            document_count = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM rag_chunks
                """
            )

            chunk_count = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT format_type(
                    attribute.atttypid,
                    attribute.atttypmod
                )
                FROM pg_attribute AS attribute
                JOIN pg_class AS table_info
                    ON table_info.oid =
                       attribute.attrelid
                WHERE
                    table_info.relname =
                    'rag_chunks'
                    AND attribute.attname =
                    'embedding'
                    AND attribute.attnum > 0
                    AND NOT attribute.attisdropped
                """
            )

            vector_type_row = cursor.fetchone()

    return {
        "pgvector_version": (
            vector_row[0]
            if vector_row is not None
            else None
        ),
        "embedding_model": EMBEDDING_MODEL,
        "embedding_dimensions": EMBEDDING_DIMENSIONS,
        "database_vector_type": (
            vector_type_row[0]
            if vector_type_row is not None
            else None
        ),
        "document_count": document_count,
        "chunk_count": chunk_count,
    }
