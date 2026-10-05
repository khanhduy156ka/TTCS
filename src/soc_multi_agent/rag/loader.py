import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from soc_multi_agent.rag.schemas import (
    KnowledgeChunk,
)


MAX_CHUNK_CHARS = 1800


@dataclass(frozen=True)
class MarkdownDocument:
    document_id: str
    title: str
    source: str
    content: str
    content_hash: str


def sha256_text(text: str) -> str:
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def make_document_id(
    relative_path: Path,
) -> str:
    normalized = (
        relative_path
        .with_suffix("")
        .as_posix()
        .lower()
    )

    slug = re.sub(
        r"[^a-z0-9/_-]+",
        "-",
        normalized,
    )

    slug = slug.replace("/", ":")

    return f"soc-lab:{slug.strip('-')}"


def load_markdown_document(
    path: Path,
    knowledge_root: Path,
) -> MarkdownDocument:
    # Dung utf-8-sig de doc duoc ca UTF-8 thuong va UTF-8 BOM do PowerShell co the ghi BOM
    text = path.read_text(
        encoding="utf-8-sig",
    ).strip()

    if not text:
        raise ValueError(
            f"Knowledge document is empty: {path}"
        )

    relative_path = path.relative_to(
        knowledge_root
    )

    title = path.stem.replace(
        "_",
        " ",
    ).strip()

    for line in text.splitlines():
        stripped = line.strip()

        if stripped.startswith("# "):
            title = stripped[2:].strip()
            break

    return MarkdownDocument(
        document_id=make_document_id(
            relative_path
        ),
        title=title,
        source=relative_path.as_posix(),
        content=text,
        content_hash=sha256_text(text),
    )


def _split_sections(
    text: str,
) -> list[tuple[str | None, str]]:
    sections: list[
        tuple[str | None, str]
    ] = []

    current_section: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_lines

        content = "\n".join(
            current_lines
        ).strip()

        if content:
            sections.append(
                (
                    current_section,
                    content,
                )
            )

        current_lines = []

    for line in text.splitlines():
        stripped = line.strip()

        heading = re.match(
            r"^(#{2,3})\s+(.+)$",
            stripped,
        )

        if heading:
            flush()

            current_section = (
                heading.group(2).strip()
            )

            continue

        # H1 la metadata cua tai lieu, khong dua vao noi dung section de retrieve
        if stripped.startswith("# "):
            continue

        current_lines.append(line)

    flush()

    return sections


def _split_large_text(
    text: str,
    max_chars: int,
) -> list[str]:
    if len(text) <= max_chars:
        return [text]

    paragraphs = [
        paragraph.strip()
        for paragraph
        in re.split(
            r"\n\s*\n",
            text,
        )
        if paragraph.strip()
    ]

    chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        if len(paragraph) > max_chars:
            if current:
                chunks.append(current)
                current = ""

            start = 0

            while start < len(paragraph):
                part = paragraph[
                    start:
                    start + max_chars
                ].strip()

                if part:
                    chunks.append(part)

                start += max_chars

            continue

        candidate = (
            paragraph
            if not current
            else f"{current}\n\n{paragraph}"
        )

        if len(candidate) <= max_chars:
            current = candidate
        else:
            chunks.append(current)
            current = paragraph

    if current:
        chunks.append(current)

    return chunks


def chunk_markdown_document(
    document: MarkdownDocument,
    max_chars: int = MAX_CHUNK_CHARS,
) -> list[KnowledgeChunk]:
    sections = _split_sections(
        document.content
    )

    if not sections:
        sections = [
            (
                None,
                document.content,
            )
        ]

    chunks: list[KnowledgeChunk] = []

    for section, section_content in sections:
        parts = _split_large_text(
            section_content,
            max_chars=max_chars,
        )

        for part in parts:
            chunk_index = len(chunks)

            chunk_id = (
                f"{document.document_id}:"
                f"{chunk_index:03d}"
            )

            chunks.append(
                KnowledgeChunk(
                    chunk_id=chunk_id,
                    document_id=(
                        document.document_id
                    ),
                    chunk_index=chunk_index,
                    title=document.title,
                    source=document.source,
                    section=section,
                    content=part,
                    content_hash=sha256_text(
                        part
                    ),
                )
            )

    return chunks


def build_embedding_text(
    chunk: KnowledgeChunk,
) -> str:
    parts = [
        f"Title: {chunk.title}",
    ]

    if chunk.section:
        parts.append(
            f"Section: {chunk.section}"
        )

    parts.append(chunk.content)

    return "\n\n".join(parts)