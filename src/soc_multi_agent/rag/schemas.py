from pydantic import BaseModel, Field


class KnowledgeChunk(BaseModel):
    chunk_id: str
    document_id: str
    chunk_index: int = Field(ge=0)
    title: str
    source: str
    section: str | None = None
    content: str
    content_hash: str


class RetrievedChunk(BaseModel):
    chunk_id: str
    document_id: str
    title: str
    source: str
    section: str | None = None
    content: str
    similarity: float
    document_version: str

    @property
    def provenance(self) -> str:
        location = self.source

        if self.section:
            location = f"{location}#{self.section}"

        return f"{location} [{self.chunk_id}]"
