"""Microsoft Windows Security documentation normalization."""

from investigation_agent.ingestion.html import extract_article
from investigation_agent.ingestion.schemas import KnowledgeDocument, RawArtifact, SourceEntry
from investigation_agent.ingestion.utils import normalize_text, sha256_text


def normalize_microsoft_document(artifact: RawArtifact, entry: SourceEntry) -> KnowledgeDocument:
    """Normalize one curated Windows Security event page."""

    title, content, modified = extract_article(artifact.path.read_text(encoding="utf-8"))
    content = normalize_text(content)
    return KnowledgeDocument(
        document_id=entry.id,
        source="microsoft",
        source_type=entry.source_type,
        title=title,
        url=artifact.url,
        content=content,
        content_hash=sha256_text(content),
        version=entry.version,
        effective_or_modified_date=modified or artifact.last_modified,
        downloaded_at=artifact.downloaded_at,
        raw_path=artifact.path.as_posix(),
        event_id=entry.event_id,
        metadata={"raw_content_hash": artifact.content_hash},
    )
