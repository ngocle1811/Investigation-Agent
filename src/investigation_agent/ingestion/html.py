"""Shared structure-aware extraction for curated Microsoft HTML pages."""

from dataclasses import dataclass

from bs4 import BeautifulSoup, Tag

from investigation_agent.ingestion.utils import normalize_text


@dataclass(frozen=True)
class ArticleSection:
    """One logical article section discovered from headings or semantic labels."""

    heading: str
    level: int
    content: str


@dataclass(frozen=True)
class ExtractedArticle:
    """A normalized article with its original logical section boundaries."""

    title: str
    content: str
    modified: str | None
    sections: tuple[ArticleSection, ...]


_BLOCK_TAGS = {"p", "pre", "ul", "ol", "table", "dl"}
_IGNORED_SECTIONS = {"in this article", "additional resources", "feedback"}


def _block_text(node: Tag) -> str:
    """Render a complete table/list/text block without cutting its internal structure."""

    if node.name in {"ul", "ol"}:
        items = [normalize_text(item.get_text(" ", strip=True)) for item in node.find_all("li")]
        return "\n".join(f"- {item}" for item in items if item)
    if node.name == "table":
        rows = []
        for row in node.find_all("tr"):
            cells = [
                normalize_text(cell.get_text(" ", strip=True))
                for cell in row.find_all(["th", "td"])
            ]
            if cells:
                rows.append(" | ".join(cells))
        return "\n".join(rows)
    return normalize_text(node.get_text("\n" if node.name == "pre" else " ", strip=True))


def _semantic_heading(node: Tag) -> str | None:
    """Promote Microsoft's bold, colon-terminated labels into section headings."""

    if node.name != "p":
        return None
    first = node.find(["strong", "b"])
    if first is None:
        return None
    label = normalize_text(first.get_text(" ", strip=True))
    if not label.endswith(":") or len(label) > 120:
        return None
    return label.rstrip(":").strip()


def _top_level_blocks(root: Tag) -> list[Tag]:
    """Return headings and complete content blocks once, in document order."""

    candidates = root.find_all(["h1", "h2", "h3", "h4", *_BLOCK_TAGS])
    result: list[Tag] = []
    for candidate in candidates:
        if any(parent is not root and parent.name in _BLOCK_TAGS for parent in candidate.parents):
            continue
        result.append(candidate)
    return result


def extract_structured_article(html: str) -> ExtractedArticle:
    """Extract readable text while preserving source headings, tables, and lists."""

    soup = BeautifulSoup(html, "html.parser")
    content_candidates = soup.select("main .content, article .content")
    root = max(
        content_candidates,
        key=lambda candidate: len(candidate.get_text(" ", strip=True)),
        default=None,
    )
    root = root or soup.select_one("main") or soup.select_one("article") or soup.body
    if root is None:
        raise ValueError("HTML source has no document body")
    if not isinstance(root, Tag):
        raise ValueError("HTML source has an invalid document body")
    for unwanted in root.select(
        "script, style, nav, footer, form, noscript, button, .buttons, .feedback-section"
    ):
        unwanted.decompose()
    title_node = root.find("h1") or soup.find("h1") or soup.find("title")
    title = normalize_text(title_node.get_text(" ", strip=True)) if title_node else "Untitled"

    section_data: list[tuple[str, int, list[str]]] = []
    current: tuple[str, int, list[str]] | None = None
    for node in _top_level_blocks(root):
        if node.name in {"h1", "h2", "h3", "h4"}:
            heading = normalize_text(node.get_text(" ", strip=True))
            if node.name == "h1":
                current = ("Overview", 2, [])
            else:
                current = (heading, int(node.name[1]), [])
            section_data.append(current)
            continue
        semantic_heading = _semantic_heading(node)
        block = _block_text(node)
        if semantic_heading:
            current = (semantic_heading, 5, [])
            section_data.append(current)
            block = normalize_text(block.removeprefix(f"{semantic_heading}:").strip())
        if current is None:
            current = ("Overview", 2, [])
            section_data.append(current)
        if block:
            current[2].append(block)

    sections = tuple(
        ArticleSection(heading=heading, level=level, content=normalize_text("\n".join(blocks)))
        for heading, level, blocks in section_data
        if heading.casefold() not in _IGNORED_SECTIONS and normalize_text("\n".join(blocks))
    )
    content = normalize_text(
        "\n\n".join(f"{section.heading}\n{section.content}" for section in sections)
    )
    if len(content) < 20:
        raise ValueError("Extracted article content is unexpectedly short")

    modified = None
    for selector, attribute in (
        ('meta[name="updated_at"]', "content"),
        ('meta[name="ms.date"]', "content"),
        ("time[datetime]", "datetime"),
    ):
        node = soup.select_one(selector)
        if node and node.get(attribute):
            modified = str(node.get(attribute))
            break
    return ExtractedArticle(title=title, content=content, modified=modified, sections=sections)


def extract_article(html: str) -> tuple[str, str, str | None]:
    """Backward-compatible tuple view of a structure-aware article extraction."""

    article = extract_structured_article(html)
    return article.title, article.content, article.modified
