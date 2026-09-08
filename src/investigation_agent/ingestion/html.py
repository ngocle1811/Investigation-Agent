"""Shared extraction for curated Microsoft HTML pages."""

from bs4 import BeautifulSoup, Tag

from investigation_agent.ingestion.utils import normalize_text


def extract_article(html: str) -> tuple[str, str, str | None]:
    """Extract a title, readable article text, and modified date from Microsoft HTML."""

    soup = BeautifulSoup(html, "html.parser")
    root = soup.select_one("main") or soup.select_one("article") or soup.body
    if root is None:
        raise ValueError("HTML source has no document body")
    if not isinstance(root, Tag):
        raise ValueError("HTML source has an invalid document body")
    for unwanted in root.select("script, style, nav, footer, form, noscript"):
        unwanted.decompose()
    title_node = root.find("h1") or soup.find("h1") or soup.find("title")
    title = normalize_text(title_node.get_text(" ", strip=True)) if title_node else "Untitled"
    content = normalize_text(root.get_text("\n", strip=True))
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
    return title, content, modified
