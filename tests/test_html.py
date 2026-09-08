"""Regression tests for Microsoft Learn article layout extraction."""

from investigation_agent.ingestion.html import extract_structured_article


def test_article_extraction_chooses_body_content_over_separate_title_block() -> None:
    article = extract_structured_article(
        """
        <main>
          <div><div class="content"><h1>Event 4625</h1></div></div>
          <div class="content">
            <h2>Event Description</h2>
            <p>This event is generated when an account logon attempt fails.</p>
          </div>
        </main>
        """
    )
    assert article.title == "Event 4625"
    assert article.sections[0].heading == "Event Description"
    assert "account logon attempt fails" in article.content
