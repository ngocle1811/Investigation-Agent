"""Knowledge search route contract tests."""

from fastapi.testclient import TestClient

from investigation_agent.api.main import app
from investigation_agent.api.routes import knowledge
from investigation_agent.rag.dense import KnowledgeSearchResponse


class FakeRetriever:
    """Capture API parameters without initializing Qdrant or an embedding model."""

    def __init__(self) -> None:
        self.call = None

    def search(self, query, *, top_k, filters):
        self.call = (query, top_k, filters)
        return KnowledgeSearchResponse(query=query, filters=filters, results=[])


def test_search_endpoint_exposes_metadata_filters(monkeypatch) -> None:
    retriever = FakeRetriever()
    monkeypatch.setattr(knowledge, "get_dense_retriever", lambda: retriever)
    response = TestClient(app).get(
        "/knowledge/search",
        params={
            "q": "failed logon",
            "top_k": 3,
            "source_type": "windows_event_doc",
            "event_id": 4625,
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "query": "failed logon",
        "filters": {
            "document_id": None,
            "source": None,
            "source_type": "windows_event_doc",
            "event_id": 4625,
            "sigma_rule_id": None,
            "technique_id": None,
            "tactic": None,
        },
        "results": [],
    }
    assert retriever.call[1] == 3
    assert retriever.call[2].event_id == 4625
