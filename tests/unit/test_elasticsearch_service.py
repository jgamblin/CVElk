"""Tests for Elasticsearch bulk operations."""

from unittest.mock import MagicMock

import pytest

from cvelk.services import elasticsearch_service
from cvelk.services.elasticsearch_service import ElasticsearchService


@pytest.fixture
def es_service(mock_settings):
    """An ElasticsearchService with a mocked client."""
    service = ElasticsearchService(mock_settings)
    service._client = MagicMock()
    return service


@pytest.fixture
def bulk_calls(monkeypatch):
    """Replace streaming_bulk, recording actions and returning queued results."""
    calls: dict = {"actions": [], "results": []}

    def fake_streaming_bulk(client, actions, **kwargs):
        calls["actions"].extend(actions)
        calls["kwargs"] = kwargs
        yield from calls["results"]

    monkeypatch.setattr(elasticsearch_service.helpers, "streaming_bulk", fake_streaming_bulk)
    return calls


def test_run_bulk_counts_missing_documents_as_neither(es_service, bulk_calls) -> None:
    """A 404 is skipped; other failures are counted as errors."""
    bulk_calls["results"] = [
        (True, {"delete": {"_id": "CVE-1", "status": 200}}),
        (False, {"delete": {"_id": "CVE-2", "status": 404}}),
        (False, {"delete": {"_id": "CVE-3", "status": 500, "error": "boom"}}),
    ]

    assert es_service.bulk_delete_cves(["CVE-1", "CVE-2", "CVE-3"]) == (1, 1)
    assert bulk_calls["kwargs"]["raise_on_error"] is False


def test_bulk_delete_actions(es_service, bulk_calls) -> None:
    """Deletes target the configured index by CVE ID."""
    es_service.bulk_delete_cves(["CVE-2024-0001"])

    assert bulk_calls["actions"] == [
        {"_op_type": "delete", "_index": "cves", "_id": "CVE-2024-0001"}
    ]


def test_bulk_update_actions(es_service, bulk_calls) -> None:
    """Updates are partial document updates."""
    es_service.bulk_update_cves([("CVE-2024-0001", {"epssScore": 12.5})])

    assert bulk_calls["actions"] == [
        {
            "_op_type": "update",
            "_index": "cves",
            "_id": "CVE-2024-0001",
            "doc": {"epssScore": 12.5},
        }
    ]


def test_bulk_index_actions(es_service, bulk_calls, sample_cve) -> None:
    """Index actions use the CVE ID as the document ID."""
    bulk_calls["results"] = [(True, {"index": {"_id": sample_cve.cve_id, "status": 201}})]

    assert es_service.bulk_index_cves([sample_cve]) == (1, 0)
    action = bulk_calls["actions"][0]
    assert action["_id"] == sample_cve.cve_id
    assert "_id" not in action["_source"]


def test_clear_kev_except(es_service) -> None:
    """CVEs no longer in KEV have their KEV fields cleared."""
    es_service.client.update_by_query.return_value = {"updated": 2}

    assert es_service.clear_kev_except(["CVE-2024-0001"]) == 2

    query = es_service.client.update_by_query.call_args.kwargs["query"]
    assert query["bool"]["must_not"] == [{"terms": {"cveId": ["CVE-2024-0001"]}}]
    assert query["bool"]["filter"] == [{"term": {"isKev": True}}]
