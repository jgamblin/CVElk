"""Elasticsearch service for CVElk.

Handles all Elasticsearch operations including:
- Connection management with authentication
- Index creation and mapping
- Bulk document indexing
- Query operations
"""

from typing import Any

from elasticsearch import Elasticsearch, helpers
from loguru import logger

from cvelk.config import Settings
from cvelk.models.cve import CVE

# Elasticsearch index mapping for CVE data
CVE_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "cveId": {"type": "keyword"},
            "sourceIdentifier": {"type": "keyword"},
            "published": {"type": "date"},
            "lastModified": {"type": "date"},
            "vulnStatus": {"type": "keyword"},
            "description": {"type": "text", "analyzer": "standard"},
            "baseScore": {"type": "float"},
            "baseSeverity": {"type": "keyword"},
            "primaryCwe": {"type": "keyword"},
            "cweIds": {"type": "keyword"},
            "referenceUrls": {"type": "keyword"},
            # EPSS fields
            "epssScore": {"type": "float"},
            "epssPercentile": {"type": "float"},
            # KEV fields
            "isKev": {"type": "boolean"},
            "kevDateAdded": {"type": "date"},
            "kevDueDate": {"type": "date"},
            "kevRansomwareUse": {"type": "boolean"},
            # CVSS v3 fields
            "cvssV3Version": {"type": "keyword"},
            "cvssV3VectorString": {"type": "keyword"},
            "cvssV3BaseScore": {"type": "float"},
            "cvssV3BaseSeverity": {"type": "keyword"},
            "cvssV3AttackVector": {"type": "keyword"},
            "cvssV3AttackComplexity": {"type": "keyword"},
            "cvssV3PrivilegesRequired": {"type": "keyword"},
            "cvssV3UserInteraction": {"type": "keyword"},
            "cvssV3Scope": {"type": "keyword"},
            "cvssV3ConfidentialityImpact": {"type": "keyword"},
            "cvssV3IntegrityImpact": {"type": "keyword"},
            "cvssV3AvailabilityImpact": {"type": "keyword"},
            "cvssV3ExploitabilityScore": {"type": "float"},
            "cvssV3ImpactScore": {"type": "float"},
            # CVSS v4 fields
            "cvssV4VectorString": {"type": "keyword"},
            "cvssV4BaseScore": {"type": "float"},
            "cvssV4BaseSeverity": {"type": "keyword"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "30s",
    },
}


class ElasticsearchService:
    """Service for Elasticsearch operations.

    Supports both local and Elastic Cloud deployments with
    various authentication methods.
    """

    def __init__(self, settings: Settings):
        """Initialize Elasticsearch service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self._client: Elasticsearch | None = None

    @property
    def client(self) -> Elasticsearch:
        """Get or create Elasticsearch client."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> Elasticsearch:
        """Create Elasticsearch client based on settings.

        Returns:
            Configured Elasticsearch client.
        """
        es_settings = self.settings.elasticsearch

        # Elastic Cloud connection
        if es_settings.is_cloud and es_settings.cloud_id:
            logger.info(f"Connecting to Elastic Cloud: {es_settings.cloud_id[:20]}...")

            if es_settings.has_api_key:
                # API key auth (api_key_id guaranteed when has_api_key is True)
                api_key_id = es_settings.api_key_id or ""
                api_key_secret = (
                    es_settings.api_key.get_secret_value() if es_settings.api_key else ""
                )
                return Elasticsearch(
                    cloud_id=es_settings.cloud_id,
                    api_key=(api_key_id, api_key_secret),
                )
            # Basic authentication
            return Elasticsearch(
                cloud_id=es_settings.cloud_id,
                basic_auth=(
                    es_settings.username,
                    es_settings.password.get_secret_value(),
                ),
            )

        # Local/self-hosted connection
        logger.info(f"Connecting to Elasticsearch: {es_settings.host}")

        client_kwargs: dict[str, Any] = {
            "hosts": [es_settings.host],
            "verify_certs": es_settings.verify_certs,
        }

        # Add authentication if password is set
        if es_settings.password.get_secret_value():
            client_kwargs["basic_auth"] = (
                es_settings.username,
                es_settings.password.get_secret_value(),
            )

        # Add CA certs if specified
        if es_settings.ca_certs:
            client_kwargs["ca_certs"] = es_settings.ca_certs

        return Elasticsearch(**client_kwargs)

    def ping(self) -> bool:
        """Check if Elasticsearch is reachable.

        Returns:
            True if connection successful.
        """
        try:
            return bool(self.client.ping())
        except Exception as e:
            logger.error(f"Elasticsearch ping failed: {e}")
            return False

    def ensure_index(self, index_name: str | None = None) -> None:
        """Ensure the CVE index exists with proper mapping.

        Args:
            index_name: Index name (defaults to settings value).
        """
        index = index_name or self.settings.elasticsearch.index_name

        if self.client.indices.exists(index=index):
            logger.info(f"Index '{index}' already exists")
            return

        logger.info(f"Creating index '{index}' with CVE mapping")
        self.client.indices.create(
            index=index,
            body=CVE_INDEX_MAPPING,
        )
        logger.info(f"Index '{index}' created successfully")

    def delete_index(self, index_name: str | None = None) -> None:
        """Delete the CVE index.

        Args:
            index_name: Index name (defaults to settings value).
        """
        index = index_name or self.settings.elasticsearch.index_name

        if self.client.indices.exists(index=index):
            logger.warning(f"Deleting index '{index}'")
            self.client.indices.delete(index=index)
            logger.info(f"Index '{index}' deleted")
        else:
            logger.info(f"Index '{index}' does not exist")

    def index_cve(self, cve: CVE, index_name: str | None = None) -> None:
        """Index a single CVE document.

        Args:
            cve: CVE model instance.
            index_name: Index name (defaults to settings value).
        """
        index = index_name or self.settings.elasticsearch.index_name
        doc = cve.to_elasticsearch_doc()
        doc_id = doc.pop("_id")

        self.client.index(
            index=index,
            id=doc_id,
            document=doc,
        )

    def bulk_index_cves(
        self,
        cves: list[CVE],
        index_name: str | None = None,
        chunk_size: int = 500,
    ) -> tuple[int, int]:
        """Bulk index multiple CVE documents.

        Args:
            cves: List of CVE model instances.
            index_name: Index name (defaults to settings value).
            chunk_size: Number of documents per bulk request.

        Returns:
            Tuple of (success_count, error_count).
        """
        index = index_name or self.settings.elasticsearch.index_name

        def generate_actions() -> Any:
            for cve in cves:
                doc = cve.to_elasticsearch_doc()
                doc_id = doc.pop("_id")
                yield {
                    "_index": index,
                    "_id": doc_id,
                    "_source": doc,
                }

        logger.info(f"Bulk indexing {len(cves)} CVEs to '{index}'")

        success, errors = helpers.bulk(
            self.client,
            generate_actions(),
            chunk_size=chunk_size,
            raise_on_error=False,
            stats_only=True,
        )

        # When stats_only=True, errors is always an int
        error_count = errors if isinstance(errors, int) else len(errors)
        logger.info(f"Bulk index complete: {success} success, {error_count} errors")
        return int(success), error_count

    def get_cve(self, cve_id: str, index_name: str | None = None) -> dict[str, Any] | None:
        """Get a CVE document by ID.

        Args:
            cve_id: CVE identifier.
            index_name: Index name (defaults to settings value).

        Returns:
            Document source if found, None otherwise.
        """
        index = index_name or self.settings.elasticsearch.index_name

        try:
            result = self.client.get(index=index, id=cve_id)
            source: dict[str, Any] = result["_source"]
            return source
        except Exception:
            return None

    def search_cves(
        self,
        query: dict[str, Any],
        index_name: str | None = None,
        size: int = 100,
    ) -> list[dict[str, Any]]:
        """Search for CVEs matching a query.

        Args:
            query: Elasticsearch query DSL.
            index_name: Index name (defaults to settings value).
            size: Maximum results to return.

        Returns:
            List of matching documents.
        """
        index = index_name or self.settings.elasticsearch.index_name

        result = self.client.search(
            index=index,
            query=query,
            size=size,
        )

        return [hit["_source"] for hit in result["hits"]["hits"]]

    def count(self, index_name: str | None = None) -> int:
        """Get document count in index.

        Args:
            index_name: Index name (defaults to settings value).

        Returns:
            Number of documents in index.
        """
        index = index_name or self.settings.elasticsearch.index_name

        try:
            result = self.client.count(index=index)
            return int(result["count"])
        except Exception:
            return 0

    def get_stats(self, index_name: str | None = None) -> dict[str, Any]:
        """Get index statistics.

        Args:
            index_name: Index name (defaults to settings value).

        Returns:
            Dictionary with index statistics.
        """
        index = index_name or self.settings.elasticsearch.index_name

        try:
            count = self.count(index)
            stats = self.client.indices.stats(index=index)
            index_stats = stats["indices"].get(index, {}).get("primaries", {})

            return {
                "index_name": index,
                "document_count": count,
                "size_bytes": index_stats.get("store", {}).get("size_in_bytes", 0),
                "indexing_total": index_stats.get("indexing", {}).get("index_total", 0),
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"error": str(e)}

    def close(self) -> None:
        """Close the Elasticsearch client."""
        if self._client:
            self._client.close()
            self._client = None
