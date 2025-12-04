"""Kibana service for CVElk.

Handles Kibana operations including:
- Dashboard import/export
- Index pattern creation
- Theme configuration
"""

import base64
import json
from pathlib import Path
from typing import Any

import httpx
from loguru import logger

from cvelk.config import Settings


class KibanaService:
    """Service for Kibana operations.

    Provides methods to configure Kibana dashboards,
    index patterns, and settings.
    """

    def __init__(self, settings: Settings):
        """Initialize Kibana service.

        Args:
            settings: Application settings.
        """
        self.settings = settings
        self.base_url = settings.kibana.host.rstrip("/")
        self._headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

        # Add authentication if password is set
        if settings.kibana.password.get_secret_value():
            password = settings.kibana.password.get_secret_value()
            credentials = f"{settings.kibana.username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            self._headers["Authorization"] = f"Basic {encoded}"

    def _url(self, path: str) -> str:
        """Build full URL for Kibana API endpoint.

        Args:
            path: API path.

        Returns:
            Full URL.
        """
        space = self.settings.kibana.space_id
        if space and space != "default":
            return f"{self.base_url}/s/{space}{path}"
        return f"{self.base_url}{path}"

    async def ping(self) -> bool:
        """Check if Kibana is reachable.

        Returns:
            True if connection successful.
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    f"{self.base_url}/api/status",
                    headers=self._headers,
                )
                return bool(response.status_code == 200)
        except Exception as e:
            logger.error(f"Kibana ping failed: {e}")
            return False

    async def set_dark_theme(self) -> bool:
        """Set Kibana to use dark theme.

        Returns:
            True if successful.
        """
        logger.info("Setting Kibana dark theme")

        try:
            # Get Kibana version for config ID
            async with httpx.AsyncClient(timeout=10) as client:
                status_response = await client.get(
                    f"{self.base_url}/api/status",
                    headers=self._headers,
                )
                if status_response.status_code != 200:
                    logger.warning("Could not get Kibana version")
                    return False

                version = status_response.json().get("version", {}).get("number", "9.0.0")

                # Kibana 9.x uses saved_objects API for settings
                url = self._url(f"/api/saved_objects/config/{version}")
                response = await client.put(
                    url,
                    headers=self._headers,
                    json={"attributes": {"theme:darkMode": True}},
                )

                if response.status_code == 200:
                    logger.info("Dark theme enabled")
                    return True

                logger.warning(f"Failed to set dark theme: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to set dark theme: {e}")
            return False

    async def import_saved_objects(
        self,
        file_path: str | Path,
        overwrite: bool = True,
    ) -> dict[str, Any]:
        """Import saved objects (dashboards, visualizations, etc.) from NDJSON file.

        Args:
            file_path: Path to NDJSON file with saved objects.
            overwrite: Whether to overwrite existing objects.

        Returns:
            Import result dictionary.
        """
        url = self._url("/api/saved_objects/_import")
        if overwrite:
            url += "?overwrite=true"

        file_path = Path(file_path)
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}

        logger.info(f"Importing saved objects from {file_path}")

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Read file content
                content = file_path.read_bytes()

                # Use multipart form upload
                files = {"file": (file_path.name, content, "application/ndjson")}

                # Remove Content-Type header for multipart
                headers = {k: v for k, v in self._headers.items() if k != "Content-Type"}

                response = await client.post(
                    url,
                    headers=headers,
                    files=files,
                )

                if response.status_code == 200:
                    result: dict[str, Any] = response.json()
                    logger.info(
                        f"Import complete: {result.get('successCount', 0)} success, "
                        f"{len(result.get('errors', []))} errors"
                    )
                    return result

                logger.error(f"Import failed: {response.status_code} - {response.text}")
                return {"error": response.text}

        except Exception as e:
            logger.error(f"Failed to import saved objects: {e}")
            return {"error": str(e)}

    async def export_saved_objects(
        self,
        types: list[str] | None = None,
        include_references: bool = True,
    ) -> bytes:
        """Export saved objects to NDJSON format.

        Args:
            types: Object types to export (e.g., ["dashboard", "visualization"]).
            include_references: Include referenced objects.

        Returns:
            NDJSON content as bytes.
        """
        url = self._url("/api/saved_objects/_export")

        export_types = types or ["dashboard", "visualization", "index-pattern", "search"]

        body = {
            "type": export_types,
            "includeReferencesDeep": include_references,
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    url,
                    headers=self._headers,
                    json=body,
                )

                if response.status_code == 200:
                    return bytes(response.content)

                logger.error(f"Export failed: {response.status_code}")
                return b""

        except Exception as e:
            logger.error(f"Failed to export saved objects: {e}")
            return b""

    async def create_data_view(
        self,
        name: str,
        index_pattern: str,
        time_field: str = "published",
        data_view_id: str = "cves-data-view",
    ) -> dict[str, Any]:
        """Create a Kibana data view (index pattern).

        Args:
            name: Data view name.
            index_pattern: Elasticsearch index pattern.
            time_field: Time field for time-based filtering.
            data_view_id: Explicit ID for the data view.

        Returns:
            Created data view info.
        """
        # Runtime field script for CVSS version classification
        cvss_version_script = """
if (doc.containsKey('cvssV4BaseScore') && doc['cvssV4BaseScore'].size() > 0) {
    emit('CVSS 4.0');
} else if (doc.containsKey('cvssV3Version') && doc['cvssV3Version'].size() > 0) {
    def v = doc['cvssV3Version'].value;
    if (v == '3.1') { emit('CVSS 3.1'); }
    else if (v == '3.0') { emit('CVSS 3.0'); }
    else { emit('CVSS 3.x'); }
} else {
    emit('CVSS 2.0');
}
""".strip()

        body = {
            "data_view": {
                "id": data_view_id,
                "title": index_pattern,
                "name": name,
                "timeFieldName": time_field,
                "runtimeFieldMap": {
                    "cvssVersion": {
                        "type": "keyword",
                        "script": {"source": cvss_version_script},
                    }
                },
            }
        }

        logger.info(f"Creating data view '{name}' (id={data_view_id}) for index '{index_pattern}'")

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # First try to delete existing data view if it exists
                delete_url = self._url(f"/api/data_views/data_view/{data_view_id}")
                await client.delete(delete_url, headers=self._headers)

                # Create data view with explicit ID
                url = self._url("/api/data_views/data_view")
                response = await client.post(
                    url,
                    headers=self._headers,
                    json=body,
                )

                if response.status_code in (200, 201):
                    result: dict[str, Any] = response.json()
                    logger.info(f"Data view created: {result.get('data_view', {}).get('id')}")
                    return result

                logger.error(
                    f"Failed to create data view: {response.status_code} - {response.text}"
                )
                return {"error": response.text}

        except Exception as e:
            logger.error(f"Failed to create data view: {e}")
            return {"error": str(e)}

    async def get_dashboard_url(self, dashboard_id: str) -> str:
        """Get the URL for a dashboard.

        Args:
            dashboard_id: Dashboard ID.

        Returns:
            Dashboard URL.
        """
        return self._url(f"/app/dashboards#/view/{dashboard_id}")

    async def set_default_dashboard(self, dashboard_id: str) -> bool:
        """Set a dashboard as the default landing page.

        Args:
            dashboard_id: Dashboard ID to set as default.

        Returns:
            True if successful.
        """
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Get Kibana version
                status_response = await client.get(
                    f"{self.base_url}/api/status",
                    headers=self._headers,
                )
                version = status_response.json().get("version", {}).get("number", "9.0.0")

                # Set default route
                url = self._url(f"/api/saved_objects/config/{version}")
                response = await client.put(
                    url,
                    headers=self._headers,
                    json={"attributes": {"defaultRoute": f"/app/dashboards#/view/{dashboard_id}"}},
                )

                if response.status_code == 200:
                    logger.info(f"Default dashboard set to {dashboard_id}")
                    return True

                logger.warning(f"Failed to set default dashboard: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to set default dashboard: {e}")
            return False

    async def create_saved_search(
        self,
        search_id: str,
        title: str,
        description: str,
        query: str,
        columns: list[str],
        data_view_id: str = "cves-data-view",
    ) -> bool:
        """Create a saved search.

        Args:
            search_id: Unique ID for the search.
            title: Search title.
            description: Search description.
            query: KQL query string.
            columns: Columns to display.
            data_view_id: Data view ID to use.

        Returns:
            True if successful.
        """
        url = self._url(f"/api/saved_objects/search/{search_id}?overwrite=true")

        payload = {
            "attributes": {
                "title": title,
                "description": description,
                "columns": columns,
                "sort": [["published", "desc"]],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {
                            "index": data_view_id,
                            "query": {"query": query, "language": "kuery"},
                            "filter": [],
                        }
                    )
                },
            },
            "references": [
                {
                    "id": data_view_id,
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                }
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, headers=self._headers, json=payload)
                if response.status_code in (200, 201):
                    logger.info(f"Created saved search: {title}")
                    return True
                logger.error(f"Failed to create search {title}: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to create search {title}: {e}")
            return False

    async def create_dashboard_programmatic(
        self,
        dashboard_id: str = "cvelk-main-dashboard",
        data_view_id: str = "cves-data-view",
    ) -> dict[str, Any]:
        """Create dashboard programmatically using Saved Objects API.

        This method creates the dashboard directly without importing NDJSON.

        Args:
            dashboard_id: Dashboard ID.
            data_view_id: Data view ID.

        Returns:
            Result with dashboard URL.
        """
        result: dict[str, Any] = {}

        # Create saved searches
        searches: list[dict[str, Any]] = [
            {
                "id": "cvelk-high-risk-search",
                "title": "High Risk CVEs",
                "description": "CVEs with CVSS >= 9 OR in KEV OR EPSS >= 0.5",
                "query": "baseScore >= 9 OR isKev: true OR epssScore >= 0.5",
                "columns": [
                    "cveId",
                    "baseScore",
                    "baseSeverity",
                    "epssScore",
                    "isKev",
                    "description",
                ],
            },
            {
                "id": "cvelk-kev-search",
                "title": "Known Exploited Vulnerabilities",
                "description": "CVEs in CISA KEV catalog",
                "query": "isKev: true",
                "columns": [
                    "cveId",
                    "baseScore",
                    "baseSeverity",
                    "epssScore",
                    "published",
                ],
            },
            {
                "id": "cvelk-high-epss-search",
                "title": "High EPSS Risk",
                "description": "CVEs with EPSS >= 0.5",
                "query": "epssScore >= 0.5",
                "columns": ["cveId", "baseScore", "epssScore", "isKev", "published"],
            },
            {
                "id": "cvelk-recent-search",
                "title": "Recent CVEs",
                "description": "Most recently published CVEs",
                "query": "",
                "columns": [
                    "cveId",
                    "baseScore",
                    "baseSeverity",
                    "epssScore",
                    "isKev",
                    "published",
                ],
            },
        ]

        for search in searches:
            await self.create_saved_search(
                search_id=search["id"],
                title=search["title"],
                description=search["description"],
                query=search["query"],
                columns=search["columns"],
                data_view_id=data_view_id,
            )

        # Dashboard markdown header
        header_markdown = (
            "# 🛡️ CVElk - Vulnerability Intelligence Dashboard\n\n"
            "Real-time CVE data from **NVD 2.0 API**, enriched with "
            "**EPSS** exploit prediction scores and **CISA KEV**.\n\n"
            "| Metric | Description | Risk Level |\n"
            "|--------|-------------|------------|\n"
            "| **CVSS** | Vulnerability Scoring (0-10) | Critical: ≥9 |\n"
            "| **EPSS** | Exploit probability in 30 days | High: ≥50% |\n"
            "| **KEV** | Known Exploited Vulnerabilities | Critical |\n\n"
            "Use the **time picker** and **search bar** to filter."
        )

        # Panel definitions
        panels = [
            {
                "version": "9.0.0",
                "type": "visualization",
                "gridData": {"x": 0, "y": 0, "w": 48, "h": 7, "i": "header"},
                "panelIndex": "header",
                "embeddableConfig": {
                    "savedVis": {
                        "title": "",
                        "type": "markdown",
                        "params": {
                            "fontSize": 12,
                            "openLinksInNewTab": False,
                            "markdown": header_markdown,
                        },
                        "data": {},
                    }
                },
            },
            {
                "version": "9.0.0",
                "type": "search",
                "gridData": {"x": 0, "y": 7, "w": 48, "h": 12, "i": "high-risk"},
                "panelIndex": "high-risk",
                "panelRefName": "panel_high_risk",
                "title": "🔴 High Risk CVEs (Critical CVSS ≥9, KEV, or EPSS ≥50%)",
                "embeddableConfig": {"enhancements": {}},
            },
            {
                "version": "9.0.0",
                "type": "search",
                "gridData": {"x": 0, "y": 19, "w": 24, "h": 12, "i": "kev"},
                "panelIndex": "kev",
                "panelRefName": "panel_kev",
                "title": "⚠️ Known Exploited (CISA KEV)",
                "embeddableConfig": {"enhancements": {}},
            },
            {
                "version": "9.0.0",
                "type": "search",
                "gridData": {"x": 24, "y": 19, "w": 24, "h": 12, "i": "epss"},
                "panelIndex": "epss",
                "panelRefName": "panel_epss",
                "title": "📊 High EPSS Risk (≥50% exploit probability)",
                "embeddableConfig": {"enhancements": {}},
            },
            {
                "version": "9.0.0",
                "type": "search",
                "gridData": {"x": 0, "y": 31, "w": 48, "h": 15, "i": "recent"},
                "panelIndex": "recent",
                "panelRefName": "panel_recent",
                "title": "📅 Recent CVEs",
                "embeddableConfig": {"enhancements": {}},
            },
        ]

        dashboard_desc = (
            "Comprehensive CVE dashboard with NVD data, EPSS risk scores, and CISA KEV status"
        )

        dashboard_payload = {
            "attributes": {
                "title": "CVElk - Vulnerability Intelligence",
                "description": dashboard_desc,
                "hits": 0,
                "optionsJSON": json.dumps(
                    {
                        "useMargins": True,
                        "syncColors": False,
                        "syncCursor": True,
                        "syncTooltips": False,
                        "hidePanelTitles": False,
                    }
                ),
                "panelsJSON": json.dumps(panels),
                "timeRestore": True,
                "timeTo": "now",
                "timeFrom": "now-1y",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps(
                        {
                            "query": {"query": "", "language": "kuery"},
                            "filter": [],
                        }
                    )
                },
            },
            "references": [
                {
                    "id": data_view_id,
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                },
                {"id": "cvelk-high-risk-search", "name": "panel_high_risk", "type": "search"},
                {"id": "cvelk-kev-search", "name": "panel_kev", "type": "search"},
                {"id": "cvelk-high-epss-search", "name": "panel_epss", "type": "search"},
                {"id": "cvelk-recent-search", "name": "panel_recent", "type": "search"},
            ],
        }

        url = self._url(f"/api/saved_objects/dashboard/{dashboard_id}?overwrite=true")

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, headers=self._headers, json=dashboard_payload)
                if response.status_code in (200, 201):
                    logger.info(f"Dashboard created: {dashboard_id}")
                    result["dashboard_id"] = dashboard_id
                    result["dashboard_url"] = f"{self.base_url}/app/dashboards#/view/{dashboard_id}"
                    result["success"] = True
                else:
                    logger.error(
                        f"Failed to create dashboard: {response.status_code} - "
                        f"{response.text[:200]}"
                    )
                    result["success"] = False
                    result["error"] = response.text
        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}")
            result["success"] = False
            result["error"] = str(e)

        return result

    async def setup_cvelk_dashboard(
        self,
        dashboard_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Set up the CVElk dashboard and data view.

        This method:
        1. Creates the data view with proper ID, time field, and runtime fields
        2. Sets dark theme
        3. Imports the dashboard from NDJSON

        Args:
            dashboard_path: Path to dashboard NDJSON file.

        Returns:
            Setup result with dashboard URL.
        """
        result: dict[str, Any] = {}

        # Step 1: Create data view with explicit ID that matches the dashboard
        # This includes the runtime field for cvssVersion
        dv_result = await self.create_data_view(
            name="CVEs",
            index_pattern=self.settings.elasticsearch.index_name,
            time_field="published",
            data_view_id="cves-data-view",
        )
        result["data_view"] = dv_result

        if "error" in dv_result:
            logger.error(f"Failed to create data view: {dv_result['error']}")
            return result

        # Step 2: Set dark theme
        theme_result = await self.set_dark_theme()
        result["dark_theme"] = theme_result

        # Step 3: Import dashboard from NDJSON
        if dashboard_path and Path(dashboard_path).exists():
            import_result = await self.import_saved_objects(dashboard_path)
            result["import"] = import_result

            # Extract dashboard ID and set URL
            if "successResults" in import_result:
                for obj in import_result["successResults"]:
                    if obj.get("type") == "dashboard":
                        dashboard_id = obj.get("destinationId") or obj.get("id")
                        result["dashboard_url"] = await self.get_dashboard_url(dashboard_id)
                        await self.set_default_dashboard(dashboard_id)
                        break
            elif import_result.get("successCount", 0) > 0:
                # Dashboard was imported but no successResults (overwrite case)
                result["dashboard_url"] = await self.get_dashboard_url("cvelk-main-dashboard")
                await self.set_default_dashboard("cvelk-main-dashboard")
        else:
            # Create dashboard programmatically if no NDJSON
            logger.info("Creating dashboard programmatically...")
            dashboard_result = await self.create_dashboard_programmatic()
            result.update(dashboard_result)
            if dashboard_result.get("success"):
                await self.set_default_dashboard("cvelk-main-dashboard")

        return result
