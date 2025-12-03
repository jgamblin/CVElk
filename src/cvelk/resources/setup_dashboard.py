#!/usr/bin/env python3
"""CVElk Dashboard Setup Script.

This script programmatically creates the CVElk dashboard in Kibana 8.x.
It uses the Saved Objects API to create:
- Data view (index pattern) for the CVEs index
- Lens visualizations embedded in the dashboard
- Comprehensive dashboard with metrics, charts, and tables

Usage:
    python setup_dashboard.py [--kibana-url URL] [--index-name NAME]
"""

import argparse
import json
import sys
from typing import Any

import requests


class KibanaDashboardBuilder:
    """Builder for CVElk Kibana dashboard."""

    def __init__(
        self,
        kibana_url: str = "http://localhost:5601",
        index_name: str = "cves",
        data_view_id: str | None = None,
    ):
        """Initialize the dashboard builder.

        Args:
            kibana_url: Kibana base URL.
            index_name: Elasticsearch index name.
            data_view_id: ID for the Kibana data view (will be looked up if not provided).
        """
        self.kibana_url = kibana_url.rstrip("/")
        self.index_name = index_name
        self.data_view_id = data_view_id
        self.headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

    def _post(self, path: str, payload: dict[str, Any]) -> requests.Response:
        """POST to Kibana API."""
        url = f"{self.kibana_url}{path}"
        return requests.post(url, headers=self.headers, json=payload, timeout=30)

    def _get(self, path: str) -> requests.Response:
        """GET from Kibana API."""
        url = f"{self.kibana_url}{path}"
        return requests.get(url, headers=self.headers, timeout=30)

    def _put(self, path: str, payload: dict[str, Any]) -> requests.Response:
        """PUT to Kibana API."""
        url = f"{self.kibana_url}{path}"
        return requests.put(url, headers=self.headers, json=payload, timeout=30)

    def check_connection(self) -> bool:
        """Check if Kibana is reachable."""
        try:
            resp = self._get("/api/status")
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def get_kibana_version(self) -> str:
        """Get Kibana version."""
        try:
            resp = self._get("/api/status")
            return resp.json().get("version", {}).get("number", "8.17.0")
        except Exception:
            return "8.17.0"

    def find_or_create_data_view(self) -> str | None:
        """Find existing data view or create one for CVEs."""
        print(f"Setting up data view for '{self.index_name}'...")

        # First, check if data view already exists
        resp = self._get("/api/data_views")
        if resp.status_code == 200:
            data_views = resp.json().get("data_view", [])
            for dv in data_views:
                if dv.get("title") == self.index_name or dv.get("name") == "CVEs":
                    self.data_view_id = dv["id"]
                    print(f"  ✓ Found existing data view: {self.data_view_id}")
                    return self.data_view_id

        # Create new data view
        payload = {
            "data_view": {
                "title": self.index_name,
                "name": "CVEs",
                "timeFieldName": "published",
            }
        }

        resp = self._post("/api/data_views/data_view", payload)
        if resp.status_code in [200, 201]:
            self.data_view_id = resp.json().get("data_view", {}).get("id")
            print(f"  ✓ Created data view: {self.data_view_id}")
            return self.data_view_id

        if resp.status_code == 400 and "Duplicate" in resp.text:
            # Try to find it again
            resp = self._get("/api/data_views")
            if resp.status_code == 200:
                data_views = resp.json().get("data_view", [])
                for dv in data_views:
                    if dv.get("title") == self.index_name:
                        self.data_view_id = dv["id"]
                        print(f"  ✓ Found existing data view: {self.data_view_id}")
                        return self.data_view_id

        print(f"  ✗ Failed to create data view: {resp.status_code}")
        return None

    def set_dark_theme(self) -> bool:
        """Enable dark theme in Kibana."""
        print("Setting dark theme...")

        version = self.get_kibana_version()
        payload = {"attributes": {"theme:darkMode": True}}
        resp = self._put(f"/api/saved_objects/config/{version}", payload)

        if resp.status_code == 200:
            print("  ✓ Dark theme enabled")
            return True

        print(f"  ⚠ Could not set dark theme: {resp.status_code}")
        return False

    def _create_metric_panel(
        self,
        panel_id: str,
        title: str,
        query: str,
        color: str,
        grid_x: int,
        grid_y: int,
    ) -> dict[str, Any]:
        """Create a Lens metric panel configuration."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": grid_x, "y": grid_y, "w": 12, "h": 8, "i": panel_id},
            "panelIndex": panel_id,
            "embeddableConfig": {
                "attributes": {
                    "title": title,
                    "visualizationType": "lnsMetric",
                    "state": {
                        "visualization": {
                            "layerId": "layer1",
                            "layerType": "data",
                            "metricAccessor": "metric1",
                            "color": color,
                        },
                        "query": {"query": query, "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "metric1": {
                                                "label": title,
                                                "dataType": "number",
                                                "operationType": "count",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                                "sourceField": "___records___",
                                            }
                                        },
                                        "columnOrder": ["metric1"],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": title,
            },
        }

    def _create_severity_pie_panel(self) -> dict[str, Any]:
        """Create the severity distribution donut chart panel."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": 0, "y": 8, "w": 16, "h": 14, "i": "severity-pie"},
            "panelIndex": "severity-pie",
            "embeddableConfig": {
                "attributes": {
                    "title": "Severity Distribution",
                    "visualizationType": "lnsPie",
                    "state": {
                        "visualization": {
                            "shape": "donut",
                            "layers": [
                                {
                                    "layerId": "layer1",
                                    "layerType": "data",
                                    "primaryGroups": ["bucket1"],
                                    "metrics": ["metric1"],
                                    "numberDisplay": "percent",
                                    "categoryDisplay": "default",
                                    "legendDisplay": "default",
                                    "nestedLegend": False,
                                }
                            ],
                        },
                        "query": {"query": "", "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "bucket1": {
                                                "label": "Severity",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "baseSeverity",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 5,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "metric1",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                    "missingBucket": False,
                                                },
                                            },
                                            "metric1": {
                                                "label": "Count",
                                                "dataType": "number",
                                                "operationType": "count",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                                "sourceField": "___records___",
                                            },
                                        },
                                        "columnOrder": ["bucket1", "metric1"],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": "Severity Distribution",
            },
        }

    def _create_time_series_panel(self) -> dict[str, Any]:
        """Create the CVEs over time stacked bar chart panel."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": 16, "y": 8, "w": 32, "h": 14, "i": "cves-over-time"},
            "panelIndex": "cves-over-time",
            "embeddableConfig": {
                "attributes": {
                    "title": "CVEs Over Time by Severity",
                    "visualizationType": "lnsXY",
                    "state": {
                        "visualization": {
                            "legend": {"isVisible": True, "position": "right"},
                            "valueLabels": "hide",
                            "preferredSeriesType": "bar_stacked",
                            "layers": [
                                {
                                    "layerId": "layer1",
                                    "layerType": "data",
                                    "seriesType": "bar_stacked",
                                    "xAccessor": "date1",
                                    "accessors": ["metric1"],
                                    "splitAccessor": "bucket1",
                                }
                            ],
                            "yTitle": "CVE Count",
                            "xTitle": "Date",
                        },
                        "query": {"query": "", "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "date1": {
                                                "label": "Published Date",
                                                "dataType": "date",
                                                "operationType": "date_histogram",
                                                "sourceField": "published",
                                                "isBucketed": True,
                                                "scale": "interval",
                                                "params": {"interval": "auto"},
                                            },
                                            "bucket1": {
                                                "label": "Severity",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "baseSeverity",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 5,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "metric1",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                    "missingBucket": False,
                                                },
                                            },
                                            "metric1": {
                                                "label": "Count",
                                                "dataType": "number",
                                                "operationType": "count",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                                "sourceField": "___records___",
                                            },
                                        },
                                        "columnOrder": ["date1", "bucket1", "metric1"],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": "CVEs Over Time by Severity",
            },
        }

    def _create_epss_distribution_panel(self) -> dict[str, Any]:
        """Create the EPSS score distribution bar chart panel."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": 0, "y": 22, "w": 24, "h": 12, "i": "epss-distribution"},
            "panelIndex": "epss-distribution",
            "embeddableConfig": {
                "attributes": {
                    "title": "EPSS Score Distribution",
                    "visualizationType": "lnsXY",
                    "state": {
                        "visualization": {
                            "legend": {"isVisible": False},
                            "valueLabels": "hide",
                            "preferredSeriesType": "bar",
                            "layers": [
                                {
                                    "layerId": "layer1",
                                    "layerType": "data",
                                    "seriesType": "bar",
                                    "xAccessor": "bucket1",
                                    "accessors": ["metric1"],
                                }
                            ],
                            "yTitle": "CVE Count",
                            "xTitle": "EPSS Score Range",
                        },
                        "query": {"query": "", "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "bucket1": {
                                                "label": "EPSS Score",
                                                "dataType": "number",
                                                "operationType": "range",
                                                "sourceField": "epssScore",
                                                "isBucketed": True,
                                                "scale": "ordinal",
                                                "params": {
                                                    "type": "range",
                                                    "ranges": [
                                                        {
                                                            "from": 0,
                                                            "to": 0.1,
                                                            "label": "0-0.1",
                                                        },
                                                        {
                                                            "from": 0.1,
                                                            "to": 0.3,
                                                            "label": "0.1-0.3",
                                                        },
                                                        {
                                                            "from": 0.3,
                                                            "to": 0.5,
                                                            "label": "0.3-0.5",
                                                        },
                                                        {
                                                            "from": 0.5,
                                                            "to": 0.7,
                                                            "label": "0.5-0.7",
                                                        },
                                                        {
                                                            "from": 0.7,
                                                            "to": 1.0,
                                                            "label": "0.7-1.0",
                                                        },
                                                    ],
                                                    "maxBars": "auto",
                                                },
                                            },
                                            "metric1": {
                                                "label": "Count",
                                                "dataType": "number",
                                                "operationType": "count",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                                "sourceField": "___records___",
                                            },
                                        },
                                        "columnOrder": ["bucket1", "metric1"],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": "EPSS Score Distribution",
            },
        }

    def _create_top_cwes_panel(self) -> dict[str, Any]:
        """Create the top CWEs horizontal bar chart panel."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": 24, "y": 22, "w": 24, "h": 12, "i": "top-cwes"},
            "panelIndex": "top-cwes",
            "embeddableConfig": {
                "attributes": {
                    "title": "Top Weakness Types (CWE)",
                    "visualizationType": "lnsXY",
                    "state": {
                        "visualization": {
                            "legend": {"isVisible": False},
                            "valueLabels": "hide",
                            "preferredSeriesType": "bar_horizontal",
                            "layers": [
                                {
                                    "layerId": "layer1",
                                    "layerType": "data",
                                    "seriesType": "bar_horizontal",
                                    "xAccessor": "bucket1",
                                    "accessors": ["metric1"],
                                }
                            ],
                            "yTitle": "CWE",
                            "xTitle": "Count",
                        },
                        "query": {"query": "", "language": "kuery"},
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "bucket1": {
                                                "label": "CWE",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "primaryCwe",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 10,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "metric1",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                    "missingBucket": False,
                                                },
                                            },
                                            "metric1": {
                                                "label": "Count",
                                                "dataType": "number",
                                                "operationType": "count",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                                "sourceField": "___records___",
                                            },
                                        },
                                        "columnOrder": ["bucket1", "metric1"],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": "Top Weakness Types (CWE)",
            },
        }

    def _create_data_table_panel(self) -> dict[str, Any]:
        """Create the high-risk CVEs data table panel."""
        return {
            "version": "8.17.0",
            "type": "lens",
            "gridData": {"x": 0, "y": 34, "w": 48, "h": 14, "i": "cve-table"},
            "panelIndex": "cve-table",
            "embeddableConfig": {
                "attributes": {
                    "title": "Recent High-Risk CVEs (Critical/High Severity)",
                    "visualizationType": "lnsDatatable",
                    "state": {
                        "visualization": {
                            "layerId": "layer1",
                            "layerType": "data",
                            "columns": [
                                {"columnId": "col1", "width": 140},
                                {"columnId": "col2", "width": 100},
                                {"columnId": "col3", "width": 80},
                                {"columnId": "col4", "width": 80},
                                {"columnId": "col5", "width": 100},
                            ],
                            "paging": {"size": 10, "enabled": True},
                            "headerRowHeight": "auto",
                            "rowHeight": "auto",
                        },
                        "query": {
                            "query": "baseSeverity: CRITICAL OR baseSeverity: HIGH",
                            "language": "kuery",
                        },
                        "filters": [],
                        "datasourceStates": {
                            "formBased": {
                                "layers": {
                                    "layer1": {
                                        "columns": {
                                            "col1": {
                                                "label": "CVE ID",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "cveId",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 20,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "col4",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                },
                                            },
                                            "col2": {
                                                "label": "Severity",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "baseSeverity",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 20,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "col4",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                },
                                            },
                                            "col3": {
                                                "label": "CVSS",
                                                "dataType": "number",
                                                "operationType": "max",
                                                "sourceField": "baseScore",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                            },
                                            "col4": {
                                                "label": "EPSS",
                                                "dataType": "number",
                                                "operationType": "max",
                                                "sourceField": "epssScore",
                                                "isBucketed": False,
                                                "scale": "ratio",
                                            },
                                            "col5": {
                                                "label": "CWE",
                                                "dataType": "string",
                                                "operationType": "terms",
                                                "scale": "ordinal",
                                                "sourceField": "primaryCwe",
                                                "isBucketed": True,
                                                "params": {
                                                    "size": 20,
                                                    "orderBy": {
                                                        "type": "column",
                                                        "columnId": "col4",
                                                    },
                                                    "orderDirection": "desc",
                                                    "otherBucket": False,
                                                },
                                            },
                                        },
                                        "columnOrder": [
                                            "col1",
                                            "col2",
                                            "col3",
                                            "col4",
                                            "col5",
                                        ],
                                        "incompleteColumns": {},
                                    }
                                }
                            }
                        },
                    },
                    "references": [
                        {
                            "type": "index-pattern",
                            "id": self.data_view_id,
                            "name": "indexpattern-datasource-layer-layer1",
                        }
                    ],
                },
                "title": "Recent High-Risk CVEs",
            },
        }

    def create_dashboard(self) -> bool:
        """Create the main CVElk dashboard with Lens visualizations."""
        print("Creating dashboard with Lens visualizations...")

        if not self.data_view_id:
            print("  ✗ No data view ID available")
            return False

        dashboard_id = "cvelk-main-dashboard"

        # Build all panels
        panels = [
            # Row 1: Key Metrics
            self._create_metric_panel("total-cves", "Total CVEs", "", "#6092C0", 0, 0),
            self._create_metric_panel(
                "critical-cves", "Critical Severity", "baseSeverity: CRITICAL", "#E7664C", 12, 0
            ),
            self._create_metric_panel("kev-cves", "In CISA KEV", "isKev: true", "#DA8B45", 24, 0),
            self._create_metric_panel(
                "high-epss", "High EPSS (>0.5)", "epssScore > 0.5", "#D36086", 36, 0
            ),
            # Row 2: Charts
            self._create_severity_pie_panel(),
            self._create_time_series_panel(),
            # Row 3: More Charts
            self._create_epss_distribution_panel(),
            self._create_top_cwes_panel(),
            # Row 4: Data Table
            self._create_data_table_panel(),
        ]

        dashboard_payload = {
            "attributes": {
                "title": "CVElk Vulnerability Intelligence Dashboard",
                "description": (
                    "Real-time vulnerability tracking with NVD, EPSS, " "and CISA KEV data"
                ),
                "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
                "optionsJSON": json.dumps(
                    {
                        "useMargins": True,
                        "syncColors": True,
                        "syncCursor": True,
                        "syncTooltips": True,
                        "hidePanelTitles": False,
                    }
                ),
                "panelsJSON": json.dumps(panels),
                "timeRestore": True,
                "timeTo": "now",
                "timeFrom": "now-1y",
                "refreshInterval": {"pause": False, "value": 300000},
            }
        }

        resp = self._post(
            f"/api/saved_objects/dashboard/{dashboard_id}?overwrite=true",
            dashboard_payload,
        )

        if resp.status_code in [200, 201]:
            print("  ✓ Dashboard created")
            print(f"\n📊 Dashboard URL: {self.kibana_url}/app/dashboards" f"#/view/{dashboard_id}")
            return True

        print(f"  ✗ Failed: {resp.status_code} - {resp.text[:300]}")
        return False

    def set_default_route(self) -> bool:
        """Set dashboard as the default landing page."""
        print("Setting default route...")

        payload = {"value": "/app/dashboards#/view/cvelk-main-dashboard"}
        resp = self._post("/api/kibana/settings/defaultRoute", payload)

        if resp.status_code == 200:
            print("  ✓ Default route set to dashboard")
            return True

        # Try alternative method for older Kibana versions
        version = self.get_kibana_version()
        payload = {"attributes": {"defaultRoute": "/app/dashboards#/view/cvelk-main-dashboard"}}
        resp = self._put(f"/api/saved_objects/config/{version}", payload)

        if resp.status_code == 200:
            print("  ✓ Default route set to dashboard")
            return True

        print("  ⚠ Could not set default route (optional)")
        return False

    def setup(self) -> bool:
        """Run the complete dashboard setup."""
        print("\n" + "=" * 50)
        print("CVElk Dashboard Setup")
        print("=" * 50 + "\n")

        if not self.check_connection():
            print(f"✗ Cannot connect to Kibana at {self.kibana_url}")
            return False

        version = self.get_kibana_version()
        print(f"✓ Connected to Kibana {version} at {self.kibana_url}\n")

        steps = [
            ("Data View", self.find_or_create_data_view),
            ("Dark Theme", self.set_dark_theme),
            ("Dashboard", self.create_dashboard),
            ("Default Route", self.set_default_route),
        ]

        success = True
        for name, func in steps:
            try:
                result = func()
                if result is None or (isinstance(result, bool) and not result):
                    if name in ["Dark Theme", "Default Route"]:
                        # Non-critical
                        pass
                    else:
                        success = False
            except Exception as e:
                print(f"  ✗ {name} failed: {e}")
                if name not in ["Dark Theme", "Default Route"]:
                    success = False

        print("\n" + "=" * 50)
        if success:
            print("✓ Dashboard setup complete!")
        else:
            print("⚠ Setup completed with some warnings")
        print("=" * 50 + "\n")

        return success


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Set up CVElk dashboard in Kibana")
    parser.add_argument(
        "--kibana-url",
        default="http://localhost:5601",
        help="Kibana URL (default: http://localhost:5601)",
    )
    parser.add_argument(
        "--index-name",
        default="cves",
        help="Elasticsearch index name (default: cves)",
    )

    args = parser.parse_args()

    builder = KibanaDashboardBuilder(
        kibana_url=args.kibana_url,
        index_name=args.index_name,
    )

    success = builder.setup()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
