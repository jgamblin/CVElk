"""CVElk - A world-class vulnerability intelligence platform.

Import NVD, EPSS, and CISA KEV data into Elasticsearch for analysis
and visualization with Kibana.
"""

__version__ = "2.0.0"
__author__ = "Jerry Gamblin"
__email__ = "jerry@gamblin.com"

from cvelk.config import Settings

__all__ = ["Settings", "__version__"]
