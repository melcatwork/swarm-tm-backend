"""NVD CVE adapter for fetching vulnerability data from the National Vulnerability Database."""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import List

import requests

from app.utils.timezone import now_gmt8
from ..core.models import ThreatIntelItem, SourceConfig
from .base_adapter import BaseAdapter

logger = logging.getLogger(__name__)


class NvdCveAdapter(BaseAdapter):
    """
    Adapter for fetching CVE data from the National Vulnerability Database (NVD) API.

    Fetches recent CVE entries published within the last 7 days and transforms
    them into normalized ThreatIntelItem objects.
    """

    API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 30
    RATE_LIMIT_RETRY_DELAY = 30

    def __init__(self, source_config: SourceConfig) -> None:
        """
        Initialize the NVD CVE adapter.

        Args:
            source_config: Configuration for this NVD source
        """
        super().__init__(source_config)

    def fetch(self) -> List[ThreatIntelItem]:
        """
        Fetch recent CVE data from the NVD API.

        Retrieves CVEs published in the last 7 days and converts them into
        ThreatIntelItem objects. Handles rate limiting with automatic retry.

        Returns:
            List of ThreatIntelItem objects representing CVEs

        Raises:
            Exception: Logs errors but returns empty list on failure
        """
        # Calculate date range (last 7 days)
        end_date = now_gmt8()
        start_date = end_date - timedelta(days=7)

        # Format dates as ISO 8601 strings
        pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "resultsPerPage": 20,
            "startIndex": 0,
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
        }

        try:
            response = self._make_request(params)

            if response is None:
                return []

            # Parse JSON response
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            logger.info(
                f"Fetched {len(vulnerabilities)} CVEs from NVD for {self.get_name()}"
            )

            # Transform CVE data into ThreatIntelItem objects
            items = []
            for vuln_entry in vulnerabilities:
                try:
                    item = self._parse_cve(vuln_entry)
                    if item:
                        items.append(item)
                except Exception as e:
                    logger.error(f"Error parsing CVE entry: {e}", exc_info=True)
                    continue

            return items

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CVEs from NVD: {e}", exc_info=True)
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching CVEs from NVD: {e}", exc_info=True)
            return []

    def _make_request(self, params: dict, retry: bool = True) -> requests.Response | None:
        """
        Make HTTP request to NVD API with rate limiting support.

        Args:
            params: Query parameters for the request
            retry: Whether to retry on rate limit (403)

        Returns:
            Response object or None on failure
        """
        try:
            response = requests.get(
                self.API_BASE_URL,
                params=params,
                timeout=self.REQUEST_TIMEOUT,
            )

            # Handle rate limiting
            if response.status_code == 403 and retry:
                logger.warning(
                    f"Rate limited by NVD API, sleeping {self.RATE_LIMIT_RETRY_DELAY}s and retrying"
                )
                time.sleep(self.RATE_LIMIT_RETRY_DELAY)
                return self._make_request(params, retry=False)

            response.raise_for_status()
            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"Request to NVD API failed: {e}")
            return None

    def _parse_cve(self, vuln_entry: dict) -> ThreatIntelItem | None:
        """
        Parse a CVE entry from NVD API response into a ThreatIntelItem.

        Args:
            vuln_entry: Raw CVE data from NVD API

        Returns:
            ThreatIntelItem object or None if parsing fails
        """
        try:
            cve_data = vuln_entry.get("cve", {})

            # Extract CVE ID
            cve_id = cve_data.get("id", "")
            if not cve_id:
                logger.warning("CVE entry missing ID, skipping")
                return None

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            if descriptions:
                description = descriptions[0].get("value", "")

            # Create title (CVE ID + first 100 chars of description)
            title = cve_id
            if description:
                desc_preview = description[:100]
                if len(description) > 100:
                    desc_preview += "..."
                title = f"{cve_id}: {desc_preview}"

            # Extract published date
            published_str = cve_data.get("published", "")
            try:
                published = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published = now_gmt8()
                logger.warning(f"Invalid published date for {cve_id}, using current time")

            # Extract severity from CVSS v3.1 metrics
            severity = self._extract_severity(cve_data)

            # Extract tags from affected products
            tags = self._extract_product_tags(cve_data)

            # Build URL
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Create ThreatIntelItem
            item = ThreatIntelItem(
                id=cve_id,
                title=title,
                summary=description,
                source="NVD",
                url=url,
                published=published,
                category="cve",
                severity=severity,
                tags=tags,
                cves=[cve_id],
                ttps=[],  # CVEs don't directly map to MITRE ATT&CK TTPs
                raw_data=vuln_entry,
            )

            return item

        except Exception as e:
            logger.error(f"Error parsing CVE entry: {e}", exc_info=True)
            return None

    def _extract_severity(self, cve_data: dict) -> str:
        """
        Extract severity level from CVSS metrics.

        Prioritizes CVSS v3.1, falls back to v3.0, then v2.0.

        Args:
            cve_data: CVE data dictionary

        Returns:
            Severity string: "critical", "high", "medium", "low", or "info"
        """
        metrics = cve_data.get("metrics", {})

        # Try CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            base_severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "")
            if base_severity:
                return base_severity.lower()

        # Try CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            base_severity = cvss_v30[0].get("cvssData", {}).get("baseSeverity", "")
            if base_severity:
                return base_severity.lower()

        # Try CVSS v2.0 (map to our severity levels)
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            base_score = cvss_v2[0].get("cvssData", {}).get("baseScore", 0)
            if base_score >= 9.0:
                return "critical"
            elif base_score >= 7.0:
                return "high"
            elif base_score >= 4.0:
                return "medium"
            elif base_score > 0:
                return "low"

        # Default to medium if no severity found
        return "medium"

    def _extract_product_tags(self, cve_data: dict) -> List[str]:
        """
        Extract product names from CVE configurations for use as tags.

        Args:
            cve_data: CVE data dictionary

        Returns:
            List of product name tags
        """
        tags = set()

        try:
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for cpe_match in cpe_matches:
                        # CPE format: cpe:2.3:part:vendor:product:version:...
                        cpe_uri = cpe_match.get("criteria", "")
                        if cpe_uri:
                            parts = cpe_uri.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                if vendor and vendor != "*":
                                    tags.add(vendor)
                                if product and product != "*":
                                    tags.add(product)

        except Exception as e:
            logger.warning(f"Error extracting product tags: {e}")

        return list(tags)[:10]  # Limit to 10 tags

    def health_check(self) -> bool:
        """
        Check if the NVD API is accessible and responding.

        Returns:
            True if the API is healthy (status < 400), False otherwise
        """
        try:
            response = requests.head(
                self.API_BASE_URL,
                timeout=self.REQUEST_TIMEOUT,
            )
            is_healthy = response.status_code < 400
            if is_healthy:
                logger.info(f"Health check passed for {self.get_name()}")
            else:
                logger.warning(
                    f"Health check failed for {self.get_name()}: "
                    f"status {response.status_code}"
                )
            return is_healthy

        except requests.exceptions.RequestException as e:
            logger.error(f"Health check failed for {self.get_name()}: {e}")
            return False
