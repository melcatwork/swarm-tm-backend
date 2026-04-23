"""Hacker News RSS adapter for fetching security news from The Hacker News feed."""

import logging
import re
from datetime import datetime, timezone
from time import struct_time
from typing import List

import feedparser

from app.utils.timezone import now_gmt8
from ..core.models import ThreatIntelItem, SourceConfig
from .base_adapter import BaseAdapter

logger = logging.getLogger(__name__)


class HackerNewsRssAdapter(BaseAdapter):
    """
    Adapter for fetching security news from The Hacker News RSS feed.

    Parses RSS entries and extracts CVE IDs, ATT&CK TTPs, and security-related
    keywords to create normalized ThreatIntelItem objects.
    """

    DEFAULT_FEED_URL = "https://feeds.feedburner.com/TheHackersNews"

    # Regex patterns for extraction
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
    HTML_TAG_PATTERN = re.compile(r"<[^>]+>")

    # Keywords for classification
    CVE_KEYWORDS = {"cve", "vulnerability", "flaw", "exploit", "patch"}
    INCIDENT_KEYWORDS = {"breach", "attack", "hack", "compromised", "leaked", "stolen"}
    CRITICAL_KEYWORDS = {"critical", "zero-day", "0-day", "zeroday"}
    HIGH_KEYWORDS = {"ransomware", "breach", "supply chain", "supply-chain"}
    COMMON_TAGS = {
        "ransomware", "phishing", "apt", "zero-day", "malware",
        "ddos", "botnet", "backdoor", "trojan", "spyware"
    }

    def __init__(self, source_config: SourceConfig) -> None:
        """
        Initialize the Hacker News RSS adapter.

        Args:
            source_config: Configuration for this RSS feed source
        """
        super().__init__(source_config)
        self.feed_url = self.source_config.config.get("feed_url", self.DEFAULT_FEED_URL)

    def fetch(self) -> List[ThreatIntelItem]:
        """
        Fetch security news items from The Hacker News RSS feed.

        Parses the RSS feed, extracts relevant security information including
        CVEs and ATT&CK TTPs, and categorizes each item based on content.

        Returns:
            List of ThreatIntelItem objects representing news articles

        Raises:
            Exception: Logs errors but returns empty list on failure
        """
        try:
            logger.info(f"Fetching RSS feed from {self.feed_url} for {self.get_name()}")

            # Parse the RSS feed
            feed = feedparser.parse(self.feed_url)

            if feed.bozo:
                logger.warning(
                    f"Feed parser encountered an error: {feed.bozo_exception}"
                )

            entries = feed.get("entries", [])
            logger.info(f"Found {len(entries)} entries in RSS feed for {self.get_name()}")

            items = []
            for entry in entries:
                try:
                    item = self._parse_entry(entry)
                    if item:
                        items.append(item)
                except Exception as e:
                    logger.error(f"Error parsing RSS entry: {e}", exc_info=True)
                    continue

            logger.info(f"Successfully parsed {len(items)} items from {self.get_name()}")
            return items

        except Exception as e:
            logger.error(f"Failed to fetch RSS feed from {self.feed_url}: {e}", exc_info=True)
            return []

    def _parse_entry(self, entry: dict) -> ThreatIntelItem | None:
        """
        Parse a single RSS entry into a ThreatIntelItem.

        Args:
            entry: RSS entry dictionary from feedparser

        Returns:
            ThreatIntelItem object or None if parsing fails
        """
        try:
            # Extract basic fields
            entry_id = entry.get("id", entry.get("link", ""))
            if not entry_id:
                logger.warning("RSS entry missing ID and link, skipping")
                return None

            title = entry.get("title", "Untitled")
            link = entry.get("link", "")

            # Extract and clean summary
            raw_summary = entry.get("summary", entry.get("description", ""))
            summary = self._clean_html(raw_summary)
            summary = summary[:500]  # Truncate to 500 chars

            # Parse published date
            published = self._parse_published_date(entry)

            # Combine title and summary for analysis
            content = f"{title} {summary}".lower()

            # Extract CVE IDs and TTPs
            cves = self._extract_cves(content)
            ttps = self._extract_ttps(content)

            # Infer category and severity
            category = self._infer_category(content, cves)
            severity = self._infer_severity(content)

            # Extract tags
            tags = self._extract_tags(content, cves, ttps)

            # Create ThreatIntelItem
            item = ThreatIntelItem(
                id=entry_id,
                title=title,
                summary=summary,
                source=self.get_name(),
                url=link,
                published=published,
                category=category,
                severity=severity,
                tags=tags,
                cves=cves,
                ttps=ttps,
                raw_data=dict(entry),
            )

            return item

        except Exception as e:
            logger.error(f"Error parsing RSS entry: {e}", exc_info=True)
            return None

    def _clean_html(self, text: str) -> str:
        """
        Remove HTML tags from text.

        Args:
            text: Raw HTML text

        Returns:
            Cleaned text with HTML tags removed
        """
        if not text:
            return ""

        # Remove HTML tags
        cleaned = self.HTML_TAG_PATTERN.sub("", text)

        # Clean up whitespace
        cleaned = " ".join(cleaned.split())

        return cleaned

    def _parse_published_date(self, entry: dict) -> datetime:
        """
        Parse published date from RSS entry.

        Args:
            entry: RSS entry dictionary

        Returns:
            Datetime object for the published date
        """
        try:
            # Try to get published_parsed (time struct)
            time_struct = entry.get("published_parsed")

            if time_struct and isinstance(time_struct, struct_time):
                # Convert struct_time to datetime
                return datetime(*time_struct[:6], tzinfo=timezone.utc)

            # Try to parse published string
            published_str = entry.get("published", "")
            if published_str:
                # feedparser usually provides parsed time, but fallback to string parsing
                return datetime.fromisoformat(published_str.replace("Z", "+00:00"))

        except Exception as e:
            logger.warning(f"Error parsing published date: {e}")

        # Default to current time if parsing fails
        return now_gmt8()

    def _extract_cves(self, content: str) -> List[str]:
        """
        Extract CVE identifiers from content.

        Args:
            content: Text content to search

        Returns:
            List of unique CVE IDs found
        """
        matches = self.CVE_PATTERN.findall(content)
        # Normalize to uppercase and deduplicate
        return list(set(cve.upper() for cve in matches))

    def _extract_ttps(self, content: str) -> List[str]:
        """
        Extract MITRE ATT&CK technique IDs from content.

        Args:
            content: Text content to search

        Returns:
            List of unique TTP IDs found
        """
        matches = self.TTP_PATTERN.findall(content)
        # Deduplicate
        return list(set(matches))

    def _infer_category(self, content: str, cves: List[str]) -> str:
        """
        Infer the category of the item based on content.

        Args:
            content: Lowercase content text
            cves: List of extracted CVE IDs

        Returns:
            Category string: "cve", "incident", or "news"
        """
        # If CVEs are mentioned, it's likely a CVE item
        if cves:
            return "cve"

        # Check for CVE-related keywords
        if any(keyword in content for keyword in self.CVE_KEYWORDS):
            return "cve"

        # Check for incident keywords
        if any(keyword in content for keyword in self.INCIDENT_KEYWORDS):
            return "incident"

        # Default to news
        return "news"

    def _infer_severity(self, content: str) -> str:
        """
        Infer severity level based on keywords in content.

        Args:
            content: Lowercase content text

        Returns:
            Severity string: "critical", "high", or "medium"
        """
        # Check for critical keywords
        if any(keyword in content for keyword in self.CRITICAL_KEYWORDS):
            return "critical"

        # Check for high severity keywords
        if any(keyword in content for keyword in self.HIGH_KEYWORDS):
            return "high"

        # Default to medium
        return "medium"

    def _extract_tags(self, content: str, cves: List[str], ttps: List[str]) -> List[str]:
        """
        Extract relevant security tags from content.

        Args:
            content: Lowercase content text
            cves: List of CVE IDs (already extracted)
            ttps: List of TTP IDs (already extracted)

        Returns:
            List of relevant tags
        """
        tags = set()

        # Add common security keywords found in content
        for keyword in self.COMMON_TAGS:
            if keyword in content:
                tags.add(keyword)

        # Limit to reasonable number of tags
        return list(tags)[:15]

    def health_check(self) -> bool:
        """
        Check if the RSS feed is accessible and valid.

        Returns:
            True if the feed is healthy (parseable and has entries), False otherwise
        """
        try:
            logger.info(f"Running health check for {self.get_name()} on {self.feed_url}")

            feed = feedparser.parse(self.feed_url)

            # Check if feed parsed without errors
            if feed.bozo:
                logger.warning(
                    f"Health check failed for {self.get_name()}: "
                    f"Feed parser error - {feed.bozo_exception}"
                )
                return False

            # Check if feed has entries
            entries = feed.get("entries", [])
            if not entries:
                logger.warning(
                    f"Health check failed for {self.get_name()}: "
                    f"Feed has no entries"
                )
                return False

            logger.info(
                f"Health check passed for {self.get_name()}: "
                f"Found {len(entries)} entries"
            )
            return True

        except Exception as e:
            logger.error(f"Health check failed for {self.get_name()}: {e}", exc_info=True)
            return False
