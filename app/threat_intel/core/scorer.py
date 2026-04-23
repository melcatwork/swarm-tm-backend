"""Citation scorer for ranking threat intelligence items by importance."""

import logging
from datetime import datetime, timedelta, timezone
from typing import List

from app.utils.timezone import now_gmt8
from .models import ThreatIntelItem

logger = logging.getLogger(__name__)


class CitationScorer:
    """
    Scores and ranks threat intelligence items by relevance and importance.

    Calculates citation scores based on severity, recency, and cross-source
    references to help prioritize which threat intelligence items are most
    critical for threat modeling.
    """

    # Severity weights
    SEVERITY_WEIGHTS = {
        "critical": 5.0,
        "high": 3.0,
        "medium": 1.5,
        "low": 0.5,
        "info": 0.2,
    }

    # Cross-reference bonus per matching item
    CROSS_REFERENCE_BONUS = 2.0

    # Base score for all items
    BASE_SCORE = 1.0

    def score_items(self, items: List[ThreatIntelItem]) -> List[ThreatIntelItem]:
        """
        Calculate citation scores for threat intelligence items and sort by score.

        Scoring algorithm:
        - Base score: 1.0
        - Severity weight: critical=5.0, high=3.0, medium=1.5, low=0.5, info=0.2
        - Recency weight: today=3.0, yesterday=2.0, this week=1.0, older=0.5
        - Cross-source bonus: +2.0 per item sharing same CVEs or similar title
        - Raw score = (base * severity * recency) + cross_source_bonus
        - Final score: normalized to 0-10 scale

        Args:
            items: List of ThreatIntelItem objects to score

        Returns:
            Sorted list of ThreatIntelItem objects (highest score first)
        """
        if not items:
            return []

        logger.info(f"Scoring {len(items)} threat intelligence items")

        # Calculate raw scores
        scored_items = []
        raw_scores = []
        for item in items:
            try:
                # Calculate severity weight
                severity_weight = self.SEVERITY_WEIGHTS.get(
                    item.severity,
                    self.SEVERITY_WEIGHTS["medium"]
                )

                # Calculate recency weight
                recency_weight = self._calculate_recency_weight(item.published)

                # Calculate cross-source bonus
                cross_source_bonus = self._calculate_cross_source_bonus(item, items)

                # Calculate raw score
                raw_score = (
                    self.BASE_SCORE * severity_weight * recency_weight
                    + cross_source_bonus
                )

                raw_scores.append(raw_score)
                scored_items.append(item)

            except Exception as e:
                logger.error(f"Error scoring item {item.id}: {e}", exc_info=True)
                # Add with default score
                raw_scores.append(self.BASE_SCORE)
                scored_items.append(item)

        # Normalize scores to 0-10 scale
        if raw_scores:
            min_score = min(raw_scores)
            max_score = max(raw_scores)

            # If all scores are the same, set them all to 5.0
            if max_score == min_score:
                for item in scored_items:
                    item.citation_score = 5.0
            else:
                # Normalize to 0-10 scale
                for item, raw_score in zip(scored_items, raw_scores):
                    normalized = 10.0 * (raw_score - min_score) / (max_score - min_score)
                    item.citation_score = round(normalized, 1)

        # Sort by citation_score descending
        scored_items.sort(key=lambda x: x.citation_score, reverse=True)

        logger.info(
            f"Scored {len(scored_items)} items. "
            f"Top score: {scored_items[0].citation_score if scored_items else 0}"
        )

        return scored_items

    def _calculate_recency_weight(self, published: datetime) -> float:
        """
        Calculate weight based on how recently the item was published.

        Args:
            published: Publication datetime

        Returns:
            Recency weight: today=3.0, yesterday=2.0, this week=1.0, older=0.5
        """
        now = now_gmt8()

        # Ensure published datetime is timezone-aware
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)

        # Calculate time difference
        age = now - published

        # Today (last 24 hours)
        if age < timedelta(days=1):
            return 3.0

        # Yesterday (1-2 days ago)
        if age < timedelta(days=2):
            return 2.0

        # This week (last 7 days)
        if age < timedelta(days=7):
            return 1.0

        # Older
        return 0.5

    def _calculate_cross_source_bonus(
        self,
        item: ThreatIntelItem,
        all_items: List[ThreatIntelItem]
    ) -> float:
        """
        Calculate bonus for items that are referenced by multiple sources.

        Checks for cross-references by:
        1. Matching CVE IDs between items
        2. Similar titles (first 50 characters match)

        Args:
            item: Item to calculate bonus for
            all_items: All items to check for cross-references

        Returns:
            Cross-reference bonus (2.0 per matching item)
        """
        cross_references = 0

        # Get item's identifying characteristics
        item_cves = set(item.cves)
        item_title_prefix = self._normalize_title(item.title[:50])

        for other_item in all_items:
            # Skip self
            if other_item.id == item.id:
                continue

            # Skip items from same source
            if other_item.source == item.source:
                continue

            # Check for CVE matches
            if item_cves and item_cves.intersection(other_item.cves):
                cross_references += 1
                continue

            # Check for similar titles (fuzzy match on first 50 chars)
            other_title_prefix = self._normalize_title(other_item.title[:50])
            if self._titles_similar(item_title_prefix, other_title_prefix):
                cross_references += 1

        # Calculate bonus
        bonus = cross_references * self.CROSS_REFERENCE_BONUS

        return bonus

    def _normalize_title(self, title: str) -> str:
        """
        Normalize title for comparison.

        Args:
            title: Title string

        Returns:
            Normalized title (lowercase, stripped)
        """
        return title.lower().strip()

    def _titles_similar(self, title1: str, title2: str) -> bool:
        """
        Check if two titles are similar enough to be considered cross-references.

        Args:
            title1: First title (normalized)
            title2: Second title (normalized)

        Returns:
            True if titles are similar, False otherwise
        """
        # Simple exact match on first 50 chars (already normalized)
        if not title1 or not title2:
            return False

        # Require at least 20 characters for matching
        if len(title1) < 20 or len(title2) < 20:
            return False

        # Check if they start with the same text
        return title1 == title2
