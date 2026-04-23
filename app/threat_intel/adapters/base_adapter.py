"""Base adapter class for threat intelligence sources."""

from abc import ABC, abstractmethod
from typing import List

from ..core.models import ThreatIntelItem, SourceConfig


class BaseAdapter(ABC):
    """
    Abstract base class for threat intelligence source adapters.

    All adapters must implement the fetch() and health_check() methods
    to provide a consistent interface for retrieving threat intelligence
    from different sources (RSS feeds, APIs, databases, etc.).

    Attributes:
        source_config: Configuration for this specific source adapter
    """

    def __init__(self, source_config: SourceConfig) -> None:
        """
        Initialize the adapter with source configuration.

        Args:
            source_config: Configuration object containing source details
                          and adapter-specific settings
        """
        self.source_config = source_config

    @abstractmethod
    def fetch(self) -> List[ThreatIntelItem]:
        """
        Fetch threat intelligence items from the source.

        This method should implement the logic to connect to the source,
        retrieve data, parse it, and return a list of normalized
        ThreatIntelItem objects.

        Returns:
            List of ThreatIntelItem objects fetched from the source

        Raises:
            Exception: If the fetch operation fails. Implementations should
                      raise appropriate exceptions with descriptive messages.
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """
        Check if the source is accessible and healthy.

        This method should verify that the source can be reached and is
        responding correctly without necessarily fetching all data.

        Returns:
            True if the source is healthy and accessible, False otherwise
        """
        pass

    def get_name(self) -> str:
        """
        Get the name of this source.

        Returns:
            The configured name of this threat intelligence source
        """
        return self.source_config.name
