"""Feed manager for orchestrating multiple threat intelligence sources."""

import importlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import yaml

from app.utils.timezone import now_gmt8
from .models import ThreatIntelItem, SourceConfig, FeedStatus
from ..adapters.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)


class FeedManager:
    """
    Manages multiple threat intelligence feeds from various sources.

    Loads source configurations from YAML, dynamically instantiates adapter
    classes, and provides methods to fetch, combine, and manage threat
    intelligence data from all configured sources.
    """

    CONFIG_FILE = Path("app/threat_intel/config/sources.yaml")

    # Adapter class name mapping (adapter_module_name -> class_name)
    ADAPTER_CLASS_MAP = {
        "nvd_cve": "NvdCveAdapter",
        "hackernews_rss": "HackerNewsRssAdapter",
        "attack_stix": "AttackStixAdapter",
    }

    def __init__(self) -> None:
        """
        Initialize the FeedManager.

        Loads source configurations from YAML and instantiates adapter
        instances for each configured source.
        """
        self.adapters: Dict[str, BaseAdapter] = {}
        self.source_configs: List[SourceConfig] = []
        self._load_sources()

    def _load_sources(self) -> None:
        """
        Load source configurations from YAML file and instantiate adapters.

        Reads the sources.yaml configuration, creates SourceConfig objects,
        and dynamically imports and instantiates the appropriate adapter
        classes for each configured source.
        """
        try:
            if not self.CONFIG_FILE.exists():
                logger.warning(f"Config file not found: {self.CONFIG_FILE}")
                return

            with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f)

            sources = config_data.get("sources", [])
            logger.info(f"Loading {len(sources)} threat intelligence sources")

            for source_data in sources:
                try:
                    # Create SourceConfig
                    source_config = SourceConfig(**source_data)
                    self.source_configs.append(source_config)

                    # Load adapter if enabled
                    if source_config.enabled:
                        adapter = self._load_adapter(source_config)
                        if adapter:
                            self.adapters[source_config.name] = adapter
                            logger.info(f"Loaded adapter: {source_config.name}")
                        else:
                            logger.error(f"Failed to load adapter: {source_config.name}")
                    else:
                        logger.info(f"Skipping disabled source: {source_config.name}")

                except Exception as e:
                    logger.error(f"Error loading source config: {e}", exc_info=True)
                    continue

            logger.info(f"Successfully loaded {len(self.adapters)} adapters")

        except Exception as e:
            logger.error(f"Failed to load sources configuration: {e}", exc_info=True)

    def _load_adapter(self, source_config: SourceConfig) -> BaseAdapter | None:
        """
        Dynamically load and instantiate an adapter class.

        Args:
            source_config: Configuration for the source

        Returns:
            Instantiated adapter or None on failure
        """
        try:
            adapter_module_name = source_config.adapter
            adapter_class_name = self.ADAPTER_CLASS_MAP.get(adapter_module_name)

            if not adapter_class_name:
                logger.error(
                    f"Unknown adapter type: {adapter_module_name}. "
                    f"Available: {list(self.ADAPTER_CLASS_MAP.keys())}"
                )
                return None

            # Import the adapter module
            module_path = f"app.threat_intel.adapters.{adapter_module_name}"
            module = importlib.import_module(module_path)

            # Get the adapter class
            adapter_class = getattr(module, adapter_class_name)

            # Instantiate the adapter
            adapter = adapter_class(source_config)

            return adapter

        except ImportError as e:
            logger.error(f"Failed to import adapter {adapter_module_name}: {e}")
            return None
        except AttributeError as e:
            logger.error(
                f"Adapter class {adapter_class_name} not found in module: {e}"
            )
            return None
        except Exception as e:
            logger.error(f"Error instantiating adapter: {e}", exc_info=True)
            return None

    def fetch_all(self) -> List[ThreatIntelItem]:
        """
        Fetch threat intelligence from all enabled sources.

        Calls fetch() on each adapter, combines all items into a flat list,
        and deduplicates by item ID.

        Returns:
            Combined and deduplicated list of ThreatIntelItem objects
        """
        all_items = []
        seen_ids = set()

        logger.info(f"Fetching from {len(self.adapters)} sources")

        for name, adapter in self.adapters.items():
            try:
                logger.info(f"Fetching from source: {name}")
                items = adapter.fetch()

                # Deduplicate by ID
                new_items = []
                for item in items:
                    if item.id not in seen_ids:
                        seen_ids.add(item.id)
                        new_items.append(item)

                all_items.extend(new_items)
                logger.info(
                    f"Fetched {len(items)} items from {name} "
                    f"({len(new_items)} unique)"
                )

            except Exception as e:
                logger.error(f"Error fetching from {name}: {e}", exc_info=True)
                continue

        logger.info(
            f"Total fetched: {len(all_items)} unique items from "
            f"{len(self.adapters)} sources"
        )
        return all_items

    def fetch_source(self, name: str) -> List[ThreatIntelItem]:
        """
        Fetch threat intelligence from a specific named source.

        Args:
            name: Name of the source to fetch from

        Returns:
            List of ThreatIntelItem objects from the source

        Raises:
            ValueError: If source name is not found
        """
        adapter = self.adapters.get(name)

        if not adapter:
            available = list(self.adapters.keys())
            raise ValueError(
                f"Source '{name}' not found. Available sources: {available}"
            )

        logger.info(f"Fetching from source: {name}")
        try:
            items = adapter.fetch()
            logger.info(f"Fetched {len(items)} items from {name}")
            return items
        except Exception as e:
            logger.error(f"Error fetching from {name}: {e}", exc_info=True)
            raise

    def get_status(self) -> List[FeedStatus]:
        """
        Get health status of all configured sources.

        Performs health checks on all adapters and returns status information
        for each source.

        Returns:
            List of FeedStatus objects with health information
        """
        statuses = []

        for source_config in self.source_configs:
            try:
                adapter = self.adapters.get(source_config.name)

                if not adapter:
                    # Source is disabled or failed to load
                    status = FeedStatus(
                        source_name=source_config.name,
                        last_fetch=None,
                        item_count=0,
                        healthy=False,
                        error="Adapter not loaded (disabled or failed)",
                    )
                else:
                    # Perform health check
                    is_healthy = adapter.health_check()

                    status = FeedStatus(
                        source_name=source_config.name,
                        last_fetch=now_gmt8() if is_healthy else None,
                        item_count=0,  # Would need to track this separately
                        healthy=is_healthy,
                        error=None if is_healthy else "Health check failed",
                    )

                statuses.append(status)

            except Exception as e:
                logger.error(
                    f"Error checking status for {source_config.name}: {e}",
                    exc_info=True
                )
                status = FeedStatus(
                    source_name=source_config.name,
                    last_fetch=None,
                    item_count=0,
                    healthy=False,
                    error=str(e),
                )
                statuses.append(status)

        return statuses

    def add_source(self, config: SourceConfig) -> None:
        """
        Add a new threat intelligence source.

        Appends the source configuration to sources.yaml and loads the
        adapter if enabled.

        Args:
            config: SourceConfig object for the new source

        Raises:
            ValueError: If source name already exists
        """
        # Check if source already exists
        if any(s.name == config.name for s in self.source_configs):
            raise ValueError(f"Source '{config.name}' already exists")

        logger.info(f"Adding new source: {config.name}")

        # Add to in-memory list
        self.source_configs.append(config)

        # Load adapter if enabled
        if config.enabled:
            adapter = self._load_adapter(config)
            if adapter:
                self.adapters[config.name] = adapter
                logger.info(f"Loaded adapter for new source: {config.name}")

        # Save to YAML
        self._save_sources()

    def toggle_source(self, name: str, enabled: bool) -> None:
        """
        Enable or disable a threat intelligence source.

        Updates the source's enabled flag in sources.yaml and loads/unloads
        the adapter accordingly.

        Args:
            name: Name of the source to toggle
            enabled: New enabled state

        Raises:
            ValueError: If source name is not found
        """
        # Find the source config
        source_config = next(
            (s for s in self.source_configs if s.name == name),
            None
        )

        if not source_config:
            raise ValueError(f"Source '{name}' not found")

        logger.info(f"Toggling source '{name}' to enabled={enabled}")

        # Update config
        source_config.enabled = enabled

        # Load or unload adapter
        if enabled:
            if name not in self.adapters:
                adapter = self._load_adapter(source_config)
                if adapter:
                    self.adapters[name] = adapter
                    logger.info(f"Loaded adapter: {name}")
        else:
            if name in self.adapters:
                del self.adapters[name]
                logger.info(f"Unloaded adapter: {name}")

        # Save to YAML
        self._save_sources()

    def remove_source(self, name: str) -> None:
        """
        Remove a threat intelligence source.

        Removes the source from sources.yaml and unloads the adapter.

        Args:
            name: Name of the source to remove

        Raises:
            ValueError: If source name is not found
        """
        # Find the source config
        source_config = next(
            (s for s in self.source_configs if s.name == name),
            None
        )

        if not source_config:
            raise ValueError(f"Source '{name}' not found")

        logger.info(f"Removing source: {name}")

        # Remove from in-memory list
        self.source_configs.remove(source_config)

        # Unload adapter
        if name in self.adapters:
            del self.adapters[name]
            logger.info(f"Unloaded adapter: {name}")

        # Save to YAML
        self._save_sources()

    def _save_sources(self) -> None:
        """
        Save current source configurations to YAML file.

        Writes the in-memory source configs back to sources.yaml.
        """
        try:
            # Convert SourceConfig objects to dicts
            sources_data = {
                "sources": [
                    config.model_dump() for config in self.source_configs
                ]
            }

            # Ensure directory exists
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

            # Write to YAML
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                yaml.dump(sources_data, f, default_flow_style=False, sort_keys=False)

            logger.info(f"Saved {len(self.source_configs)} sources to {self.CONFIG_FILE}")

        except Exception as e:
            logger.error(f"Failed to save sources configuration: {e}", exc_info=True)
            raise
