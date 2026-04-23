"""IaC Serialiser for LLM-readable infrastructure representation.

Converts asset graphs and raw IaC into clean structured text that security-focused
LLMs can reason about comprehensively. Does NOT apply any rules or checks—simply
presents the IaC in the clearest possible form.
"""

from typing import Dict, List, Any


class IaCSerialiser:
    """
    Converts asset graph and raw IaC into clean structured text for LLM security analysis.

    Does not apply any rules or checks. Simply presents the IaC in the clearest
    possible form for comprehensive LLM reasoning.
    """

    def serialise(
        self,
        asset_graph: Dict[str, Any],
        raw_iac: Dict[str, Any] = None,
    ) -> str:
        """
        Serialise asset graph and optional raw IaC into LLM-readable text.

        Args:
            asset_graph: Parsed AssetGraph dictionary (from parsers)
            raw_iac: Optional raw IaC dictionary (Terraform HCL or CloudFormation)

        Returns:
            Multi-section text representation optimised for LLM comprehension
        """
        sections = []
        sections.append(self._serialise_summary(asset_graph))
        sections.append(self._serialise_resources(asset_graph))
        sections.append(self._serialise_relationships(asset_graph))

        if raw_iac:
            sections.append(self._serialise_raw_attributes(raw_iac))

        return '\n\n'.join(filter(None, sections))

    def _serialise_summary(self, graph: Dict[str, Any]) -> str:
        """Generate infrastructure summary by resource type."""
        assets = graph.get('assets', [])

        if not assets:
            return 'INFRASTRUCTURE SUMMARY:\n  No assets found'

        by_type: Dict[str, List[Dict]] = {}
        for asset in assets:
            asset_type = asset.get('type', 'unknown')
            by_type.setdefault(asset_type, []).append(asset)

        lines = ['INFRASTRUCTURE SUMMARY:']
        for rtype in sorted(by_type.keys()):
            items = by_type[rtype]
            lines.append(f'  {rtype}: {len(items)} resource(s)')

        return '\n'.join(lines)

    def _serialise_resources(self, graph: Dict[str, Any]) -> str:
        """Serialise individual resource details with all attributes."""
        assets = graph.get('assets', [])

        if not assets:
            return ''

        sections = ['RESOURCE DETAILS:']

        for asset in assets:
            rtype = asset.get('type', 'unknown')
            rid = asset.get('id', 'unnamed')

            sections.append(f'\n[{rtype}] {rid}')

            # Serialise all attributes except internal fields
            skip = {'id', 'type', 'assets', 'connections', 'relationships'}

            for key, value in asset.items():
                if key in skip:
                    continue
                if value is None or value == '' or value == []:
                    continue

                # Handle nested dictionaries and lists
                if isinstance(value, dict):
                    if value:  # Only show non-empty dicts
                        sections.append(f'  {key}:')
                        for k, v in value.items():
                            if v is not None and v != '':
                                sections.append(f'    {k}: {v}')
                elif isinstance(value, list):
                    if value:  # Only show non-empty lists
                        sections.append(f'  {key}: {", ".join(str(v) for v in value)}')
                else:
                    sections.append(f'  {key}: {value}')

        return '\n'.join(sections)

    def _serialise_relationships(self, graph: Dict[str, Any]) -> str:
        """Serialise resource relationships and connections."""
        relationships = graph.get('relationships', [])

        if not relationships:
            return ''

        lines = ['RESOURCE RELATIONSHIPS:']

        for rel in relationships:
            src = rel.get('source', '')
            tgt = rel.get('target', '')
            rel_type = rel.get('type', 'connected_to')

            # Include relationship properties if present
            props = rel.get('properties', {})
            if props:
                prop_str = ', '.join(f'{k}={v}' for k, v in props.items() if v is not None)
                lines.append(f'  {src} --[{rel_type}: {prop_str}]--> {tgt}')
            else:
                lines.append(f'  {src} --[{rel_type}]--> {tgt}')

        return '\n'.join(lines)

    def _serialise_raw_attributes(self, raw_iac: Dict[str, Any]) -> str:
        """
        Serialise raw IaC attributes for additional detail beyond parsed graph.

        This provides the LLM with original IaC attributes that may not be
        captured in the normalized asset graph.
        """
        lines = ['RAW IaC ATTRIBUTES (additional detail):']

        # Handle Terraform format (resource blocks)
        if 'resource' in raw_iac:
            for resource_type, resources in raw_iac.get('resource', {}).items():
                if not isinstance(resources, dict):
                    continue

                for resource_name, config in resources.items():
                    lines.append(f'\n{resource_type}.{resource_name}:')
                    self._flatten_config(config, lines, indent=2)

        # Handle CloudFormation format (Resources section)
        elif 'Resources' in raw_iac:
            for resource_name, resource_def in raw_iac.get('Resources', {}).items():
                resource_type = resource_def.get('Type', 'Unknown')
                lines.append(f'\n{resource_name} ({resource_type}):')

                properties = resource_def.get('Properties', {})
                if properties:
                    lines.append('  Properties:')
                    self._flatten_config(properties, lines, indent=4)

        return '\n'.join(lines)

    def _flatten_config(
        self,
        config: Any,
        lines: List[str],
        indent: int,
    ) -> None:
        """
        Recursively flatten nested configuration dictionaries and lists.

        Args:
            config: Configuration value to flatten
            lines: List to append formatted lines to
            indent: Current indentation level (spaces)
        """
        prefix = ' ' * indent

        if isinstance(config, dict):
            for k, v in config.items():
                if isinstance(v, (dict, list)):
                    lines.append(f'{prefix}{k}:')
                    self._flatten_config(v, lines, indent + 2)
                else:
                    if v is not None and v != '':
                        lines.append(f'{prefix}{k}: {v}')

        elif isinstance(config, list):
            for i, item in enumerate(config):
                if isinstance(item, (dict, list)):
                    lines.append(f'{prefix}- Item {i + 1}:')
                    self._flatten_config(item, lines, indent + 2)
                else:
                    if item is not None and item != '':
                        lines.append(f'{prefix}- {item}')

        else:
            if config is not None and config != '':
                lines.append(f'{prefix}{config}')
