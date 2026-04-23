"""
Consensus aggregator — counts technique+asset combinations across agents.

Design principle: operates on technique_id and asset_id as opaque identifiers.
Counts how often each combination appears across agents. No specific attack
types, signal names, or technique IDs are checked. Pure structural counting.
"""

import logging
from typing import List, Dict, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)


def aggregate_consensus(
    agent_paths: Dict[str, List[dict]],
) -> List[dict]:
    """
    Aggregates attack paths from multiple agents and identifies
    high-consensus techniques (discovered by multiple agents).

    Args:
        agent_paths: Dictionary mapping agent_name -> list of attack paths

    Returns:
        List of consensus findings with technique_id, asset_id, count, agents
    """
    # Count (technique_id, asset_id) pairs across all agents
    combination_counts: Dict[Tuple[str, str], Dict[str, any]] = defaultdict(
        lambda: {'count': 0, 'agents': set(), 'technique_name': '', 'paths': []}
    )

    for agent_name, paths in agent_paths.items():
        for path in paths:
            steps = path.get('steps', [])
            for step in steps:
                technique_id = step.get('technique_id', '')
                asset_id = step.get('target_asset', step.get('asset_id', ''))
                technique_name = step.get('technique_name', '')

                if not technique_id or not asset_id:
                    continue

                key = (technique_id, asset_id)
                combination_counts[key]['count'] += 1
                combination_counts[key]['agents'].add(agent_name)
                combination_counts[key]['technique_name'] = technique_name
                combination_counts[key]['paths'].append(path.get('name', ''))

    # Convert to list and sort by count
    consensus_findings = []
    for (technique_id, asset_id), data in combination_counts.items():
        consensus_findings.append({
            'technique_id': technique_id,
            'technique_name': data['technique_name'],
            'asset_id': asset_id,
            'count': data['count'],
            'agent_count': len(data['agents']),
            'agents': list(data['agents']),
            'paths': data['paths'][:5],  # Sample of paths
        })

    consensus_findings.sort(key=lambda x: x['count'], reverse=True)

    logger.info(
        f"Consensus aggregation: {len(consensus_findings)} unique "
        f"technique+asset combinations found"
    )

    return consensus_findings


def get_high_consensus_techniques(
    consensus_findings: List[dict],
    min_agent_count: int = 2,
) -> List[dict]:
    """
    Filters consensus findings to only include high-consensus
    techniques (discovered by multiple agents).

    Args:
        consensus_findings: List from aggregate_consensus()
        min_agent_count: Minimum number of agents that must discover it

    Returns:
        Filtered list of high-consensus findings
    """
    high_consensus = [
        f for f in consensus_findings
        if f['agent_count'] >= min_agent_count
    ]

    logger.info(
        f"High-consensus filter: {len(high_consensus)} findings "
        f"discovered by {min_agent_count}+ agents"
    )

    return high_consensus
