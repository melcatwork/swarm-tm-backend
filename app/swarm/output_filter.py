"""
Output filter — ensures high-confidence findings appear in
all run type outputs regardless of composite score.

Design principle: 'important' is defined by match_confidence
and severity from VulnMatcher output. No specific attack types
or technique IDs are checked.
"""

import logging
from typing import List, Dict, Set

logger = logging.getLogger(__name__)


def _is_path_evidence_grounded(
    path: dict,
    confirmed_vuln_ids: Set[str],
    confirmed_technique_ids: Set[str],
) -> bool:
    """
    Returns True if a path references evidence from confirmed
    vulnerability findings. Checks structural properties —
    vuln_id references and technique_id overlaps — not content.
    """
    steps = path.get('steps', [])
    path_techniques = {
        s.get('technique_id', '') for s in steps
        if s.get('technique_id')
    }
    path_vuln_refs = {
        s.get('vuln_id', '') for s in steps
        if s.get('vuln_id')
    }
    return bool(
        path_vuln_refs & confirmed_vuln_ids
        or path_techniques & confirmed_technique_ids
    )


def filter_and_rank_paths(
    paths: List[dict],
    vuln_context,
    min_composite_score: float = 5.0,
) -> List[dict]:
    """
    Separates paths into confirmed-grounded and score-filtered.
    Confirmed-grounded paths always appear, regardless of score.
    All filtering is based on vuln_id and technique_id overlap
    with confirmed findings — not on content keywords.
    """
    matched_vulns = getattr(vuln_context, 'matched_vulns', [])
    confirmed_vuln_ids = {
        v.vuln_id for v in matched_vulns
        if v.match_confidence == 'CONFIRMED'
    }
    confirmed_technique_ids = {
        v.technique_id for v in matched_vulns
        if v.match_confidence == 'CONFIRMED'
        and v.technique_id
    }

    must_include = []
    score_filtered = []

    for path in paths:
        is_grounded = _is_path_evidence_grounded(
            path, confirmed_vuln_ids, confirmed_technique_ids
        )
        composite = path.get(
            'adjusted_composite_score',
            path.get('composite_score', 0.0),
        )
        if is_grounded:
            path['grounded_in_confirmed_vuln'] = True
            path['include_reason'] = (
                'Path references confirmed vulnerability evidence'
            )
            must_include.append(path)
        elif composite >= min_composite_score:
            path['grounded_in_confirmed_vuln'] = False
            score_filtered.append(path)

    for group in (must_include, score_filtered):
        group.sort(
            key=lambda p: p.get(
                'adjusted_composite_score',
                p.get('composite_score', 0.0),
            ),
            reverse=True,
        )

    logger.info(
        f"Output filter: {len(must_include)} confirmed-grounded paths, "
        f"{len(score_filtered)} score-filtered paths"
    )
    return must_include + score_filtered


def extract_confirmed_findings_as_paths(
    vuln_context,
) -> List[dict]:
    """
    Synthesises attack paths from confirmed MatchedVulns via
    assembled chains. Safety net that is independent of LLM
    agent output. Based on chain structure, not specific attacks.
    """
    assembled_chains = getattr(
        vuln_context, 'assembled_chains', []
    )
    matched_vulns = getattr(vuln_context, 'matched_vulns', [])
    confirmed_vuln_ids = {
        v.vuln_id for v in matched_vulns
        if v.match_confidence == 'CONFIRMED'
    }

    synthesised = []
    for chain in assembled_chains:
        has_confirmed = any(
            s.vuln_id in confirmed_vuln_ids
            for s in chain.steps
            if not s.is_gap_filler and s.vuln_id
        )
        if not has_confirmed:
            continue

        steps = [
            {
                'step_number': i,
                'technique_id': s.technique_id,
                'technique_name': s.technique_name,
                'kill_chain_phase': s.phase,
                'asset_id': s.resource_id,
                'target_asset': s.resource_id,
                'vuln_id': s.vuln_id,
                'description': s.description,
                'action_description': s.description,
                'outcome': s.description,
                'exploitation_commands': s.exploitation_commands,
                'detection_gap': s.detection_gap,
                'is_gap_filler': s.is_gap_filler,
            }
            for i, s in enumerate(chain.steps, 1)
        ]
        synthesised.append({
            'id': f'confirmed-{chain.chain_id}',  # Primary ID field for consistency
            'path_id': f'confirmed-{chain.chain_id}',  # Legacy field (kept for compatibility)
            'name': chain.chain_name,
            'source': 'confirmed_vuln_synthesis',
            'grounded_in_confirmed_vuln': True,
            'include_reason': (
                'Synthesised from confirmed vulnerability '
                'evidence — guaranteed output'
            ),
            'chain_score': chain.chain_score,
            'composite_score': chain.chain_score,
            'adjusted_composite_score': chain.chain_score,
            'has_kev_vuln': chain.has_kev_vuln,
            'undetectable_steps': chain.undetectable_steps,
            'steps': steps,
            'summary': chain.summary,
        })

    logger.info(
        f"Synthesised {len(synthesised)} paths from confirmed vulnerabilities"
    )
    return synthesised


def build_confirmed_findings_summary(
    vuln_context,
) -> List[dict]:
    """
    Builds confirmed_findings from CONFIRMED MatchedVulns.
    Independent of LLM agent output. Driven by VulnMatcher
    confidence scores — not by attack type checking.
    """
    matched_vulns = getattr(vuln_context, 'matched_vulns', [])
    confirmed = [
        {
            'vuln_id': v.vuln_id,
            'name': v.name,
            'resource_id': v.resource_id,
            'resource_type': v.resource_type,
            'technique_id': v.technique_id,
            'technique_name': v.technique_name,
            'kill_chain_phase': v.kill_chain_phase,
            'risk_score': round(v.risk_score, 2),
            'cvss_score': v.cvss_score,
            'exploitation_commands': v.exploitation_commands[:3],
            'detection_gap': v.detection_gap,
            'cloudtrail_logged': v.cloudtrail_logged,
            'match_confidence': v.match_confidence,
            'match_reason': v.match_reason,
        }
        for v in matched_vulns
        if v.match_confidence == 'CONFIRMED'
    ]

    logger.info(
        f"Built confirmed findings summary: {len(confirmed)} findings"
    )
    return confirmed
