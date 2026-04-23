"""
Persona selector — injects security-specialist personas when
high-confidence findings exist that need domain expertise.

Design principle: injection decisions are based entirely on
finding severity and confidence. No specific attack types,
signal names, or technique IDs are checked. Any HIGH or
CRITICAL confirmed finding triggers specialist injection.
"""

import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)


def _has_high_confidence_findings(vuln_context) -> bool:
    """
    Returns True if VulnContext contains any finding that is
    both HIGH/CRITICAL severity and CONFIRMED confidence.
    Does not check what type of finding it is.
    """
    # Check matched vulnerabilities
    for vuln in getattr(vuln_context, 'matched_vulns', []):
        if (vuln.match_confidence == 'CONFIRMED'
                and vuln.cvss_score >= 7.0):
            return True

    # Check cloud signals
    signals = getattr(vuln_context, 'cloud_signals', [])
    high_signals = [
        s for s in signals if s.severity in ('HIGH', 'CRITICAL')
    ]
    return len(high_signals) >= 1


def _has_privilege_escalation_findings(vuln_context) -> bool:
    """
    Returns True if any confirmed finding is in a phase
    associated with privilege escalation or lateral movement.
    Based on kill_chain_phase, not technique ID or signal name.
    """
    escalation_phases = {
        'privilege_escalation',
        'lateral_movement',
        'credential_access',
    }
    for vuln in getattr(vuln_context, 'matched_vulns', []):
        if (vuln.match_confidence == 'CONFIRMED'
                and vuln.kill_chain_phase in escalation_phases):
            return True
    return False


def _get_specialist_personas(
    needed_type: str,
    all_available: List[str],
) -> List[str]:
    """
    Returns personas suited to a finding type.
    The mapping here is persona expertise, not detection rules.
    cloud_native_attacker is always the first choice for any
    cloud infrastructure finding.
    """
    cloud_specialists = [
        'cloud_native_attacker',
        'apt29_cozy_bear',
        'volt_typhoon',
    ]
    lateral_specialists = [
        'cloud_native_attacker',
        'lateral_movement_specialist',
        'insider_threat',
    ]
    if needed_type == 'cloud':
        candidates = cloud_specialists
    elif needed_type == 'lateral':
        candidates = lateral_specialists
    else:
        candidates = cloud_specialists

    return [p for p in candidates if p in all_available]


def select_personas_for_context(
    requested_personas: List[str],
    vuln_context,
    run_type: str,
    all_available_personas: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Augments persona list based on finding severity and
    confidence. Returns (final_personas, injected_personas).

    Injection logic:
    - Any HIGH/CRITICAL confirmed finding → inject cloud specialist
    - Any privilege escalation / lateral movement finding →
      inject lateral specialist
    - Single and quick runs: cap at 3 personas total
    - Multi and stigmergic: all personas run, no cap
    """
    result = list(requested_personas)
    injected = []

    if _has_high_confidence_findings(vuln_context):
        candidates = _get_specialist_personas(
            'cloud', all_available_personas
        )
        for persona_id in candidates:
            if persona_id not in result:
                result.append(persona_id)
                injected.append(persona_id)
                logger.info(
                    f"Injected {persona_id} for high-confidence findings"
                )
                break

    if _has_privilege_escalation_findings(vuln_context):
        candidates = _get_specialist_personas(
            'lateral', all_available_personas
        )
        for persona_id in candidates:
            if persona_id not in result:
                result.append(persona_id)
                injected.append(persona_id)
                logger.info(
                    f"Injected {persona_id} for privilege escalation findings"
                )
                break

    if run_type in ('single', 'quick'):
        if len(result) > 3:
            logger.info(
                f"Capping personas at 3 for {run_type} run "
                f"(was {len(result)})"
            )
            result = result[:3]
            injected = [p for p in injected if p in result]

    return result, injected


def get_persona_priority_order(
    personas: List[str],
    vuln_context,
) -> List[str]:
    """
    Moves specialist personas to run first when high-confidence
    findings exist. Not based on finding type — based on whether
    specialist knowledge would help reason about what was found.
    """
    if not _has_high_confidence_findings(vuln_context):
        return personas

    specialists = {
        'cloud_native_attacker', 'apt29_cozy_bear', 'volt_typhoon',
        'lateral_movement_specialist',
    }
    priority = [p for p in personas if p in specialists]
    remainder = [p for p in personas if p not in specialists]
    return priority + remainder
