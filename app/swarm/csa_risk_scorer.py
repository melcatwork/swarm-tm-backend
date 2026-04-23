"""
CSA CII 5×5 Risk Matrix Scorer

Implements the Singapore Cyber Security Agency (CSA)
Critical Information Infrastructure (CII) Risk Assessment
Guide (February 2021) Section 4.2 — Risk Assessment Methodology.

The 5×5 risk matrix combines:
- Likelihood (1-5): Derived from Discoverability, Exploitability, Reproducibility
- Impact (1-5): User-configured data classification level
- Risk Level (1-25): Likelihood × Impact

Risk bands and tolerance actions follow CSA CII guidelines.
"""

import logging
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ImpactLevel(Enum):
    """CSA CII Impact classification levels (Section 4.2, Task B)."""
    NEGLIGIBLE = 1  # Public data, negligible effect
    MINOR = 2       # Official data, limited adverse effect
    MODERATE = 3    # Restricted data, some adverse effect
    SEVERE = 4      # Confidential data, serious adverse effect
    VERY_SEVERE = 5 # Top Secret, exceptionally grave adverse effect


class LikelihoodLevel(Enum):
    """CSA CII Likelihood levels (Section 4.2, Task A)."""
    VERY_LOW = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    VERY_HIGH = 5


class RiskBand(Enum):
    """CSA CII Risk bands with tolerance actions."""
    LOW = "Low"
    MEDIUM = "Medium"
    MEDIUM_HIGH = "Medium-High"
    HIGH = "High"
    VERY_HIGH = "Very High"


# CSA CII 5×5 Risk Matrix Lookup Table
# Risk Level = Likelihood (rows) × Impact (columns)
RISK_MATRIX = {
    # Likelihood: VERY_LOW (1)
    (1, 1): (1, RiskBand.LOW),
    (1, 2): (2, RiskBand.LOW),
    (1, 3): (3, RiskBand.LOW),
    (1, 4): (4, RiskBand.MEDIUM),
    (1, 5): (5, RiskBand.MEDIUM),

    # Likelihood: LOW (2)
    (2, 1): (2, RiskBand.LOW),
    (2, 2): (4, RiskBand.MEDIUM),
    (2, 3): (6, RiskBand.MEDIUM),
    (2, 4): (8, RiskBand.MEDIUM_HIGH),
    (2, 5): (10, RiskBand.HIGH),

    # Likelihood: MODERATE (3)
    (3, 1): (3, RiskBand.LOW),
    (3, 2): (6, RiskBand.MEDIUM),
    (3, 3): (9, RiskBand.MEDIUM_HIGH),
    (3, 4): (12, RiskBand.HIGH),
    (3, 5): (15, RiskBand.HIGH),

    # Likelihood: HIGH (4)
    (4, 1): (4, RiskBand.MEDIUM),
    (4, 2): (8, RiskBand.MEDIUM_HIGH),
    (4, 3): (12, RiskBand.HIGH),
    (4, 4): (16, RiskBand.HIGH),
    (4, 5): (20, RiskBand.VERY_HIGH),

    # Likelihood: VERY_HIGH (5)
    (5, 1): (5, RiskBand.MEDIUM),
    (5, 2): (10, RiskBand.HIGH),
    (5, 3): (15, RiskBand.HIGH),
    (5, 4): (20, RiskBand.VERY_HIGH),
    (5, 5): (25, RiskBand.VERY_HIGH),
}


# Risk tolerance action recommendations per band
RISK_TOLERANCE_ACTIONS = {
    RiskBand.VERY_HIGH: (
        "Cannot be accepted. Activity must cease immediately or "
        "mitigation applied immediately. Escalate to senior management."
    ),
    RiskBand.HIGH: (
        "Cannot be accepted. Treatment strategies must be developed "
        "and implemented within 1 month. Requires management approval."
    ),
    RiskBand.MEDIUM_HIGH: (
        "Cannot be accepted. Treatment strategies must be developed "
        "and implemented within 3-6 months."
    ),
    RiskBand.MEDIUM: (
        "Can be accepted with regular monitoring if no cost-effective "
        "treatment exists. Residual risk must be documented."
    ),
    RiskBand.LOW: (
        "Can be accepted with periodic monitoring. Document acceptance decision."
    ),
}


# Impact label descriptors
IMPACT_LABELS = {
    1: "Negligible",
    2: "Minor",
    3: "Moderate",
    4: "Severe",
    5: "Very Severe",
}


# Likelihood label descriptors
LIKELIHOOD_LABELS = {
    1: "Very Low",
    2: "Low",
    3: "Moderate",
    4: "High",
    5: "Very High",
}


def calculate_likelihood_from_der(
    discoverability: int,
    exploitability: int,
    reproducibility: int,
) -> tuple[int, str]:
    """
    Calculate likelihood score (1-5) from D/E/R sub-factors.

    Per CSA CII guidance, likelihood is the average of three factors,
    rounded to nearest integer:
    - Discoverability: How easy to find the vulnerability/path
    - Exploitability: How easy to exploit successfully
    - Reproducibility: How reliably the attack can be repeated

    Args:
        discoverability: Score 1-5
        exploitability: Score 1-5
        reproducibility: Score 1-5

    Returns:
        Tuple of (likelihood_score, likelihood_label)
    """
    avg = (discoverability + exploitability + reproducibility) / 3.0
    likelihood_score = round(avg)
    likelihood_score = max(1, min(5, likelihood_score))  # Clamp to 1-5

    likelihood_label = LIKELIHOOD_LABELS[likelihood_score]

    logger.debug(
        f"Likelihood from D:{discoverability} E:{exploitability} "
        f"R:{reproducibility} = {likelihood_score} ({likelihood_label})"
    )

    return likelihood_score, likelihood_label


def estimate_discoverability(path: Dict[str, Any]) -> tuple[int, str]:
    """
    Estimate discoverability (1-5) from attack path characteristics.

    Factors:
    - Internet-facing assets = easier to discover (4-5)
    - Internal assets with initial access = moderate (3)
    - Deep internal assets = harder (1-2)
    - Reconnaissance techniques = easier (4-5)

    Returns:
        Tuple of (score, rationale)
    """
    steps = path.get('steps', [])
    if not steps:
        return 3, "No steps available for assessment"

    # Check for initial access techniques (easier to discover)
    first_step = steps[0]
    first_technique = first_step.get('technique_id', '')
    first_phase = first_step.get('kill_chain_phase', '')

    # Internet-facing initial access = high discoverability
    if 'Initial Access' in first_phase or first_technique.startswith('T1190'):
        return 4, "Internet-facing initial access point — easily discoverable via reconnaissance"

    # Reconnaissance or lateral movement = moderate-high
    if 'Reconnaissance' in first_phase:
        return 4, "Begins with reconnaissance phase — discoverable with network scanning"

    # Phishing or credential access = moderate
    if first_technique.startswith('T1566') or 'credential' in first_step.get('technique_name', '').lower():
        return 3, "Requires social engineering or credential access — moderately discoverable"

    # Deep lateral movement = lower discoverability
    if len(steps) >= 5 and 'Lateral Movement' in first_phase:
        return 2, "Requires significant lateral movement — less discoverable without initial foothold"

    # Default: moderate discoverability
    return 3, "Standard attack path with moderate discoverability"


def estimate_exploitability(path: Dict[str, Any]) -> tuple[int, str]:
    """
    Estimate exploitability (1-5) from attack path characteristics.

    Factors:
    - Confirmed vulnerabilities (from vuln_id) = high (4-5)
    - Number of steps (complexity) = inversely related
    - Evaluation scores (if available) = direct correlation

    Returns:
        Tuple of (score, rationale)
    """
    steps = path.get('steps', [])
    evaluation = path.get('evaluation', {})

    # Use existing feasibility score if available
    feasibility = evaluation.get('feasibility_score')
    if feasibility:
        # Map 0-10 feasibility to 1-5 exploitability
        exploitability_score = max(1, min(5, round(feasibility / 2)))
        return exploitability_score, f"Derived from feasibility score {feasibility}/10"

    # Check for confirmed vulnerabilities
    has_confirmed_vuln = any(
        step.get('vuln_id') for step in steps
    )
    if has_confirmed_vuln:
        return 5, "Path includes confirmed vulnerability with exploit code — highly exploitable"

    # Complexity check (more steps = harder to exploit)
    num_steps = len(steps)
    if num_steps <= 3:
        return 4, f"Short attack path ({num_steps} steps) — relatively easy to execute"
    elif num_steps <= 5:
        return 3, f"Moderate complexity ({num_steps} steps) — requires coordination"
    else:
        return 2, f"Complex attack path ({num_steps} steps) — significant technical skill required"


def estimate_reproducibility(path: Dict[str, Any]) -> tuple[int, str]:
    """
    Estimate reproducibility (1-5) from attack path characteristics.

    Factors:
    - Detection difficulty (higher = more reproducible)
    - Persistence techniques = higher reproducibility
    - Time-dependent steps = lower reproducibility

    Returns:
        Tuple of (score, rationale)
    """
    steps = path.get('steps', [])
    evaluation = path.get('evaluation', {})

    # Use detection difficulty as proxy for reproducibility
    detection_score = evaluation.get('detection_score')
    if detection_score:
        # Map 0-10 detection difficulty to 1-5 reproducibility
        reproducibility_score = max(1, min(5, round(detection_score / 2)))
        return reproducibility_score, f"Low detection risk (score {detection_score}/10) enables reliable reproduction"

    # Check for persistence techniques (high reproducibility)
    has_persistence = any(
        'persistence' in step.get('kill_chain_phase', '').lower()
        for step in steps
    )
    if has_persistence:
        return 4, "Includes persistence mechanisms — attack can be reliably repeated"

    # Check for covering tracks (suggests reproducibility concerns)
    has_covering_tracks = any(
        'covering' in step.get('kill_chain_phase', '').lower()
        for step in steps
    )
    if has_covering_tracks:
        return 3, "Includes evasion techniques — moderate reproducibility with operational security"

    # Default: moderate reproducibility
    return 3, "Standard attack techniques with moderate reproducibility"


def derive_cia_classification(steps: List[Dict[str, Any]]) -> List[str]:
    """
    Derive CIA impact classification from kill chain phases.

    Maps kill chain phases to CIA triad impacts:
    - Confidentiality: credential_access, discovery, collection, exfiltration
    - Integrity: execution, persistence, defense_evasion, impact
    - Availability: initial_access, lateral_movement, impact

    Args:
        steps: Attack path steps with kill_chain_phase

    Returns:
        List of impacted CIA components (e.g., ['Confidentiality', 'Integrity'])
    """
    cia_map = {
        'initial_access': ['Availability'],
        'reconnaissance': ['Availability'],
        'execution': ['Integrity', 'Availability'],
        'persistence': ['Integrity', 'Availability'],
        'privilege_escalation': ['Integrity', 'Availability'],
        'defense_evasion': ['Integrity'],
        'credential_access': ['Confidentiality'],
        'discovery': ['Confidentiality'],
        'lateral_movement': ['Availability', 'Integrity'],
        'collection': ['Confidentiality'],
        'exfiltration': ['Confidentiality'],
        'impact': ['Integrity', 'Availability'],
    }

    cia_set = set()
    for step in steps:
        phase = step.get('kill_chain_phase', '').lower().replace(' ', '_').replace('&', '').strip()
        impacts = cia_map.get(phase, [])
        cia_set.update(impacts)

    # Return in priority order: C, I, A
    priority = ['Confidentiality', 'Integrity', 'Availability']
    return [c for c in priority if c in cia_set]


def generate_risk_scenario(
    path: Dict[str, Any],
    impact_score: int,
) -> Dict[str, str]:
    """
    Generate risk scenario following CSA CII Section 4.1 Task C format.

    Risk scenario = Threat Event + Vulnerability + Asset + Consequence

    Args:
        path: Attack path dictionary
        impact_score: User-configured impact level (1-5)

    Returns:
        Dict with threat_event, vulnerability, asset, consequence
    """
    steps = path.get('steps', [])
    if not steps:
        return {}

    first_step = steps[0]
    last_step = steps[-1]

    threat_event = f"{path.get('threat_actor', 'Threat actor')} executes {first_step.get('technique_name', 'attack technique')}"

    vulnerability = f"Infrastructure allows {len(steps)}-step attack path from {first_step.get('kill_chain_phase', 'entry point')} to {last_step.get('kill_chain_phase', 'objective')}"

    asset = first_step.get('target_asset', 'target infrastructure')

    # Consequence based on impact level
    impact_label = IMPACT_LABELS[impact_score]
    if impact_score >= 4:
        consequence = f"Severe compromise of {asset} leading to {impact_label.lower()} data exposure or service disruption"
    elif impact_score >= 3:
        consequence = f"Moderate compromise affecting {asset} with potential for {impact_label.lower()} business impact"
    else:
        consequence = f"Limited compromise of {asset} with {impact_label.lower()} operational impact"

    return {
        'threat_event': threat_event,
        'vulnerability': vulnerability,
        'asset': asset,
        'consequence': consequence,
    }


def generate_risk_register_entry(
    path: Dict[str, Any],
    risk_score: int,
    risk_band: RiskBand,
) -> Dict[str, str]:
    """
    Generate risk register entry with existing measures and treatment plan.

    Args:
        path: Attack path dictionary
        risk_score: Calculated risk level (1-25)
        risk_band: Risk band classification

    Returns:
        Dict with existing_measures and treatment_plan
    """
    steps = path.get('steps', [])

    # Identify existing measures from mitigations
    existing_mitigations = []
    for step in steps:
        mit = step.get('mitigation')
        if mit:
            existing_mitigations.append(mit.get('mitigation_name', ''))

    if existing_mitigations:
        existing_measures = f"Current controls: {', '.join(existing_mitigations[:3])}"
        if len(existing_mitigations) > 3:
            existing_measures += f" (+{len(existing_mitigations) - 3} more)"
    else:
        existing_measures = "No existing mitigations identified in path analysis"

    # Treatment plan based on risk band
    if risk_band in (RiskBand.VERY_HIGH, RiskBand.HIGH):
        treatment_plan = "Immediate mitigation required. Implement all recommended controls. Review within 30 days."
    elif risk_band == RiskBand.MEDIUM_HIGH:
        treatment_plan = "Develop treatment plan within 30 days. Implement controls within 3-6 months."
    elif risk_band == RiskBand.MEDIUM:
        treatment_plan = "Monitor regularly. Implement cost-effective controls. Document acceptance if no treatment."
    else:
        treatment_plan = "Accept with periodic monitoring. Document risk acceptance decision."

    return {
        'existing_measures': existing_measures,
        'treatment_plan': treatment_plan,
    }


def score_attack_path(
    path: Dict[str, Any],
    impact_score: int,
) -> Dict[str, Any]:
    """
    Score a single attack path using CSA CII 5×5 risk matrix.

    Args:
        path: Attack path dictionary with steps and evaluation
        impact_score: User-configured impact level (1-5)

    Returns:
        Dict containing:
        - likelihood: {score, label, sub_factors: {D, E, R}}
        - impact: {score, label, rationale}
        - risk_level: int (1-25)
        - risk_band: str
        - risk_tolerance_action: str
        - cia_classification: List[str]
        - risk_scenario: Dict
        - risk_register_entry: Dict
    """
    # Step 1: Calculate likelihood from D/E/R
    d_score, d_rationale = estimate_discoverability(path)
    e_score, e_rationale = estimate_exploitability(path)
    r_score, r_rationale = estimate_reproducibility(path)

    likelihood_score, likelihood_label = calculate_likelihood_from_der(
        d_score, e_score, r_score
    )

    # Step 2: Use configured impact
    impact_label = IMPACT_LABELS[impact_score]

    # Step 3: Lookup risk level and band from matrix
    risk_level, risk_band = RISK_MATRIX[(likelihood_score, impact_score)]

    # Step 4: Get tolerance action
    tolerance_action = RISK_TOLERANCE_ACTIONS[risk_band]

    # Step 5: Derive CIA classification
    steps = path.get('steps', [])
    cia = derive_cia_classification(steps)

    # Step 6: Generate risk scenario
    risk_scenario = generate_risk_scenario(path, impact_score)

    # Step 7: Generate risk register entry
    risk_register = generate_risk_register_entry(path, risk_level, risk_band)

    logger.info(
        f"Scored path {path.get('id', 'unknown')}: "
        f"L:{likelihood_score} × I:{impact_score} = "
        f"{risk_level} ({risk_band.value})"
    )

    return {
        'likelihood': {
            'score': likelihood_score,
            'label': likelihood_label,
            'sub_factors': {
                'discoverability': {
                    'score': d_score,
                    'descriptor': LIKELIHOOD_LABELS.get(d_score, ''),
                    'rationale': d_rationale,
                },
                'exploitability': {
                    'score': e_score,
                    'descriptor': LIKELIHOOD_LABELS.get(e_score, ''),
                    'rationale': e_rationale,
                },
                'reproducibility': {
                    'score': r_score,
                    'descriptor': LIKELIHOOD_LABELS.get(r_score, ''),
                    'rationale': r_rationale,
                },
            },
        },
        'impact': {
            'score': impact_score,
            'label': impact_label,
            'rationale': f"User-configured data classification: {impact_label}",
        },
        'risk_level': risk_level,
        'risk_band': risk_band.value,
        'risk_tolerance_action': tolerance_action,
        'cia_classification': cia,
        'risk_scenario': risk_scenario,
        'risk_register_entry': risk_register,
    }


def score_all_paths(
    paths: List[Dict[str, Any]],
    impact_score: int,
) -> Dict[str, Any]:
    """
    Score all attack paths and generate risk assessment summary.

    Args:
        paths: List of attack path dictionaries
        impact_score: User-configured impact level (1-5)

    Returns:
        Dict containing:
        - scored_paths: List of paths with csa_risk_score field added
        - risk_distribution: Count of paths per risk band
        - highest_band: Highest risk band present
        - paths_scored: Total paths scored
        - framework: Framework identifier
        - impact_configuration: User's impact setting
    """
    if not paths:
        logger.warning("No paths to score")
        return {
            'scored_paths': [],
            'risk_distribution': {},
            'highest_band': None,
            'paths_scored': 0,
            'framework': 'CSA CII Risk Assessment Guide (Feb 2021) Section 4.2',
            'impact_configuration': {
                'user_set_score': impact_score,
                'label': IMPACT_LABELS.get(impact_score, 'Unknown'),
            },
        }

    scored_paths = []
    distribution = {
        'Very High': 0,
        'High': 0,
        'Medium-High': 0,
        'Medium': 0,
        'Low': 0,
    }

    for path in paths:
        csa_score = score_attack_path(path, impact_score)
        path_with_score = {**path, 'csa_risk_score': csa_score}
        scored_paths.append(path_with_score)

        band = csa_score['risk_band']
        distribution[band] = distribution.get(band, 0) + 1

    # Determine highest band present
    band_priority = ['Very High', 'High', 'Medium-High', 'Medium', 'Low']
    highest_band = None
    for band in band_priority:
        if distribution.get(band, 0) > 0:
            highest_band = band
            break

    # Sort paths by risk level descending
    scored_paths.sort(
        key=lambda p: p['csa_risk_score']['risk_level'],
        reverse=True
    )

    logger.info(
        f"Scored {len(scored_paths)} paths. Highest band: {highest_band}. "
        f"Distribution: {distribution}"
    )

    return {
        'scored_paths': scored_paths,
        'risk_distribution': distribution,
        'highest_band': highest_band,
        'paths_scored': len(scored_paths),
        'framework': 'CSA CII Risk Assessment Guide (Feb 2021) Section 4.2',
        'impact_configuration': {
            'user_set_score': impact_score,
            'label': IMPACT_LABELS.get(impact_score, 'Unknown'),
        },
    }
