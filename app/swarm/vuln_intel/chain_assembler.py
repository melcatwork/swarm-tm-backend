import os
from dataclasses import dataclass, field
from typing import Optional
from .vuln_matcher import MatchedVuln

# Maximum number of steps in an assembled attack chain
MAX_CHAIN_STEPS = int(os.getenv('SWARM_MAX_CHAIN_STEPS', '10'))

KILL_CHAIN_ORDER = [
    'reconnaissance',
    'resource_development',
    'initial_access',
    'execution',
    'persistence',
    'privilege_escalation',
    'defense_evasion',
    'credential_access',
    'discovery',
    'lateral_movement',
    'collection',
    'exfiltration',
    'impact',
]

# ATT&CK gap-fillers: when we have vulns in phases A and C
# but nothing in phase B, insert this technique
GAP_FILLERS = {
    ('initial_access', 'credential_access'): {
        'technique_id': 'T1552.005',
        'technique_name': 'Cloud Instance Metadata API',
        'description': (
            'Gap-fill: after gaining initial access to cloud '
            'compute, attempt IMDS credential theft to obtain '
            'IAM role credentials before pivoting further.'
        ),
    },
    ('credential_access', 'lateral_movement'): {
        'technique_id': 'T1078.004',
        'technique_name': 'Valid Cloud Accounts',
        'description': (
            'Gap-fill: use stolen cloud credentials to '
            'authenticate as the IAM role and pivot to other '
            'cloud services or accounts.'
        ),
    },
    ('lateral_movement', 'collection'): {
        'technique_id': 'T1530',
        'technique_name': 'Data from Cloud Storage Object',
        'description': (
            'Gap-fill: use established cloud access to '
            'enumerate and collect data from cloud storage.'
        ),
    },
    ('collection', 'exfiltration'): {
        'technique_id': 'T1567.002',
        'technique_name': 'Exfiltration to Cloud Storage',
        'description': (
            'Gap-fill: transfer collected data to '
            'attacker-controlled external storage.'
        ),
    },
    ('initial_access', 'lateral_movement'): {
        'technique_id': 'T1078.004',
        'technique_name': 'Valid Cloud Accounts',
        'description': (
            'Gap-fill: use cloud-native credential abuse to '
            'pivot after initial access without intermediate steps.'
        ),
    },
}

@dataclass
class ChainStep:
    phase: str
    technique_id: str
    technique_name: str
    vuln_id: Optional[str]      # None if gap-filler
    vuln_name: str
    resource_id: str
    description: str
    exploitation_commands: list[str]
    detection_gap: str
    risk_score: float
    is_gap_filler: bool = False

@dataclass
class AssembledChain:
    chain_id: str
    chain_name: str
    steps: list[ChainStep]
    chain_score: float
    has_kev_vuln: bool
    has_poc: bool
    completeness: float         # 0.0 to 1.0
    phases_covered: list[str]
    undetectable_steps: int
    summary: str

class ChainAssembler:
    """
    Takes a list of matched vulnerabilities and assembles them
    into ordered attack chains covering all kill chain phases.

    Assembly strategy:
    1. Group vulns by kill chain phase
    2. Select highest risk_score vuln per phase
    3. Identify phase gaps between covered phases
    4. Insert gap-filler techniques for logical continuity
    5. Score the assembled chain
    6. Generate multiple chains if vulns support alternate paths
    """

    def assemble(
        self,
        matched_vulns: list[MatchedVuln],
        asset_graph: dict,
        max_chains: int = 5,
    ) -> list[AssembledChain]:
        if not matched_vulns:
            return []

        # Group by kill chain phase and sort by risk score
        by_phase: dict[str, list[MatchedVuln]] = {}
        for v in matched_vulns:
            phase = v.kill_chain_phase
            if phase not in by_phase:
                by_phase[phase] = []
            by_phase[phase].append(v)

        # Sort vulnerabilities in each phase by risk score (descending)
        for phase in by_phase:
            by_phase[phase].sort(key=lambda v: v.risk_score, reverse=True)

        # Build primary chain from best vuln per phase
        primary = self._build_chain(
            by_phase, matched_vulns, 'primary', rank_offset=0
        )
        chains = [primary] if primary else []

        # Build 4 alternate chains using different vulnerability rankings
        if len(matched_vulns) > 3 and max_chains > 1:
            for alt_num in range(1, min(5, max_chains)):
                alt = self._build_chain(
                    by_phase, matched_vulns, f'alternate-{alt_num}', rank_offset=alt_num
                )
                # Only add if different from existing chains
                if alt and not any(alt.chain_id == c.chain_id for c in chains):
                    chains.append(alt)
                    # Stop if we've hit max_chains
                    if len(chains) >= max_chains:
                        break

        return chains[:max_chains]

    def _build_chain(
        self,
        by_phase: dict,
        all_vulns: list[MatchedVuln],
        chain_type: str,
        rank_offset: int = 0,
    ) -> Optional[AssembledChain]:
        covered_phases = sorted(
            by_phase.keys(),
            key=lambda p: KILL_CHAIN_ORDER.index(p)
            if p in KILL_CHAIN_ORDER else 99
        )
        if len(covered_phases) < 2:
            return None

        steps: list[ChainStep] = []

        for i, phase in enumerate(covered_phases):
            vulns_in_phase = by_phase[phase]  # Already sorted by risk score in assemble()

            # Select vuln based on rank_offset, with wraparound if not enough vulns
            vuln_idx = rank_offset % len(vulns_in_phase) if len(vulns_in_phase) > 0 else 0
            selected_vuln = vulns_in_phase[vuln_idx]
            steps.append(ChainStep(
                phase=phase,
                technique_id=selected_vuln.technique_id,
                technique_name=selected_vuln.technique_name,
                vuln_id=selected_vuln.vuln_id,
                vuln_name=selected_vuln.name,
                resource_id=selected_vuln.resource_id,
                description=selected_vuln.description,
                exploitation_commands=selected_vuln.exploitation_commands,
                detection_gap=selected_vuln.detection_gap,
                risk_score=selected_vuln.risk_score,
                is_gap_filler=False,
            ))

            # Check for gap to next phase
            if i + 1 < len(covered_phases):
                next_phase = covered_phases[i + 1]
                gap_key = (phase, next_phase)
                if gap_key in GAP_FILLERS:
                    filler = GAP_FILLERS[gap_key]
                    # Find a suitable resource for the gap step
                    resource = selected_vuln.resource_id
                    steps.append(ChainStep(
                        phase=f'{phase}_to_{next_phase}',
                        technique_id=filler['technique_id'],
                        technique_name=filler['technique_name'],
                        vuln_id=None,
                        vuln_name='Gap-fill technique',
                        resource_id=resource,
                        description=filler['description'],
                        exploitation_commands=[],
                        detection_gap='',
                        risk_score=0.0,
                        is_gap_filler=True,
                    ))

        if not steps:
            return None

        chain_score = self._score_chain(steps, all_vulns)
        has_kev = any(
            v.in_kev for v in all_vulns
            if not v.in_kev is None
        )
        has_poc = any(v.poc_references for v in all_vulns)
        non_gap = [s for s in steps if not s.is_gap_filler]
        phases = [s.phase for s in non_gap]
        completeness = len(phases) / max(
            len(KILL_CHAIN_ORDER), 1
        )
        undetectable = sum(
            1 for s in steps
            if s.detection_gap and not s.is_gap_filler
        )

        vuln_ids = [
            s.vuln_id for s in non_gap[:2]
            if s.vuln_id
        ]
        name = (
            f'{chain_type.title()} attack path: '
            + ' → '.join(vuln_ids[:2])
        )

        return AssembledChain(
            chain_id=(
                f'{chain_type}_'
                + '_'.join(
                    s.technique_id for s in non_gap[:3]
                )
            ),
            chain_name=name,
            steps=steps,
            chain_score=chain_score,
            has_kev_vuln=has_kev,
            has_poc=has_poc,
            completeness=completeness,
            phases_covered=phases,
            undetectable_steps=undetectable,
            summary=self._summarise(steps),
        )

    def _score_chain(
        self,
        steps: list[ChainStep],
        all_vulns: list[MatchedVuln],
    ) -> float:
        non_gap = [s for s in steps if not s.is_gap_filler]
        if not non_gap:
            return 0.0

        avg_risk = sum(
            s.risk_score for s in non_gap
        ) / len(non_gap)

        # Bonuses
        kev_bonus = 1.5 if any(
            v.in_kev for v in all_vulns
        ) else 1.0
        poc_bonus = 1.2 if any(
            v.poc_references for v in all_vulns
        ) else 1.0
        completeness_bonus = 1.0 + (len(non_gap) / 10.0)
        undetectable_bonus = 1.0 + (
            sum(
                1 for s in non_gap if s.detection_gap
            ) * 0.1
        )

        return min(10.0,
            avg_risk
            * kev_bonus
            * poc_bonus
            * completeness_bonus
            * undetectable_bonus
        )

    def _summarise(self, steps: list[ChainStep]) -> str:
        non_gap = [s for s in steps if not s.is_gap_filler]
        if not non_gap:
            return 'Empty chain'
        phases = ' → '.join(s.phase for s in non_gap[:4])
        ids = ' → '.join(
            s.vuln_id or s.technique_id
            for s in non_gap[:4]
        )
        return f'{phases} | {ids}'

    def format_for_prompt(
        self, chains: list[AssembledChain]
    ) -> str:
        if not chains:
            return ''
        lines = [
            'ASSEMBLED ATTACK CHAINS:',
            'These chains are built from specific vulnerabilities',
            'and abuse patterns confirmed in this infrastructure.',
            'Generate attack paths that follow these chains.',
            '',
        ]
        for chain in chains:
            lines.append(
                f'Chain: {chain.chain_name}'
            )
            lines.append(
                f'Score: {chain.chain_score:.1f}/10 | '
                f'KEV: {chain.has_kev_vuln} | '
                f'PoC: {chain.has_poc} | '
                f'Undetectable steps: {chain.undetectable_steps}'
            )
            lines.append('Steps:')
            for i, step in enumerate(chain.steps, 1):
                prefix = '[GAP-FILL]' if step.is_gap_filler else ''
                lines.append(
                    f'  {i}. {prefix} {step.technique_id} '
                    f'{step.technique_name}'
                )
                lines.append(
                    f'     Vuln: {step.vuln_id or "ATT&CK"} | '
                    f'Target: {step.resource_id}'
                )
                if step.exploitation_commands:
                    lines.append(
                        f'     Command: '
                        f'{step.exploitation_commands[0]}'
                    )
                if step.detection_gap:
                    lines.append(
                        f'     Detection gap: {step.detection_gap}'
                    )
            lines.append('')
        return '\n'.join(lines)
