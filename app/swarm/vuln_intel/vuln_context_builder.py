"""Vulnerability Context Builder - Orchestrates all vulnerability intelligence.

This module provides a single entry point for building complete vulnerability
context from IaC asset graphs. It orchestrates:
- Cloud signal extraction (misconfigurations, abuse-enabling conditions)
- Vulnerability matching (CVEs and cloud abuse patterns)
- Attack chain assembly (multi-step exploitation sequences)

The resulting VulnContext object is injected into agent prompts to guide
vulnerability-driven attack path generation.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from .vuln_matcher import VulnMatcher, MatchedVuln
from .chain_assembler import ChainAssembler, AssembledChain
from ..iac_signal_extractor import IaCSignalExtractor, CloudSignal

logger = logging.getLogger(__name__)


@dataclass
class VulnContext:
    """
    Complete vulnerability context for injection into agent prompts.
    One instance per swarm run, shared across all agents.

    This dataclass packages all vulnerability intelligence discovered
    from the IaC asset graph, ready for injection into agent prompts.
    """
    cloud_signals: List[CloudSignal]
    matched_vulns: List[MatchedVuln]
    assembled_chains: List[AssembledChain]
    signal_prompt: str
    vuln_prompt: str
    chain_prompt: str
    combined_prompt: str
    stats: Dict[str, Any]


class VulnContextBuilder:
    """
    Orchestrates signal extraction, vulnerability matching,
    and chain assembly into a single VulnContext object.

    This is the single entry point for all vulnerability intelligence
    used in threat modeling. Called once per run before any agent executes.

    Usage:
        builder = VulnContextBuilder(nvd_api_key=os.getenv('NVD_API_KEY'))
        vuln_context = await builder.build(
            asset_graph=parsed_asset_graph,
            raw_iac=raw_iac_dict,
            include_cve_lookup=True
        )

        # Pass vuln_context to all agent prompts
        prompt = build_agent_prompt(
            persona=persona,
            asset_graph=asset_graph,
            vuln_context=vuln_context
        )
    """

    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize vulnerability context builder.

        Args:
            nvd_api_key: Optional NVD API key for CVE lookups.
                        Without key: 5 requests per 30 seconds.
                        With key: 50 requests per 30 seconds.
        """
        self.signal_extractor = IaCSignalExtractor()
        self.vuln_matcher = VulnMatcher(nvd_api_key=nvd_api_key)
        self.chain_assembler = ChainAssembler()
        logger.info(
            f"[VulnContextBuilder] Initialized "
            f"(NVD API key: {'configured' if nvd_api_key else 'not configured'})"
        )

    async def build(
        self,
        asset_graph: Dict[str, Any],
        raw_iac: Optional[Dict[str, Any]] = None,
        include_cve_lookup: bool = True,
    ) -> VulnContext:
        """
        Build complete vulnerability context from asset graph.

        This method orchestrates the complete vulnerability intelligence pipeline:
        1. Extract cloud configuration signals (IMDSv1, wildcard IAM, etc.)
        2. Match CVEs and cloud abuse patterns to resources
        3. Assemble multi-step attack chains from matched vulnerabilities
        4. Format all intelligence for agent prompt injection

        Args:
            asset_graph: Parsed infrastructure asset graph dictionary
            raw_iac: Optional raw IaC for additional signal extraction
            include_cve_lookup: Whether to query NVD for CVEs (requires internet)

        Returns:
            VulnContext object with all vulnerability intelligence
        """
        logger.info("[VulnContextBuilder] Building vulnerability context")

        # Step 1: Extract cloud signals
        logger.info("[VulnContextBuilder] Step 1: Extracting cloud signals")
        signals = self.signal_extractor.extract(asset_graph, raw_iac)
        signal_prompt = self.signal_extractor.format_for_agent_prompt(signals)
        logger.info(
            f"[VulnContextBuilder] Extracted {len(signals)} cloud signals "
            f"({sum(1 for s in signals if s.severity == 'HIGH')} HIGH severity)"
        )

        # Step 2: Match vulnerabilities
        logger.info("[VulnContextBuilder] Step 2: Matching vulnerabilities")
        matched_vulns = await self.vuln_matcher.match(
            asset_graph=asset_graph,
            cloud_signals=signals,
            include_cve_lookup=include_cve_lookup,
        )
        vuln_prompt = self.vuln_matcher.format_for_prompt(matched_vulns)
        logger.info(
            f"[VulnContextBuilder] Matched {len(matched_vulns)} vulnerabilities "
            f"({sum(1 for v in matched_vulns if v.in_kev)} KEV, "
            f"{sum(1 for v in matched_vulns if v.risk_score >= 8.0)} critical)"
        )

        # Step 3: Assemble chains (1 primary + 4 alternates)
        logger.info("[VulnContextBuilder] Step 3: Assembling attack chains")
        assembled_chains = self.chain_assembler.assemble(
            matched_vulns=matched_vulns,
            asset_graph=asset_graph,
            max_chains=5,
        )
        chain_prompt = self.chain_assembler.format_for_prompt(assembled_chains)
        logger.info(
            f"[VulnContextBuilder] Assembled {len(assembled_chains)} attack chains "
            f"(top score: {assembled_chains[0].chain_score if assembled_chains else 0:.1f})"
        )

        # Step 4: Build combined prompt section
        combined = self._build_combined_prompt(
            signal_prompt, vuln_prompt, chain_prompt
        )

        # Calculate statistics
        stats = {
            'signals_detected': len(signals),
            'high_signals': sum(1 for s in signals if s.severity == 'HIGH'),
            'medium_signals': sum(1 for s in signals if s.severity == 'MEDIUM'),
            'low_signals': sum(1 for s in signals if s.severity == 'LOW'),
            'vulns_matched': len(matched_vulns),
            'kev_vulns': sum(1 for v in matched_vulns if v.in_kev),
            'critical_vulns': sum(1 for v in matched_vulns if v.risk_score >= 8.0),
            'high_vulns': sum(1 for v in matched_vulns if v.risk_score >= 6.0),
            'chains_assembled': len(assembled_chains),
            'top_chain_score': (
                assembled_chains[0].chain_score if assembled_chains else 0.0
            ),
            'kev_chains': sum(1 for c in assembled_chains if c.has_kev_vuln),
            'undetectable_chains': sum(
                1 for c in assembled_chains if c.undetectable_steps > 0
            ),
        }

        logger.info(
            f"[VulnContextBuilder] Context built successfully: "
            f"{stats['vulns_matched']} vulns, {stats['chains_assembled']} chains"
        )

        return VulnContext(
            cloud_signals=signals,
            matched_vulns=matched_vulns,
            assembled_chains=assembled_chains,
            signal_prompt=signal_prompt,
            vuln_prompt=vuln_prompt,
            chain_prompt=chain_prompt,
            combined_prompt=combined,
            stats=stats,
        )

    def build_sync(
        self,
        asset_graph: Dict[str, Any],
        raw_iac: Optional[Dict[str, Any]] = None,
        include_cve_lookup: bool = True,
    ) -> VulnContext:
        """
        Synchronous wrapper for build().

        Use this when calling from synchronous code that cannot use async/await.

        Args:
            asset_graph: Parsed infrastructure asset graph dictionary
            raw_iac: Optional raw IaC for additional signal extraction
            include_cve_lookup: Whether to query NVD for CVEs

        Returns:
            VulnContext object with all vulnerability intelligence
        """
        return asyncio.run(self.build(
            asset_graph, raw_iac, include_cve_lookup
        ))

    def _build_combined_prompt(
        self,
        signal_prompt: str,
        vuln_prompt: str,
        chain_prompt: str
    ) -> str:
        """
        Combine all vulnerability intelligence into a single prompt section.

        Args:
            signal_prompt: Formatted cloud signals
            vuln_prompt: Formatted matched vulnerabilities
            chain_prompt: Formatted assembled chains

        Returns:
            Combined prompt string ready for injection
        """
        sections = []

        # Header
        sections.append('=' * 80)
        sections.append('VULNERABILITY INTELLIGENCE FOR THIS INFRASTRUCTURE')
        sections.append('=' * 80)
        sections.append('')

        # Add each section if non-empty
        if signal_prompt and 'No high-risk' not in signal_prompt:
            sections.append(signal_prompt)
            sections.append('')

        if vuln_prompt and 'No specific CVEs' not in vuln_prompt:
            sections.append(vuln_prompt)
            sections.append('')

        if chain_prompt:
            sections.append(chain_prompt)
            sections.append('')

        # Instruction section
        sections.append('=' * 80)
        sections.append('INSTRUCTION: VULNERABILITY-DRIVEN ATTACK PATH GENERATION')
        sections.append('=' * 80)
        sections.append('')
        sections.append(
            'When generating attack paths, you MUST reference specific vulnerability IDs '
            '(e.g., AWS-IMDS-001, CVE-2024-XXXXX, AWS-IAM-002) rather than generic ATT&CK '
            'techniques alone.'
        )
        sections.append('')
        sections.append(
            'Use the exploitation commands provided above as evidence for how each step '
            'is executed in this specific infrastructure.'
        )
        sections.append('')
        sections.append(
            'Prioritize attack paths that chain the assembled attack chains shown above, '
            'as these represent multi-step sequences with confirmed exploitability.'
        )
        sections.append('')
        sections.append(
            'Detection gaps are highlighted for each vulnerability. When a vulnerability '
            'has a detection gap (e.g., "IMDS calls do not appear in CloudTrail"), '
            'explain how this enables stealthy exploitation.'
        )
        sections.append('')
        sections.append('=' * 80)
        sections.append('')

        return '\n'.join(sections)
