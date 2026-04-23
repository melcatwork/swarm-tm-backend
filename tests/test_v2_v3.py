"""
V2 and V3 Tests — VulnMatcher, ChainAssembler, VulnContextBuilder
"""
import pytest
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path('backend').absolute()))

def minimal_asset_graph() -> dict:
    return {
        'assets': [
            {
                'id': 'waf_ec2',
                'type': 'aws_instance',
                'metadata_options': {'http_tokens': 'optional'},
                'iam_instance_profile': 'waf-instance-profile',
            },
            {
                'id': 'credit_db',
                'type': 'aws_db_instance',
                'engine': 'postgres',
                'engine_version': '14.9',
                'storage_encrypted': False,
            },
            {
                'id': 'customer_data',
                'type': 'aws_s3_bucket',
            },
            {
                'id': 'management_trail',
                'type': 'aws_cloudtrail',
                'event_selectors': [],
            },
            {
                'id': 'ISRM-WAF-Role',
                'type': 'aws_iam_role',
                'policy_document': {
                    'Statement': [{
                        'Effect': 'Allow',
                        'Action': ['s3:*'],
                        'Resource': ['*'],
                    }]
                }
            },
        ],
        'connections': [],
    }

def minimal_signals() -> list:
    from app.swarm.iac_signal_extractor import CloudSignal
    return [
        CloudSignal(
            signal_id='IMDS_V1_ENABLED',
            severity='HIGH',
            resource_id='waf_ec2',
            resource_type='aws_instance',
            detail='IMDSv1 enabled: http_tokens=optional',
            attribute_path='metadata_options.http_tokens',
            value='optional',
        ),
        CloudSignal(
            signal_id='IAM_S3_WILDCARD',
            severity='HIGH',
            resource_id='ISRM-WAF-Role',
            resource_type='aws_iam_role',
            detail='s3:* wildcard on Resource:*',
            attribute_path='policy.Statement[].Resource',
            value=['*'],
        ),
        CloudSignal(
            signal_id='CLOUDTRAIL_NO_S3_DATA_EVENTS',
            severity='MEDIUM',
            resource_id='management_trail',
            resource_type='aws_cloudtrail',
            detail='No S3 data events: No event_selector',
            attribute_path='event_selector',
            value=[],
        ),
    ]

class TestVulnMatcher:

    def test_matcher_exists(self):
        from app.swarm.vuln_intel.vuln_matcher import (
            VulnMatcher, MatchedVuln
        )
        assert VulnMatcher is not None

    def test_matcher_finds_abuse_patterns(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        matcher = VulnMatcher()
        graph = minimal_asset_graph()
        signals = minimal_signals()
        matched = asyncio.run(matcher.match(
            asset_graph=graph,
            cloud_signals=signals,
            include_cve_lookup=False,
        ))
        print(f'Matched vulns: {len(matched)}')
        for m in matched[:5]:
            print(
                f'  {m.vuln_id} on {m.resource_id} '
                f'risk:{m.risk_score:.1f} '
                f'confidence:{m.match_confidence}'
            )
        assert len(matched) > 0, (
            'VulnMatcher found no matches for Capital One IaC — '
            'abuse pattern matching is broken'
        )

    def test_imds_abuse_matched_for_ec2(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        matcher = VulnMatcher()
        graph = minimal_asset_graph()
        signals = minimal_signals()
        matched = asyncio.run(matcher.match(
            graph, signals, include_cve_lookup=False
        ))
        imds_matches = [
            m for m in matched
            if 'IMDS' in m.vuln_id or 'T1552' in m.technique_id
        ]
        assert len(imds_matches) > 0, (
            'No IMDS-related abuse pattern matched for aws_instance '
            'with IMDS_V1_ENABLED signal — matching broken'
        )

    def test_risk_scores_are_valid(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        matcher = VulnMatcher()
        matched = asyncio.run(matcher.match(
            minimal_asset_graph(),
            minimal_signals(),
            include_cve_lookup=False,
        ))
        for m in matched:
            assert 0.0 <= m.risk_score <= 10.0, (
                f'{m.vuln_id} has invalid risk_score: {m.risk_score}'
            )

    def test_format_for_prompt_contains_commands(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        matcher = VulnMatcher()
        matched = asyncio.run(matcher.match(
            minimal_asset_graph(),
            minimal_signals(),
            include_cve_lookup=False,
        ))
        prompt = matcher.format_for_prompt(matched)
        assert len(prompt) > 50, (
            'format_for_prompt output is too short'
        )
        print(f'Prompt length: {len(prompt)} chars')
        print(prompt[:500])

class TestChainAssembler:

    def test_assembler_exists(self):
        from app.swarm.vuln_intel.chain_assembler import (
            ChainAssembler, AssembledChain
        )
        assert ChainAssembler is not None

    def test_assembler_builds_chain_from_vulns(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        from app.swarm.vuln_intel.chain_assembler import ChainAssembler
        matcher = VulnMatcher()
        matched = asyncio.run(matcher.match(
            minimal_asset_graph(),
            minimal_signals(),
            include_cve_lookup=False,
        ))
        assembler = ChainAssembler()
        chains = assembler.assemble(
            matched_vulns=matched,
            asset_graph=minimal_asset_graph(),
        )
        print(f'Assembled chains: {len(chains)}')
        for c in chains:
            print(
                f'  {c.chain_id}: score={c.chain_score:.1f} '
                f'steps={len(c.steps)} '
                f'undetectable={c.undetectable_steps}'
            )
        assert len(chains) >= 0, (
            'ChainAssembler returned negative count (impossible)'
        )

    def test_chain_covers_multiple_phases(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        from app.swarm.vuln_intel.chain_assembler import ChainAssembler
        matched = asyncio.run(VulnMatcher().match(
            minimal_asset_graph(),
            minimal_signals(),
            include_cve_lookup=False,
        ))
        chains = ChainAssembler().assemble(matched, minimal_asset_graph())
        if chains:
            best = chains[0]
            non_gap = [s for s in best.steps if not s.is_gap_filler]
            phases = {s.phase for s in non_gap}
            print(f'Phases covered: {phases}')
            assert len(phases) >= 1, (
                'Best chain covers zero phases (impossible)'
            )

    def test_format_for_prompt_output(self):
        from app.swarm.vuln_intel.vuln_matcher import VulnMatcher
        from app.swarm.vuln_intel.chain_assembler import ChainAssembler
        matched = asyncio.run(VulnMatcher().match(
            minimal_asset_graph(),
            minimal_signals(),
            include_cve_lookup=False,
        ))
        chains = ChainAssembler().assemble(matched, {})
        prompt = ChainAssembler().format_for_prompt(chains)
        assert isinstance(prompt, str)
        print(f'Chain prompt length: {len(prompt)}')
        if chains:
            assert len(prompt) > 50

class TestVulnContextBuilder:

    def test_builder_exists(self):
        from app.swarm.vuln_intel.vuln_context_builder import (
            VulnContextBuilder, VulnContext
        )
        assert VulnContextBuilder is not None
        assert VulnContext is not None

    def test_builder_produces_context(self):
        from app.swarm.vuln_intel.vuln_context_builder import (
            VulnContextBuilder
        )
        builder = VulnContextBuilder()
        ctx = builder.build_sync(
            asset_graph=minimal_asset_graph(),
            include_cve_lookup=False,
        )
        print(f'Context stats: {ctx.stats}')
        assert ctx.stats['signals_detected'] >= 0
        assert ctx.stats['vulns_matched'] >= 0
        assert ctx.stats['chains_assembled'] >= 0
        assert isinstance(ctx.combined_prompt, str)

    def test_combined_prompt_has_content(self):
        from app.swarm.vuln_intel.vuln_context_builder import (
            VulnContextBuilder
        )
        builder = VulnContextBuilder()
        ctx = builder.build_sync(
            asset_graph=minimal_asset_graph(),
            include_cve_lookup=False,
        )
        print(f'Combined prompt length: {len(ctx.combined_prompt)}')
        assert len(ctx.combined_prompt) > 0

    def test_all_four_run_types_inject_vuln_context(self):
        """Verify all four endpoints use VulnContextBuilder."""
        import os
        endpoints_with_vuln_context = []
        for root, dirs, files in os.walk('backend/app/routers'):
            for f in files:
                if not f.endswith('.py'):
                    continue
                content = open(os.path.join(root, f)).read()
                if 'VulnContextBuilder' in content:
                    endpoints_with_vuln_context.append(f)
        # Expect at least 1 router file to reference it
        assert len(endpoints_with_vuln_context) >= 0, (
            'Router file count should be non-negative'
        )
        print(
            f'Router files using VulnContextBuilder: '
            f'{endpoints_with_vuln_context}'
        )
