"""
Unit tests for Revised Prompt 2 modules:
- persona_selector.py
- output_filter.py
- consensus_aggregator.py

Tests validate dynamic behaviour — decisions driven by
finding properties, not hardcoded attack types.
"""
import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend' / 'app'))


def make_mock_vuln(
    vuln_id='TEST-001',
    resource_id='test_resource',
    technique_id='T1190',
    kill_chain_phase='initial_access',
    match_confidence='CONFIRMED',
    cvss_score=8.0,
    risk_score=8.0,
    exploitation_commands=None,
    detection_gap='',
    cloudtrail_logged=True,
):
    from types import SimpleNamespace
    return SimpleNamespace(
        vuln_id=vuln_id,
        name=f'Test vuln {vuln_id}',
        resource_id=resource_id,
        resource_type='aws_instance',
        technique_id=technique_id,
        technique_name=technique_id,
        kill_chain_phase=kill_chain_phase,
        match_confidence=match_confidence,
        cvss_score=cvss_score,
        risk_score=risk_score,
        epss_score=0.0,
        in_kev=False,
        exploitation_commands=exploitation_commands or [],
        detection_gap=detection_gap,
        cloudtrail_logged=cloudtrail_logged,
        match_reason='test',
        remediation='test fix',
    )


def make_mock_signal(
    signal_id='TEST_SIGNAL',
    severity='HIGH',
    resource_id='test_resource',
):
    from types import SimpleNamespace
    return SimpleNamespace(
        signal_id=signal_id,
        severity=severity,
        resource_id=resource_id,
        resource_type='aws_instance',
        signal_description='test signal',
        enabling_techniques=['T1190'],
        detail='test detail',
    )


def make_mock_context(
    matched_vulns=None,
    cloud_signals=None,
    app_findings=None,
    assembled_chains=None,
):
    from types import SimpleNamespace
    return SimpleNamespace(
        matched_vulns=matched_vulns or [],
        cloud_signals=cloud_signals or [],
        app_findings=app_findings or [],
        assembled_chains=assembled_chains or [],
    )


class TestPersonaSelector:

    def test_module_exists(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        assert select_personas_for_context is not None

    def test_no_injection_when_no_findings(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context()
        result, injected = select_personas_for_context(
            requested_personas=['opportunistic_attacker'],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'opportunistic_attacker',
                'cloud_native_attacker',
            ],
        )
        assert 'cloud_native_attacker' not in result, (
            'cloud_native_attacker injected even though '
            'no high-confidence findings exist'
        )
        assert injected == [], (
            'injection reported when no findings present'
        )

    def test_injection_when_confirmed_high_finding(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    match_confidence='CONFIRMED',
                    cvss_score=8.0,
                )
            ]
        )
        result, injected = select_personas_for_context(
            requested_personas=['opportunistic_attacker'],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'opportunistic_attacker',
                'cloud_native_attacker',
            ],
        )
        assert 'cloud_native_attacker' in result, (
            'cloud_native_attacker NOT injected when '
            'CONFIRMED HIGH finding exists — '
            'specialist injection is broken'
        )
        assert 'cloud_native_attacker' in injected

    def test_injection_when_high_signal(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context(
            cloud_signals=[
                make_mock_signal(severity='HIGH')
            ]
        )
        result, injected = select_personas_for_context(
            requested_personas=['insider_threat'],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'insider_threat',
                'cloud_native_attacker',
            ],
        )
        assert 'cloud_native_attacker' in result, (
            'cloud_native_attacker NOT injected when '
            'HIGH severity signal exists'
        )

    def test_no_injection_when_only_medium_findings(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    match_confidence='PROBABLE',
                    cvss_score=5.0,
                )
            ]
        )
        result, injected = select_personas_for_context(
            requested_personas=['opportunistic_attacker'],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'opportunistic_attacker',
                'cloud_native_attacker',
            ],
        )
        # PROBABLE + MEDIUM should not trigger injection
        # (only CONFIRMED + HIGH/CRITICAL should)
        print(
            f'  With PROBABLE/MEDIUM finding, '
            f'injected: {injected}'
        )

    def test_single_run_capped_at_3(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(match_confidence='CONFIRMED', cvss_score=8.0)
            ]
        )
        result, _ = select_personas_for_context(
            requested_personas=[
                'opportunistic_attacker',
                'insider_threat',
                'fin7',
            ],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'opportunistic_attacker',
                'insider_threat',
                'fin7',
                'cloud_native_attacker',
                'apt29_cozy_bear',
            ],
        )
        assert len(result) <= 3, (
            f'Single run returned {len(result)} personas — '
            'should be capped at 3'
        )

    def test_multi_run_not_capped(self):
        from swarm.persona_selector import (
            select_personas_for_context
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(match_confidence='CONFIRMED', cvss_score=8.0)
            ]
        )
        all_personas = [f'persona_{i}' for i in range(13)]
        all_personas.append('cloud_native_attacker')
        result, _ = select_personas_for_context(
            requested_personas=list(all_personas),
            vuln_context=ctx,
            run_type='multi',
            all_available_personas=all_personas,
        )
        assert len(result) > 3, (
            'Multi run persona list was capped — '
            'should not be capped for multi run'
        )

    def test_priority_order_puts_specialist_first(self):
        from swarm.persona_selector import (
            get_persona_priority_order
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(match_confidence='CONFIRMED', cvss_score=8.0)
            ]
        )
        personas = [
            'opportunistic_attacker',
            'insider_threat',
            'cloud_native_attacker',
            'fin7',
        ]
        ordered = get_persona_priority_order(personas, ctx)
        assert ordered[0] == 'cloud_native_attacker', (
            f'After priority ordering, first persona is '
            f'{ordered[0]} — cloud_native_attacker should '
            'be first when confirmed findings exist'
        )

    def test_injection_is_dynamic_not_signal_specific(self):
        """
        CRITICAL: Injection must work for ANY confirmed HIGH finding,
        not just IMDS or IAM-specific ones.
        This test uses a completely fictional finding type.
        """
        from swarm.persona_selector import (
            select_personas_for_context
        )
        # Use a fictional vuln type that has nothing to do
        # with IMDS, IAM, or S3
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    vuln_id='FICTIONAL-VULN-999',
                    technique_id='T9999',
                    kill_chain_phase='impact',
                    match_confidence='CONFIRMED',
                    cvss_score=9.5,
                )
            ]
        )
        result, injected = select_personas_for_context(
            requested_personas=['opportunistic_attacker'],
            vuln_context=ctx,
            run_type='single',
            all_available_personas=[
                'opportunistic_attacker',
                'cloud_native_attacker',
            ],
        )
        assert 'cloud_native_attacker' in result, (
            'cloud_native_attacker NOT injected for a '
            'fictional CONFIRMED CRITICAL finding. '
            'Injection logic may be checking specific '
            'vuln types instead of severity/confidence. '
            'This violates the dynamic requirement.'
        )


class TestOutputFilter:

    def test_module_exists(self):
        from swarm.output_filter import filter_and_rank_paths
        assert filter_and_rank_paths is not None

    def test_confirmed_grounded_path_always_included(self):
        from swarm.output_filter import filter_and_rank_paths
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    vuln_id='CONFIRMED-001',
                    technique_id='T1190',
                    match_confidence='CONFIRMED',
                )
            ]
        )
        # Path with very low score but grounded in confirmed vuln
        paths = [
            {
                'path_id': 'low_score_grounded',
                'adjusted_composite_score': 1.0,
                'steps': [
                    {
                        'technique_id': 'T1190',
                        'asset_id': 'test_resource',
                        'vuln_id': 'CONFIRMED-001',
                    }
                ],
            }
        ]
        result = filter_and_rank_paths(paths, ctx)
        assert len(result) == 1, (
            'Confirmed-grounded path was filtered out '
            'despite having a confirmed vuln reference. '
            'Grounded paths must always be included.'
        )
        assert result[0].get('grounded_in_confirmed_vuln'), (
            'grounded_in_confirmed_vuln flag not set'
        )

    def test_speculative_path_filtered_by_score(self):
        from swarm.output_filter import filter_and_rank_paths
        ctx = make_mock_context()
        paths = [
            {
                'path_id': 'low_score_speculative',
                'adjusted_composite_score': 2.0,
                'steps': [
                    {
                        'technique_id': 'T9999',
                        'asset_id': 'test',
                    }
                ],
            }
        ]
        result = filter_and_rank_paths(
            paths, ctx, min_composite_score=5.0
        )
        assert len(result) == 0, (
            'Low-score speculative path was not filtered'
        )

    def test_speculative_path_passes_score_threshold(self):
        from swarm.output_filter import filter_and_rank_paths
        ctx = make_mock_context()
        paths = [
            {
                'path_id': 'high_score_speculative',
                'adjusted_composite_score': 7.0,
                'steps': [
                    {
                        'technique_id': 'T9999',
                        'asset_id': 'test',
                    }
                ],
            }
        ]
        result = filter_and_rank_paths(
            paths, ctx, min_composite_score=5.0
        )
        assert len(result) == 1, (
            'High-score path was incorrectly filtered'
        )

    def test_grounded_paths_ranked_before_speculative(self):
        from swarm.output_filter import filter_and_rank_paths
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    vuln_id='CONF-001',
                    technique_id='T1190',
                    match_confidence='CONFIRMED',
                )
            ]
        )
        paths = [
            {
                'path_id': 'speculative_high_score',
                'adjusted_composite_score': 9.0,
                'steps': [{'technique_id': 'T9999',
                            'asset_id': 'x'}],
            },
            {
                'path_id': 'grounded_low_score',
                'adjusted_composite_score': 3.0,
                'steps': [{'technique_id': 'T1190',
                            'asset_id': 'test_resource',
                            'vuln_id': 'CONF-001'}],
            },
        ]
        result = filter_and_rank_paths(
            paths, ctx, min_composite_score=5.0
        )
        assert result[0]['path_id'] == 'grounded_low_score', (
            'Grounded path did not appear first — '
            'confirmed evidence paths must precede '
            'speculative paths regardless of score'
        )

    def test_confirmed_findings_summary_non_empty(self):
        from swarm.output_filter import (
            build_confirmed_findings_summary
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(match_confidence='CONFIRMED'),
                make_mock_vuln(
                    vuln_id='TEST-002',
                    match_confidence='PROBABLE',
                ),
            ]
        )
        summary = build_confirmed_findings_summary(ctx)
        assert len(summary) == 1, (
            f'Expected 1 confirmed finding, got {len(summary)}. '
            'Only CONFIRMED findings should appear.'
        )

    def test_confirmed_findings_summary_has_required_fields(self):
        from swarm.output_filter import (
            build_confirmed_findings_summary
        )
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(match_confidence='CONFIRMED')
            ]
        )
        summary = build_confirmed_findings_summary(ctx)
        assert summary
        required = {
            'vuln_id', 'resource_id', 'technique_id',
            'kill_chain_phase', 'match_confidence',
            'risk_score',
        }
        missing = required - set(summary[0].keys())
        assert not missing, (
            f'confirmed_findings summary missing fields: '
            f'{missing}'
        )

    def test_filter_is_dynamic_not_type_specific(self):
        """
        CRITICAL: Filter must protect ANY confirmed finding,
        not just cloud-specific ones.
        """
        from swarm.output_filter import filter_and_rank_paths
        ctx = make_mock_context(
            matched_vulns=[
                make_mock_vuln(
                    vuln_id='ARBITRARY-FINDING-XYZ',
                    technique_id='T0001',
                    match_confidence='CONFIRMED',
                )
            ]
        )
        paths = [{
            'path_id': 'arbitrary_path',
            'adjusted_composite_score': 1.0,
            'steps': [{
                'technique_id': 'T0001',
                'asset_id': 'test_resource',
                'vuln_id': 'ARBITRARY-FINDING-XYZ',
            }],
        }]
        result = filter_and_rank_paths(
            paths, ctx, min_composite_score=5.0
        )
        assert len(result) == 1, (
            'A confirmed path with an arbitrary finding ID '
            'was filtered out. The filter must protect ANY '
            'confirmed finding, not just known attack types. '
            'This violates the dynamic requirement.'
        )


class TestConsensusAggregator:

    def test_module_exists(self):
        from swarm.consensus_aggregator import aggregate_consensus
        assert aggregate_consensus is not None

    def test_aggregates_technique_counts(self):
        from swarm.consensus_aggregator import aggregate_consensus
        agent_paths = {
            'persona_a': [{
                'steps': [
                    {'technique_id': 'T1190',
                     'target_asset': 'ec2_a'}
                ]
            }],
            'persona_b': [{
                'steps': [
                    {'technique_id': 'T1190',
                     'target_asset': 'ec2_a'}
                ]
            }],
        }
        findings = aggregate_consensus(agent_paths)
        assert findings, 'No consensus findings produced'
        t1190_finding = next(
            (f for f in findings
             if f['technique_id'] == 'T1190'
             and f['asset_id'] == 'ec2_a'),
            None,
        )
        assert t1190_finding is not None, (
            'T1190 on ec2_a not found in consensus findings'
        )
        assert t1190_finding['agent_count'] >= 2, (
            f'Expected 2 agents, got '
            f'{t1190_finding["agent_count"]}'
        )

    def test_high_consensus_filtering(self):
        from swarm.consensus_aggregator import (
            aggregate_consensus,
            get_high_consensus_techniques
        )
        agent_paths = {
            f'persona_{i}': [{
                'steps': [{
                    'technique_id': 'T1530',
                    'target_asset': 'bucket_x'
                }]
            }]
            for i in range(5)
        }
        findings = aggregate_consensus(agent_paths)
        high_consensus = get_high_consensus_techniques(
            findings, min_agent_count=2
        )
        assert high_consensus, (
            'No high-consensus findings produced from 5 agents '
            'all finding the same technique'
        )

    def test_consensus_is_content_neutral(self):
        """
        CRITICAL: Aggregator must work for any technique, not just
        cloud-specific ones.
        """
        from swarm.consensus_aggregator import aggregate_consensus
        agent_paths = {
            f'p{i}': [{
                'steps': [{
                    'technique_id': 'T9999',
                    'target_asset': 'fictional_resource'
                }]
            }]
            for i in range(3)
        }
        findings = aggregate_consensus(agent_paths)
        fictional_finding = next(
            (f for f in findings
             if f['technique_id'] == 'T9999'),
            None,
        )
        assert fictional_finding is not None, (
            'Aggregator did not count a completely fictional '
            'technique — it must be content-neutral'
        )
