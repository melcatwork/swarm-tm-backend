"""
Tests that all four run types accept, preserve, and return
attack paths of up to 10 steps without truncation.

These tests are structural — they do not check specific
technique names, only that step count is preserved and
that path structure is correct at any length up to 10.
"""
import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

FIXTURE_PATH = Path(__file__).parent / 'fixtures' / 'ten_step_chain.json'


class TestChainAssemblerLength:

    def test_max_chain_steps_constant_is_10(self):
        import importlib
        import os
        os.environ.setdefault('SWARM_MAX_CHAIN_STEPS', '10')
        try:
            from app.swarm.vuln_intel.chain_assembler import MAX_CHAIN_STEPS
        except ImportError:
            from app.swarm.chain_assembler import MAX_CHAIN_STEPS
        assert MAX_CHAIN_STEPS == 10, (
            f'MAX_CHAIN_STEPS is {MAX_CHAIN_STEPS}, expected 10'
        )

    def test_assemble_does_not_truncate_long_chain(self):
        """
        Provide 10 matched vulns across 10 distinct phases.
        All 10 must appear in the assembled chain.
        """
        from types import SimpleNamespace
        try:
            from app.swarm.vuln_intel.chain_assembler import ChainAssembler
        except ImportError:
            from app.swarm.chain_assembler import ChainAssembler

        phases = [
            'reconnaissance', 'initial_access', 'execution',
            'persistence', 'privilege_escalation',
            'defense_evasion', 'credential_access', 'discovery',
            'collection', 'exfiltration',
        ]
        matched_vulns = [
            SimpleNamespace(
                vuln_id=f'VULN-{i:03d}',
                name=f'Test vuln {i}',
                description='test',
                resource_id=f'asset_{i}',
                resource_type='aws_instance',
                kill_chain_phase=phase,
                technique_id=f'T100{i}',
                technique_name=f'Technique {i}',
                cvss_score=8.0,
                epss_score=0.1,
                in_kev=False,
                exploitation_difficulty='MEDIUM',
                exploitation_commands=[],
                detection_gap='',
                cloudtrail_logged=True,
                guardduty_detects=False,
                poc_references=[],
                match_confidence='CONFIRMED',
                match_reason='test',
                remediation='test fix',
                risk_score=8.0,
            )
            for i, phase in enumerate(phases)
        ]

        assembler = ChainAssembler()
        chains = assembler.assemble(
            matched_vulns=matched_vulns,
            asset_graph={'assets': [], 'connections': []},
        )
        assert chains, 'No chains produced from 10 matched vulns'
        best = chains[0]
        non_gap = [s for s in best.steps if not s.is_gap_filler]
        assert len(non_gap) == 10, (
            f'Chain has {len(non_gap)} confirmed steps, '
            f'expected 10. Chain was truncated.'
        )

    def test_gap_filling_does_not_cap_total_steps(self):
        """
        3 confirmed steps far apart in the kill chain should
        produce up to 10 total steps with gap fillers inserted,
        not a truncated chain.
        """
        from types import SimpleNamespace
        try:
            from app.swarm.vuln_intel.chain_assembler import ChainAssembler
        except ImportError:
            from app.swarm.chain_assembler import ChainAssembler

        matched_vulns = [
            SimpleNamespace(
                vuln_id='VULN-001',
                name='Entry point',
                description='test',
                resource_id='asset_a',
                resource_type='aws_instance',
                kill_chain_phase='initial_access',
                technique_id='T1190',
                technique_name='Exploit',
                cvss_score=9.0,
                epss_score=0.3,
                in_kev=True,
                exploitation_difficulty='LOW',
                exploitation_commands=['curl http://target'],
                detection_gap='No WAF logs',
                cloudtrail_logged=False,
                guardduty_detects=False,
                poc_references=[],
                match_confidence='CONFIRMED',
                match_reason='signal detected',
                remediation='patch',
                risk_score=9.0,
            ),
            SimpleNamespace(
                vuln_id='VULN-002',
                name='Credential access',
                description='test',
                resource_id='asset_b',
                resource_type='aws_iam_role',
                kill_chain_phase='credential_access',
                technique_id='T1552',
                technique_name='Credentials',
                cvss_score=8.0,
                epss_score=0.2,
                in_kev=False,
                exploitation_difficulty='LOW',
                exploitation_commands=[],
                detection_gap='Not in CloudTrail',
                cloudtrail_logged=False,
                guardduty_detects=False,
                poc_references=[],
                match_confidence='CONFIRMED',
                match_reason='env var detected',
                remediation='use secrets manager',
                risk_score=8.0,
            ),
            SimpleNamespace(
                vuln_id='VULN-003',
                name='Exfiltration',
                description='test',
                resource_id='asset_c',
                resource_type='aws_s3_bucket',
                kill_chain_phase='exfiltration',
                technique_id='T1530',
                technique_name='Data from Cloud Storage',
                cvss_score=9.5,
                epss_score=0.4,
                in_kev=True,
                exploitation_difficulty='LOW',
                exploitation_commands=['aws s3 sync'],
                detection_gap='No S3 data events',
                cloudtrail_logged=False,
                guardduty_detects=False,
                poc_references=[],
                match_confidence='CONFIRMED',
                match_reason='no bucket policy',
                remediation='add bucket policy',
                risk_score=9.5,
            ),
        ]

        assembler = ChainAssembler()
        chains = assembler.assemble(
            matched_vulns=matched_vulns,
            asset_graph={'assets': [], 'connections': []},
        )
        assert chains, 'No chains produced'
        best = chains[0]
        total = len(best.steps)
        print(
            f'\n  Total steps with gap fillers: {total}'
            f'\n  Confirmed steps: '
            f'{len([s for s in best.steps if not s.is_gap_filler])}'
        )
        assert total >= 3, (
            'Chain has fewer steps than confirmed vulns'
        )
        assert total <= 10, (
            f'Chain has {total} steps — exceeds 10 step maximum'
        )


class TestOutputFilterPreservesLength:

    def test_long_grounded_path_not_truncated(self):
        from app.swarm.output_filter import filter_and_rank_paths
        from types import SimpleNamespace

        ctx = SimpleNamespace(
            matched_vulns=[
                SimpleNamespace(
                    vuln_id=f'CONF-{i:03d}',
                    technique_id=f'T100{i}',
                    match_confidence='CONFIRMED',
                    cvss_v3_severity='HIGH',
                    risk_score=8.0,
                )
                for i in range(10)
            ],
            assembled_chains=[],
            cloud_signals=[],
            app_findings=[],
        )

        ten_step_path = {
            'path_id': 'test-long-path',
            'adjusted_composite_score': 8.0,
            'grounded_in_confirmed_vuln': False,
            'steps': [
                {
                    'step_number': i + 1,
                    'technique_id': f'T100{i}',
                    'asset_id': f'asset_{i}',
                    'kill_chain_phase': 'initial_access',
                    'vuln_id': f'CONF-{i:03d}',
                    'description': f'Step {i + 1}',
                }
                for i in range(10)
            ],
        }

        result = filter_and_rank_paths(
            paths=[ten_step_path],
            vuln_context=ctx,
        )
        assert result, 'Path was filtered out entirely'
        assert len(result[0]['steps']) == 10, (
            f'Steps were truncated: got {len(result[0]["steps"])}'
            ' expected 10'
        )

    def test_synthesised_path_includes_all_steps(self):
        from app.swarm.output_filter import extract_confirmed_findings_as_paths
        from types import SimpleNamespace

        steps = [
            SimpleNamespace(
                technique_id=f'T100{i}',
                technique_name=f'Tech {i}',
                phase=f'phase_{i}',
                resource_id=f'asset_{i}',
                vuln_id=f'CONF-{i:03d}',
                description=f'Step {i+1}',
                exploitation_commands=[],
                detection_gap='',
                is_gap_filler=False,
            )
            for i in range(10)
        ]

        chain = SimpleNamespace(
            chain_id='test-chain',
            chain_name='Ten step test chain',
            steps=steps,
            chain_score=8.5,
            has_kev_vuln=True,
            undetectable_steps=2,
            summary='Test chain with 10 steps',
        )

        ctx = SimpleNamespace(
            matched_vulns=[
                SimpleNamespace(
                    vuln_id=f'CONF-{i:03d}',
                    match_confidence='CONFIRMED',
                )
                for i in range(10)
            ],
            assembled_chains=[chain],
            cloud_signals=[],
            app_findings=[],
        )

        paths = extract_confirmed_findings_as_paths(ctx)
        assert paths, 'No synthesised paths produced'
        assert len(paths[0]['steps']) == 10, (
            f'Synthesised path has {len(paths[0]["steps"])} steps,'
            ' expected 10'
        )


class TestFixtureStructure:

    def test_fixture_exists(self):
        assert FIXTURE_PATH.exists(), (
            f'Fixture not found at {FIXTURE_PATH}. '
            'Run Task 7 to create it.'
        )

    def test_fixture_has_ten_steps(self):
        with open(FIXTURE_PATH) as f:
            data = json.load(f)
        steps = data.get('steps', [])
        assert len(steps) == 10, (
            f'Fixture has {len(steps)} steps, expected 10'
        )

    def test_fixture_steps_are_numbered_correctly(self):
        with open(FIXTURE_PATH) as f:
            data = json.load(f)
        for i, step in enumerate(data['steps'], 1):
            assert step.get('step_number') == i, (
                f'Step {i} has step_number '
                f'{step.get("step_number")}'
            )

    def test_fixture_covers_multiple_phases(self):
        with open(FIXTURE_PATH) as f:
            data = json.load(f)
        phases = {
            s.get('kill_chain_phase')
            for s in data['steps']
        }
        assert len(phases) >= 6, (
            f'Fixture only covers {len(phases)} phases, '
            'should cover at least 6 distinct phases'
        )

    def test_fixture_has_required_fields_on_every_step(self):
        with open(FIXTURE_PATH) as f:
            data = json.load(f)
        required = {
            'step_number', 'technique_id', 'technique_name',
            'kill_chain_phase', 'asset_id', 'description',
        }
        for step in data['steps']:
            missing = required - set(step.keys())
            assert not missing, (
                f'Step {step.get("step_number")} missing: '
                f'{missing}'
            )


class TestResponseSchemaAcceptsLongPaths:

    def test_attack_path_model_accepts_10_steps(self):
        """
        Find and instantiate the AttackPath or equivalent
        Pydantic model with 10 steps. Should not raise.
        """
        import importlib
        import os

        step_data = {
            'step_number': 1,
            'technique_id': 'T1190',
            'technique_name': 'Exploit',
            'kill_chain_phase': 'initial_access',
            'target_asset': 'test_asset',
            'action_description': 'test step',
            'outcome': 'test outcome',
        }

        # Try to find the model
        model_locations = [
            ('app.swarm.models', 'AttackPath'),
            ('app.swarm.schemas', 'AttackPath'),
            ('app.swarm.types', 'AttackPath'),
            ('app.routers.models', 'AttackPath'),
        ]

        model_class = None
        for module_path, class_name in model_locations:
            try:
                mod = importlib.import_module(module_path)
                model_class = getattr(mod, class_name, None)
                if model_class:
                    break
            except ImportError:
                continue

        if model_class is None:
            pytest.skip(
                'AttackPath model not found — check model '
                'location and update model_locations list'
            )

        # Try instantiating with 10 steps
        try:
            path = model_class(
                id='test-ten-step',
                name='Ten step test',
                objective='Test objective',
                threat_actor='Test Actor',
                impact_type='confidentiality',
                difficulty='medium',
                steps=[step_data] * 10,
            )
            assert len(path.steps) == 10
        except Exception as e:
            pytest.fail(
                f'AttackPath model rejected 10 steps: {e}'
            )
