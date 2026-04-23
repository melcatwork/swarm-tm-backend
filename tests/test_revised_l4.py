"""
Revised L4 Tests — LLM path evaluator and finding-based seeding
"""
import pytest
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path('backend').absolute()))

from app.swarm.path_evaluator import PathEvaluator, PathEvaluationResult
from app.swarm.security_analyser import SecurityFinding

def make_finding(
    fid, rid, rtype, technique, phase, severity='HIGH'
) -> SecurityFinding:
    return SecurityFinding(
        finding_id=fid,
        resource_id=rid,
        resource_type=rtype,
        category='COMPUTE',
        title=f'Finding {fid}',
        description=f'Security issue on {rid}',
        severity=severity,
        technique_id=technique,
        technique_name=technique,
        kill_chain_phase=phase,
        exploitation_detail='',
        exploitation_commands=[],
        detection_gap='',
        affected_relationships=[],
        remediation='',
        confidence='HIGH',
        reasoning='',
    )

class MockLLMGoodScore:
    def call(self, **kwargs):
        return '''{
  "evidence_score": 9.0,
  "cloud_specificity": 8.5,
  "technique_accuracy": 9.0,
  "exploitability": 8.0,
  "detection_evasion": 7.5,
  "grounded_findings": ["F001", "F002"],
  "ungrounded_steps": [],
  "evaluator_reasoning": "Path correctly uses IMDSv1 chain",
  "improvement_suggestions": "None needed"
}'''

class MockLLMBadScore:
    def call(self, **kwargs):
        return '''{
  "evidence_score": 2.0,
  "cloud_specificity": 1.5,
  "technique_accuracy": 2.0,
  "exploitability": 3.0,
  "detection_evasion": 2.0,
  "grounded_findings": [],
  "ungrounded_steps": ["web shell — no evidence in IaC"],
  "evaluator_reasoning": "Path uses web shell but no web server found",
  "improvement_suggestions": "Use IMDSv1 credential theft instead"
}'''

class TestPathEvaluator:

    def test_evaluator_exists(self):
        assert PathEvaluator is not None
        assert PathEvaluationResult is not None

    def test_good_path_scores_high(self):
        evaluator = PathEvaluator(llm_client=MockLLMGoodScore())
        path = {
            'path_id': 'test_path_1',
            'name': 'IMDSv1 credential theft chain',
            'steps': [
                {
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing App',
                    'asset_id': 'waf_ec2',
                    'description': 'SSRF on WAF',
                },
                {
                    'technique_id': 'T1552.005',
                    'technique_name': 'Cloud Instance Metadata API',
                    'asset_id': 'waf_ec2',
                    'description': 'IMDS credential theft',
                },
                {
                    'technique_id': 'T1530',
                    'technique_name': 'Data from Cloud Storage',
                    'asset_id': 'customer_data',
                    'description': 'S3 exfiltration',
                },
            ],
        }
        findings = [
            make_finding('F001', 'waf_ec2', 'aws_instance',
                         'T1552.005', 'credential_access'),
            make_finding('F002', 'customer_data', 'aws_s3_bucket',
                         'T1530', 'exfiltration'),
        ]
        result = asyncio.run(evaluator.evaluate_path(
            path, findings, {}
        ))
        assert result.composite_score > 7.0, (
            f'Good cloud-native path scored too low: '
            f'{result.composite_score}'
        )
        assert len(result.grounded_findings) > 0

    def test_bad_path_scores_low(self):
        evaluator = PathEvaluator(llm_client=MockLLMBadScore())
        path = {
            'path_id': 'test_path_2',
            'name': 'Web shell path',
            'steps': [
                {
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing App',
                    'asset_id': 'waf_ec2',
                    'description': 'Initial access',
                },
                {
                    'technique_id': 'T1505.003',
                    'technique_name': 'Web Shell',
                    'asset_id': 'app_server',
                    'description': 'Deploy web shell',
                },
                {
                    'technique_id': 'T1005',
                    'technique_name': 'Data from Local System',
                    'asset_id': 'credit_db',
                    'description': 'Collect DB data',
                },
            ],
        }
        findings = [
            make_finding('F001', 'waf_ec2', 'aws_instance',
                         'T1552.005', 'credential_access'),
        ]
        result = asyncio.run(evaluator.evaluate_path(
            path, findings, {}
        ))
        assert result.composite_score < 5.0, (
            f'Poor non-cloud path scored too high: '
            f'{result.composite_score}'
        )
        assert len(result.ungrounded_steps) > 0

    def test_evaluator_result_has_all_fields(self):
        evaluator = PathEvaluator(llm_client=MockLLMGoodScore())
        result = asyncio.run(evaluator.evaluate_path(
            {'path_id': 'p1', 'steps': []}, [], {}
        ))
        assert hasattr(result, 'evidence_score')
        assert hasattr(result, 'cloud_specificity')
        assert hasattr(result, 'technique_accuracy')
        assert hasattr(result, 'exploitability')
        assert hasattr(result, 'detection_evasion')
        assert hasattr(result, 'composite_score')
        assert hasattr(result, 'grounded_findings')
        assert hasattr(result, 'ungrounded_steps')

    def test_no_hard_coded_chain_patterns(self):
        """Verify CloudContextScorer hard-coded patterns removed."""
        import os
        for root, dirs, files in os.walk('backend/app/swarm'):
            for f in files:
                if not f.endswith('.py'):
                    continue
                content = open(os.path.join(root, f)).read()
                # The old hard-coded chain list from original L4
                assert 'CLOUD_CHAINS = [' not in content, (
                    f'{f} still contains hard-coded CLOUD_CHAINS '
                    f'list — remove CloudContextScorer'
                )

    def test_finding_based_seeding_function_exists(self):
        try:
            from app.swarm.incident_pheromone_seeder import (
                seed_from_findings
            )
            found = True
        except ImportError:
            # May be in a different module
            import os
            found = False
            for root, dirs, files in os.walk('backend/app/swarm'):
                for f in files:
                    if not f.endswith('.py'):
                        continue
                    content = open(
                        os.path.join(root, f)
                    ).read()
                    if 'seed_from_findings' in content:
                        found = True
                        break
                if found:
                    break
        assert found, (
            'seed_from_findings not found anywhere — '
            'Revised L4 finding-based seeding not implemented'
        )
