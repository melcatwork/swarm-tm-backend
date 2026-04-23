"""
Revised L3 Tests — Selective ATT&CK technique reference
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path('backend').absolute()))

class TestRevisedL3KB:

    def test_kb_yaml_exists(self):
        kb_path = Path('backend/app/swarm/knowledge/cloud_ttp_kb.yaml')
        assert kb_path.exists(), 'cloud_ttp_kb.yaml not found'

    def test_kb_has_extended_techniques(self):
        import yaml
        with open('backend/app/swarm/knowledge/cloud_ttp_kb.yaml') as f:
            kb = yaml.safe_load(f)
        techniques = kb.get('techniques', {})
        # New techniques added in Revised L3
        new_techniques = [
            'T1537', 'T1021.007', 'T1136.003',
            'T1098.001', 'T1526', 'T1619',
            'T1609', 'T1610', 'T1611',
        ]
        missing = [
            t for t in new_techniques if t not in techniques
        ]
        assert not missing, (
            f'KB missing new techniques from Revised L3: {missing}'
        )

    def test_get_techniques_for_findings_exists(self):
        from app.swarm.knowledge.kb_loader import (
            get_techniques_for_findings
        )
        assert get_techniques_for_findings is not None

    def test_selective_injection_only_relevant_techniques(self):
        from app.swarm.knowledge.kb_loader import (
            get_techniques_for_findings
        )
        from app.swarm.security_analyser import SecurityFinding

        # Create findings that only reference T1552.005 and T1530
        findings = [
            SecurityFinding(
                finding_id='F001',
                resource_id='waf_ec2',
                resource_type='aws_instance',
                category='COMPUTE',
                title='IMDSv1',
                description='IMDSv1 enabled',
                severity='HIGH',
                technique_id='T1552.005',
                technique_name='Cloud Instance Metadata API',
                kill_chain_phase='credential_access',
                exploitation_detail='',
                exploitation_commands=[],
                detection_gap='',
                affected_relationships=[],
                remediation='',
                confidence='HIGH',
                reasoning='',
            ),
            SecurityFinding(
                finding_id='F002',
                resource_id='customer_data',
                resource_type='aws_s3_bucket',
                category='STORAGE',
                title='S3 wildcard',
                description='s3:* on all resources',
                severity='HIGH',
                technique_id='T1530',
                technique_name='Data from Cloud Storage',
                kill_chain_phase='exfiltration',
                exploitation_detail='',
                exploitation_commands=[],
                detection_gap='',
                affected_relationships=[],
                remediation='',
                confidence='HIGH',
                reasoning='',
            ),
        ]
        result = get_techniques_for_findings(findings)
        # Should contain T1552.005 and T1530
        assert 'T1552.005' in result or 'Cloud Instance' in result
        assert 'T1530' in result or 'Cloud Storage' in result
        # Should NOT inject unrelated techniques like T1609
        assert 'T1609' not in result, (
            'Selective injection is including irrelevant techniques'
        )

    def test_kb_entries_have_aws_implementation(self):
        import yaml
        with open('backend/app/swarm/knowledge/cloud_ttp_kb.yaml') as f:
            kb = yaml.safe_load(f)
        techniques = kb.get('techniques', {})
        for tid, entry in techniques.items():
            has_aws = (
                'aws' in str(entry).lower()
                or 'aws_implementation' in entry
                or 'cloud_platforms' in entry
            )
            assert has_aws, (
                f'Technique {tid} in KB has no AWS implementation '
                f'detail — add aws: block'
            )
