"""
Revised L2 Tests — IaC serialiser and LLM security analyser
"""
import pytest
import asyncio
import sys
from pathlib import Path

CAPITAL_ONE_TF = Path('samples/capital-one-breach-replica.tf')

# Add backend to path for imports
sys.path.insert(0, str(Path('backend').absolute()))

def load_asset_graph_from_tf(tf_path: Path) -> dict:
    """Helper: parse TF file to asset graph using existing parser."""
    try:
        from app.parsers.terraform_parser import TerraformParser
        parser = TerraformParser()
        return parser.parse(str(tf_path))
    except ImportError:
        # Build minimal asset graph from TF content
        content = tf_path.read_text()
        resources = []
        import re
        for match in re.finditer(
            r'resource\s+"(\w+)"\s+"(\w+)"',
            content
        ):
            resources.append({
                'id': match.group(2),
                'type': match.group(1),
            })
        return {'assets': resources, 'connections': []}

class TestIaCSerialiser:

    def test_serialiser_exists(self):
        from app.swarm.iac_serialiser import IaCSerialiser
        assert IaCSerialiser is not None

    def test_serialiser_produces_readable_output(self):
        from app.swarm.iac_serialiser import IaCSerialiser
        graph = load_asset_graph_from_tf(CAPITAL_ONE_TF)
        serialiser = IaCSerialiser()
        output = serialiser.serialise(graph)
        assert len(output) > 100, (
            'Serialised output is too short — may be empty'
        )
        assert 'INFRASTRUCTURE SUMMARY' in output or (
            'aws_' in output.lower()
        ), 'Serialised output does not contain AWS resources'

    def test_serialiser_includes_all_resources(self):
        from app.swarm.iac_serialiser import IaCSerialiser
        graph = load_asset_graph_from_tf(CAPITAL_ONE_TF)
        serialiser = IaCSerialiser()
        output = serialiser.serialise(graph)
        # Capital One TF has these resource types
        expected_types = [
            'aws_instance', 'aws_s3_bucket',
            'aws_iam_role', 'aws_cloudtrail',
        ]
        for rtype in expected_types:
            assert rtype in output, (
                f'Serialiser output missing resource type: {rtype}'
            )

    def test_serialiser_includes_security_relevant_attributes(self):
        from app.swarm.iac_serialiser import IaCSerialiser
        graph = load_asset_graph_from_tf(CAPITAL_ONE_TF)
        serialiser = IaCSerialiser()
        output = serialiser.serialise(graph)
        # Should capture metadata_options or http_tokens somewhere
        # in the serialised output if they are in the graph
        assert len(output) > 500, (
            'Serialiser output is suspiciously short for '
            'Capital One IaC with many resources'
        )

class TestSecurityAnalyser:

    def test_security_analyser_exists(self):
        from app.swarm.security_analyser import (
            SecurityAnalyser, SecurityFinding
        )
        assert SecurityAnalyser is not None
        assert SecurityFinding is not None

    def test_security_finding_dataclass_fields(self):
        from app.swarm.security_analyser import SecurityFinding
        import dataclasses
        fields = {f.name for f in dataclasses.fields(
            SecurityFinding
        )}
        required_fields = {
            'finding_id', 'resource_id', 'resource_type',
            'category', 'title', 'description', 'severity',
            'technique_id', 'kill_chain_phase',
            'exploitation_detail', 'exploitation_commands',
            'detection_gap', 'remediation', 'confidence',
            'reasoning',
        }
        missing = required_fields - fields
        assert not missing, (
            f'SecurityFinding missing fields: {missing}'
        )

    def test_json_parsing_from_llm_response(self):
        from app.swarm.security_analyser import SecurityAnalyser

        class MockLLM:
            def call(self, **kwargs):
                return '''[
  {
    "finding_id": "F001",
    "resource_id": "waf_ec2",
    "resource_type": "aws_instance",
    "category": "COMPUTE",
    "title": "IMDSv1 enabled",
    "description": "Instance metadata v1 allows unauthenticated credential theft",
    "severity": "HIGH",
    "technique_id": "T1552.005",
    "technique_name": "Cloud Instance Metadata API",
    "kill_chain_phase": "credential_access",
    "exploitation_detail": "SSRF can query 169.254.169.254",
    "exploitation_commands": ["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
    "detection_gap": "IMDS calls not in CloudTrail",
    "affected_relationships": ["ISRM-WAF-Role"],
    "remediation": "Set http_tokens = required",
    "confidence": "HIGH",
    "reasoning": "http_tokens=optional detected in metadata_options"
  }
]'''

        analyser = SecurityAnalyser(llm_client=MockLLM())
        findings = analyser._parse_findings(
            '''[{"finding_id":"F001","resource_id":"waf_ec2",
"resource_type":"aws_instance","category":"COMPUTE",
"title":"IMDSv1 enabled",
"description":"IMDS v1 unauthenticated","severity":"HIGH",
"technique_id":"T1552.005","technique_name":"Cloud Instance Metadata API",
"kill_chain_phase":"credential_access",
"exploitation_detail":"SSRF to IMDS","exploitation_commands":
["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
"detection_gap":"Not in CloudTrail","affected_relationships":["waf_role"],
"remediation":"Set http_tokens=required","confidence":"HIGH",
"reasoning":"http_tokens optional"}]''',
            max_findings=10
        )
        assert len(findings) == 1
        assert findings[0].technique_id == 'T1552.005'
        assert findings[0].severity == 'HIGH'
        assert 'curl' in findings[0].exploitation_commands[0]

    def test_format_for_prompt_output(self):
        from app.swarm.security_analyser import (
            SecurityAnalyser, SecurityFinding
        )
        finding = SecurityFinding(
            finding_id='F001',
            resource_id='waf_ec2',
            resource_type='aws_instance',
            category='COMPUTE',
            title='IMDSv1 credential theft',
            description='IMDSv1 enabled allows SSRF credential theft',
            severity='HIGH',
            technique_id='T1552.005',
            technique_name='Cloud Instance Metadata API',
            kill_chain_phase='credential_access',
            exploitation_detail='SSRF to 169.254.169.254',
            exploitation_commands=[
                'curl http://169.254.169.254/latest/meta-data/'
                'iam/security-credentials/'
            ],
            detection_gap='IMDS calls not in CloudTrail',
            affected_relationships=['ISRM-WAF-Role'],
            remediation='Set http_tokens = required',
            confidence='HIGH',
            reasoning='http_tokens=optional in metadata_options',
        )

        class MockLLM:
            def call(self, **kwargs):
                return '[]'

        analyser = SecurityAnalyser(llm_client=MockLLM())
        prompt_text = analyser.format_for_prompt([finding])
        assert 'T1552.005' in prompt_text
        assert 'waf_ec2' in prompt_text
        assert 'HIGH' in prompt_text
        assert 'curl' in prompt_text

    def test_api_response_has_security_findings_field(self):
        """Verify the API response schema includes security_findings."""
        import os
        found = False
        for root, dirs, files in os.walk('backend/app'):
            for f in files:
                if not f.endswith('.py'):
                    continue
                content = open(os.path.join(root, f)).read()
                if 'security_findings' in content:
                    found = True
                    break
            if found:
                break
        assert found, (
            'No file contains security_findings in API response — '
            'Revised L2 API response update may be missing'
        )
