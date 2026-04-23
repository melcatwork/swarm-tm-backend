import asyncio
import httpx
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from .intel_db import IntelDatabase

logger = logging.getLogger(__name__)

# Terraform resource type to software keyword mapping
# Used to build the resource_type_cve_index
RESOURCE_SOFTWARE_MAP = {
    'aws_db_instance': [
        'mysql', 'postgres', 'postgresql', 'oracle',
        'sqlserver', 'mariadb', 'aurora',
    ],
    'aws_rds_cluster': ['aurora', 'mysql', 'postgresql'],
    'aws_elasticache_cluster': ['redis', 'memcached'],
    'aws_elasticache_replication_group': ['redis'],
    'aws_eks_cluster': ['kubernetes', 'eks'],
    'aws_eks_node_group': ['kubernetes', 'eks', 'linux'],
    'aws_lambda_function': [
        'python', 'nodejs', 'java', 'dotnet', 'ruby', 'go',
    ],
    'aws_elastic_beanstalk_environment': [
        'tomcat', 'nginx', 'apache', 'nodejs', 'python',
    ],
    'aws_elasticsearch_domain': ['elasticsearch', 'opensearch'],
    'aws_opensearch_domain': ['opensearch', 'elasticsearch'],
    'aws_mq_broker': ['activemq', 'rabbitmq'],
    'aws_instance': [
        'linux', 'ubuntu', 'amazon linux', 'openssl',
        'openssh', 'apache', 'nginx',
    ],
    'aws_ecs_task_definition': [
        'docker', 'container', 'linux',
    ],
    'aws_lb': ['nginx', 'http2'],
    'aws_api_gateway_rest_api': ['api gateway'],
    'aws_cognito_user_pool': ['cognito'],
    'aws_s3_bucket': ['s3'],
    'aws_iam_role': ['iam'],
    'aws_security_group': ['network'],
}

# CPE prefix to Terraform resource type mapping
# Used to auto-classify NVD CVEs to resource types
CPE_TO_RESOURCE = {
    'cpe:2.3:a:postgresql': ['aws_db_instance', 'aws_rds_cluster'],
    'cpe:2.3:a:mysql': ['aws_db_instance', 'aws_rds_cluster'],
    'cpe:2.3:a:oracle:mysql': ['aws_db_instance'],
    'cpe:2.3:a:mariadb': ['aws_db_instance'],
    'cpe:2.3:a:redis': [
        'aws_elasticache_cluster',
        'aws_elasticache_replication_group',
    ],
    'cpe:2.3:a:pivotal_software:spring_framework': [
        'aws_lambda_function',
        'aws_elastic_beanstalk_environment',
    ],
    'cpe:2.3:a:apache:log4j': ['aws_lambda_function'],
    'cpe:2.3:a:apache:activemq': ['aws_mq_broker'],
    'cpe:2.3:a:kubernetes': ['aws_eks_cluster', 'aws_eks_node_group'],
    'cpe:2.3:a:openssl': ['aws_instance', 'aws_lambda_function'],
    'cpe:2.3:o:linux': ['aws_instance', 'aws_eks_node_group'],
    'cpe:2.3:a:openbsd:openssh': ['aws_instance'],
    'cpe:2.3:a:nodejs': ['aws_lambda_function'],
    'cpe:2.3:a:python': ['aws_lambda_function'],
    'cpe:2.3:a:elastic:elasticsearch': [
        'aws_elasticsearch_domain',
        'aws_opensearch_domain',
    ],
    'cpe:2.3:a:amazon:amazon_web_services': [
        'aws_instance', 'aws_s3_bucket',
        'aws_iam_role', 'aws_lambda_function',
    ],
}

class IntelSyncer:
    """
    Pulls threat intelligence from authoritative sources and
    writes normalised records to the local SQLite database.

    Sources:
      - NVD REST API v2 (CVEs)
      - CISA KEV JSON feed (exploited CVEs)
      - EPSS CSV bulk download (exploitability scores)
      - OSV.dev REST API (open source package vulns)
      - ATT&CK STIX bundle (cloud techniques)
      - CloudSploit GitHub (cloud misconfig checks)
      - GitHub Advisory Database GraphQL API (PoC evidence)
    """

    NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    KEV_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
               'known_exploited_vulnerabilities.json')
    EPSS_URL = ('https://epss.cyentia.com/epss_scores-current.csv.gz')
    EPSS_SIMPLE = 'https://api.first.org/data/v1/epss'
    OSV_URL = 'https://api.osv.dev/v1/query'
    ATTCK_URL = ('https://raw.githubusercontent.com/mitre/cti/'
                 'master/enterprise-attack/enterprise-attack.json')
    CLOUDSPLOIT_URL = ('https://raw.githubusercontent.com/'
                       'aquasecurity/cloudsploit/master/plugins/')
    GHSA_URL = 'https://api.github.com/advisories'

    def __init__(
        self,
        db: IntelDatabase,
        nvd_api_key: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.db = db
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token

    async def sync_all(self, force: bool = False):
        state = self.db.get_sync_state()
        tasks = []
        if self._needs_sync(state, 'KEV', hours=24) or force:
            tasks.append(self.sync_kev())
        if self._needs_sync(state, 'EPSS', hours=24) or force:
            tasks.append(self.sync_epss())
        if self._needs_sync(state, 'NVD', hours=168) or force:
            tasks.append(self.sync_nvd_recent())
        if self._needs_sync(state, 'ATTCK', hours=168) or force:
            tasks.append(self.sync_attck_cloud())
        if self._needs_sync(state, 'OSV', hours=168) or force:
            tasks.append(self.sync_osv())
        if self._needs_sync(state, 'GHSA', hours=168) or force:
            tasks.append(self.sync_github_advisories())
        results = await asyncio.gather(
            *tasks, return_exceptions=True
        )
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f'Sync task failed: {r}')

    def _needs_sync(
        self,
        state: dict,
        source: str,
        hours: int,
    ) -> bool:
        if source not in state:
            return True
        last = state[source].get('last_sync', '')
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
            return datetime.utcnow() - last_dt > timedelta(
                hours=hours
            )
        except Exception:
            return True

    async def sync_kev(self):
        logger.info('Syncing CISA KEV...')
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(self.KEV_URL)
                resp.raise_for_status()
                data = resp.json()
            kev_ids = {}
            for v in data.get('vulnerabilities', []):
                kev_ids[v['cveID']] = v.get('dateAdded', '')
            # Update in_kev flag for all matching CVEs
            for cve_id, date_added in kev_ids.items():
                self.db.upsert_cve({
                    'cve_id': cve_id,
                    'description': '',
                    'cvss_v3_score': 0.0,
                    'cvss_v3_severity': 'UNKNOWN',
                    'epss_score': 0.0,
                    'epss_percentile': 0.0,
                    'in_kev': 1,
                    'kev_date_added': date_added,
                    'affected_products_json': '[]',
                    'affected_versions': '',
                    'cpe_matches_json': '[]',
                    'technique_ids_json': '["T1190"]',
                    'kill_chain_phase': 'initial_access',
                    'poc_in_github': 0,
                    'nuclei_template_exists': 0,
                    'metasploit_module_exists': 0,
                    'references_json': '[]',
                    'published_date': '',
                    'last_modified': '',
                    'source': 'KEV',
                })
            self.db.update_sync_state('KEV', len(kev_ids))
            logger.info(f'KEV sync: {len(kev_ids)} entries')
        except Exception as e:
            logger.error(f'KEV sync failed: {e}')

    async def sync_epss(self):
        logger.info('Syncing EPSS scores...')
        try:
            # Use the simple API for recent high-scoring CVEs
            # rather than the full bulk download
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    self.EPSS_SIMPLE,
                    params={
                        'order': 'epss-desc',
                        'limit': 1000,
                    }
                )
                resp.raise_for_status()
                data = resp.json()
            count = 0
            for item in data.get('data', []):
                cve_id = item.get('cve', '')
                if not cve_id:
                    continue
                # Update EPSS score for existing CVEs
                # or insert placeholder for new ones
                self.db.upsert_cve({
                    'cve_id': cve_id,
                    'description': '',
                    'cvss_v3_score': 0.0,
                    'cvss_v3_severity': 'UNKNOWN',
                    'epss_score': float(item.get('epss', 0)),
                    'epss_percentile': float(
                        item.get('percentile', 0)
                    ),
                    'in_kev': 0,
                    'kev_date_added': None,
                    'affected_products_json': '[]',
                    'affected_versions': '',
                    'cpe_matches_json': '[]',
                    'technique_ids_json': '["T1190"]',
                    'kill_chain_phase': 'initial_access',
                    'poc_in_github': 0,
                    'nuclei_template_exists': 0,
                    'metasploit_module_exists': 0,
                    'references_json': '[]',
                    'published_date': '',
                    'last_modified': '',
                    'source': 'EPSS',
                })
                count += 1
            self.db.update_sync_state('EPSS', count)
            logger.info(f'EPSS sync: {count} scores')
        except Exception as e:
            logger.error(f'EPSS sync failed: {e}')

    async def sync_nvd_recent(self, days_back: int = 120):
        logger.info(f'Syncing NVD (last {days_back} days)...')
        pub_start = (
            datetime.utcnow() - timedelta(days=days_back)
        ).strftime('%Y-%m-%dT00:00:00.000')
        pub_end = datetime.utcnow().strftime(
            '%Y-%m-%dT23:59:59.999'
        )
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        start_index = 0
        results_per_page = 2000
        total_processed = 0
        while True:
            params = {
                'pubStartDate': pub_start,
                'pubEndDate': pub_end,
                'startIndex': start_index,
                'resultsPerPage': results_per_page,
            }
            try:
                async with httpx.AsyncClient(
                    timeout=60.0
                ) as client:
                    resp = await client.get(
                        self.NVD_API,
                        params=params,
                        headers=headers,
                    )
                    if resp.status_code == 429:
                        wait = 30 if self.nvd_api_key else 6
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as e:
                logger.warning(f'NVD page failed: {e}')
                break
            vulns = data.get('vulnerabilities', [])
            for v in vulns:
                parsed = self._parse_nvd_entry(v)
                if parsed:
                    self.db.upsert_cve(parsed)
                    self._index_cve_for_resources(parsed)
                    total_processed += 1
            total_results = data.get('totalResults', 0)
            start_index += results_per_page
            if start_index >= total_results:
                break
            # Rate limiting
            await asyncio.sleep(
                0.6 if self.nvd_api_key else 6.0
            )
        self.db.update_sync_state('NVD', total_processed)
        logger.info(f'NVD sync: {total_processed} CVEs')

    def _parse_nvd_entry(self, raw: dict) -> Optional[dict]:
        cve = raw.get('cve', {})
        cve_id = cve.get('id', '')
        if not cve_id:
            return None
        desc_list = cve.get('descriptions', [])
        description = next(
            (d.get('value', '') for d in desc_list
             if d.get('lang') == 'en'),
            ''
        )
        metrics = cve.get('metrics', {})
        cvss_score = 0.0
        cvss_severity = 'UNKNOWN'
        for key in ['cvssMetricV31', 'cvssMetricV30',
                    'cvssMetricV2']:
            if key in metrics and metrics[key]:
                m = metrics[key][0].get('cvssData', {})
                cvss_score = float(m.get('baseScore', 0.0))
                cvss_severity = m.get(
                    'baseSeverity',
                    m.get('accessVector', 'UNKNOWN')
                )
                break
        cpe_matches = []
        configs = cve.get('configurations', [])
        for config in configs:
            for node in config.get('nodes', []):
                for cpe in node.get('cpeMatch', []):
                    uri = cpe.get('criteria', '')
                    if uri:
                        cpe_matches.append(uri)
        refs = [
            r.get('url', '')
            for r in cve.get('references', [])
            if r.get('url')
        ]
        technique_ids = self._infer_techniques(description)
        return {
            'cve_id': cve_id,
            'description': description[:1000],
            'cvss_v3_score': cvss_score,
            'cvss_v3_severity': cvss_severity,
            'epss_score': 0.0,
            'epss_percentile': 0.0,
            'in_kev': 0,
            'kev_date_added': None,
            'affected_products_json': json.dumps([]),
            'affected_versions': '',
            'cpe_matches_json': json.dumps(cpe_matches[:20]),
            'technique_ids_json': json.dumps(technique_ids),
            'kill_chain_phase': self._infer_phase(
                technique_ids
            ),
            'poc_in_github': 0,
            'nuclei_template_exists': 0,
            'metasploit_module_exists': 0,
            'references_json': json.dumps(refs[:10]),
            'published_date': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'source': 'NVD',
        }

    def _index_cve_for_resources(self, parsed: dict):
        cpe_matches = json.loads(
            parsed.get('cpe_matches_json', '[]')
        )
        cve_id = parsed.get('cve_id', '')
        if not cve_id:
            return
        indexed = set()
        for cpe in cpe_matches:
            cpe_lower = cpe.lower()
            for prefix, resource_types in CPE_TO_RESOURCE.items():
                if cpe_lower.startswith(prefix.lower()):
                    for rt in resource_types:
                        if (rt, cpe_lower[:40]) not in indexed:
                            keyword = prefix.split(':')[-1]
                            self.db.index_cve_for_resource(
                                rt, cve_id, keyword
                            )
                            indexed.add((rt, cpe_lower[:40]))

    def _infer_techniques(self, description: str) -> list[str]:
        desc = description.lower()
        techniques = []
        if any(w in desc for w in [
            'remote code execution', 'rce',
            'command injection', 'code injection'
        ]):
            techniques.append('T1190')
        if any(w in desc for w in [
            'privilege escalation', 'elevation of privilege',
            'root access', 'administrator'
        ]):
            techniques.append('T1548')
        if any(w in desc for w in [
            'information disclosure', 'credential',
            'password', 'sensitive information',
            'plaintext'
        ]):
            techniques.append('T1552')
        if any(w in desc for w in [
            'denial of service', 'dos', 'crash',
            'memory exhaustion'
        ]):
            techniques.append('T1499')
        if any(w in desc for w in [
            'authentication bypass', 'auth bypass',
            'unauthenticated'
        ]):
            techniques.append('T1078')
        if any(w in desc for w in [
            'sql injection', 'sqli', 'nosql injection'
        ]):
            techniques.append('T1190')
        if any(w in desc for w in [
            'path traversal', 'directory traversal',
            'lfi', 'local file inclusion'
        ]):
            techniques.append('T1083')
        if any(w in desc for w in [
            'ssrf', 'server-side request forgery'
        ]):
            techniques.append('T1190')
        if any(w in desc for w in [
            'container escape', 'docker escape',
            'namespace escape'
        ]):
            techniques.append('T1611')
        if not techniques:
            techniques.append('T1190')
        return list(set(techniques))

    def _infer_phase(self, technique_ids: list) -> str:
        phase_map = {
            'T1190': 'initial_access',
            'T1078': 'initial_access',
            'T1548': 'privilege_escalation',
            'T1552': 'credential_access',
            'T1499': 'impact',
            'T1083': 'discovery',
            'T1611': 'privilege_escalation',
        }
        for tid in technique_ids:
            if tid in phase_map:
                return phase_map[tid]
        return 'initial_access'

    async def sync_attck_cloud(self):
        logger.info('Syncing ATT&CK Cloud techniques...')
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(self.ATTCK_URL)
                resp.raise_for_status()
                bundle = resp.json()
        except Exception as e:
            logger.error(f'ATT&CK sync failed: {e}')
            return
        cloud_techniques = []
        for obj in bundle.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            platforms = obj.get('x_mitre_platforms', [])
            if not any(p in platforms for p in [
                'AWS', 'Azure', 'GCP',
                'IaaS', 'SaaS', 'Containers',
            ]):
                continue
            technique_id = ''
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', '')
                    break
            if not technique_id:
                continue
            desc = obj.get('description', '')
            kill_chain = 'initial_access'
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    kill_chain = phase.get(
                        'phase_name', 'initial_access'
                    ).replace('-', '_')
                    break
            resource_types = self._map_technique_to_resources(
                technique_id, platforms
            )
            abuse_id = f'ATTCK-{technique_id.replace(".", "-")}'
            self.db.upsert_abuse({
                'abuse_id': abuse_id,
                'name': obj.get('name', technique_id),
                'source': 'ATTCK',
                'category': kill_chain.upper(),
                'cloud_providers_json': json.dumps(
                    [p for p in platforms
                     if p in ('AWS', 'Azure', 'GCP',
                               'IaaS', 'SaaS')]
                ),
                'affected_terraform_resources_json': json.dumps(
                    resource_types
                ),
                'description': desc[:500],
                'kill_chain_phase': kill_chain,
                'technique_id': technique_id,
                'technique_name': obj.get('name', ''),
                'exploitation_difficulty': 'MEDIUM',
                'exploitation_commands_json': '[]',
                'detection_gap': '',
                'cloudtrail_logged': 1,
                'guardduty_finding': None,
                'remediation': '',
                'references_json': json.dumps([
                    ref.get('url', '')
                    for ref in obj.get('external_references', [])
                    if ref.get('url')
                ][:3]),
                'cvss_equivalent': 7.0,
            })
            cloud_techniques.append(technique_id)
        self.db.update_sync_state('ATTCK', len(cloud_techniques))
        logger.info(
            f'ATT&CK sync: {len(cloud_techniques)} cloud techniques'
        )

    def _map_technique_to_resources(
        self,
        technique_id: str,
        platforms: list,
    ) -> list[str]:
        # Map ATT&CK techniques to Terraform resource types
        TECH_RESOURCE_MAP = {
            'T1552.005': [
                'aws_instance', 'aws_launch_template'
            ],
            'T1530': ['aws_s3_bucket', 'aws_s3_object'],
            'T1537': ['aws_s3_bucket'],
            'T1078.004': ['aws_iam_role', 'aws_iam_user'],
            'T1548': ['aws_iam_role', 'aws_iam_policy'],
            'T1136.003': ['aws_iam_user', 'aws_iam_role'],
            'T1562.008': ['aws_cloudtrail'],
            'T1190': [
                'aws_instance', 'aws_lb',
                'aws_api_gateway_rest_api',
            ],
            'T1609': ['aws_ecs_task_definition'],
            'T1610': ['aws_ecs_service'],
            'T1611': [
                'aws_ecs_task_definition',
                'aws_eks_cluster',
            ],
            'T1525': ['aws_ecr_repository'],
            'T1578': ['aws_instance', 'aws_eks_cluster'],
        }
        resources = TECH_RESOURCE_MAP.get(technique_id, [])
        if not resources:
            # Generic mapping based on platform
            if 'AWS' in platforms or 'IaaS' in platforms:
                resources = ['aws_instance']
        return resources

    async def sync_osv(self):
        logger.info('Syncing OSV.dev...')
        ecosystems = ['PyPI', 'npm', 'Maven', 'Go', 'RubyGems']
        count = 0
        for ecosystem in ecosystems:
            try:
                async with httpx.AsyncClient(
                    timeout=30.0
                ) as client:
                    resp = await client.post(
                        'https://api.osv.dev/v1/query',
                        json={
                            'package': {
                                'ecosystem': ecosystem
                            }
                        }
                    )
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                for vuln in data.get('vulns', [])[:200]:
                    osv_id = vuln.get('id', '')
                    if not osv_id:
                        continue
                    # Map OSV ecosystem to Lambda runtimes
                    if ecosystem == 'PyPI':
                        resource_types = ['aws_lambda_function']
                        software_kw = 'python'
                    elif ecosystem == 'npm':
                        resource_types = ['aws_lambda_function']
                        software_kw = 'nodejs'
                    elif ecosystem == 'Maven':
                        resource_types = ['aws_lambda_function']
                        software_kw = 'java'
                    else:
                        resource_types = ['aws_lambda_function']
                        software_kw = ecosystem.lower()
                    severity = vuln.get('database_specific', {})
                    cvss = float(
                        severity.get('cvss_score', 5.0) or 5.0
                    )
                    aliases = vuln.get('aliases', [])
                    cve_alias = next(
                        (a for a in aliases
                         if a.startswith('CVE-')), osv_id
                    )
                    self.db.upsert_cve({
                        'cve_id': cve_alias,
                        'description': vuln.get(
                            'summary', ''
                        )[:500],
                        'cvss_v3_score': cvss,
                        'cvss_v3_severity': (
                            'CRITICAL' if cvss >= 9.0
                            else 'HIGH' if cvss >= 7.0
                            else 'MEDIUM'
                        ),
                        'epss_score': 0.0,
                        'epss_percentile': 0.0,
                        'in_kev': 0,
                        'kev_date_added': None,
                        'affected_products_json': json.dumps(
                            [ecosystem]
                        ),
                        'affected_versions': str(
                            vuln.get('affected', [{}])[0]
                            .get('ranges', [{}])[0]
                            .get('events', '')
                        )[:100],
                        'cpe_matches_json': '[]',
                        'technique_ids_json': '["T1190"]',
                        'kill_chain_phase': 'initial_access',
                        'poc_in_github': 0,
                        'nuclei_template_exists': 0,
                        'metasploit_module_exists': 0,
                        'references_json': json.dumps(
                            vuln.get('references', [])[:3]
                        ),
                        'published_date': vuln.get(
                            'published', ''
                        ),
                        'last_modified': vuln.get(
                            'modified', ''
                        ),
                        'source': f'OSV/{ecosystem}',
                    })
                    for rt in resource_types:
                        self.db.index_cve_for_resource(
                            rt, cve_alias, software_kw
                        )
                    count += 1
                await asyncio.sleep(1.0)
            except Exception as e:
                logger.warning(f'OSV {ecosystem} failed: {e}')
        self.db.update_sync_state('OSV', count)
        logger.info(f'OSV sync: {count} entries')

    async def sync_github_advisories(self):
        logger.info('Syncing GitHub Advisory Database...')
        if not self.github_token:
            logger.info(
                'No GITHUB_TOKEN — skipping GHSA sync. '
                'Set GITHUB_TOKEN env var to enable.'
            )
            return
        headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github+json',
        }
        count = 0
        page = 1
        while page <= 5:  # max 500 advisories per sync
            try:
                async with httpx.AsyncClient(
                    timeout=30.0
                ) as client:
                    resp = await client.get(
                        self.GHSA_URL,
                        headers=headers,
                        params={
                            'per_page': 100,
                            'page': page,
                            'severity': 'high,critical',
                            'ecosystem': (
                                'pip,npm,maven,rubygems,go'
                            ),
                        }
                    )
                    if resp.status_code != 200:
                        break
                    advisories = resp.json()
                    if not advisories:
                        break
            except Exception as e:
                logger.warning(f'GHSA page {page} failed: {e}')
                break
            for adv in advisories:
                ghsa_id = adv.get('ghsa_id', '')
                cve_id = adv.get('cve_id') or ghsa_id
                if not cve_id:
                    continue
                # Mark CVE as having GitHub PoC evidence
                # if references contain exploit links
                refs = adv.get('references', [])
                has_poc = any(
                    'exploit' in r.lower()
                    or 'poc' in r.lower()
                    or 'proof' in r.lower()
                    for r in refs
                )
                cvss = float(
                    adv.get('cvss', {}).get('score', 5.0) or 5.0
                )
                self.db.upsert_cve({
                    'cve_id': cve_id,
                    'description': adv.get(
                        'description', ''
                    )[:500],
                    'cvss_v3_score': cvss,
                    'cvss_v3_severity': adv.get(
                        'severity', 'HIGH'
                    ).upper(),
                    'epss_score': 0.0,
                    'epss_percentile': 0.0,
                    'in_kev': 0,
                    'kev_date_added': None,
                    'affected_products_json': json.dumps(
                        [v.get('package', {}).get('name', '')
                         for v in adv.get(
                             'vulnerabilities', []
                         )]
                    ),
                    'affected_versions': '',
                    'cpe_matches_json': '[]',
                    'technique_ids_json': '["T1190"]',
                    'kill_chain_phase': 'initial_access',
                    'poc_in_github': 1 if has_poc else 0,
                    'nuclei_template_exists': 0,
                    'metasploit_module_exists': 0,
                    'references_json': json.dumps(refs[:5]),
                    'published_date': adv.get(
                        'published_at', ''
                    ),
                    'last_modified': adv.get(
                        'updated_at', ''
                    ),
                    'source': 'GHSA',
                })
                count += 1
            page += 1
            await asyncio.sleep(1.0)
        self.db.update_sync_state('GHSA', count)
        logger.info(f'GHSA sync: {count} advisories')
