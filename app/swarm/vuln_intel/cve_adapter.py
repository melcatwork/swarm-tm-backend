from dataclasses import dataclass
from typing import Optional
from .intel_db import IntelDatabase, CVEEntry, AbusePattern

@dataclass
class CVEMatch:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v3_severity: str
    epss_score: float
    epss_percentile: float
    in_kev: bool
    kev_date_added: Optional[str]
    affected_product: str
    affected_version_range: str
    technique_ids: list[str]
    poc_available: bool
    poc_references: list[str]
    remediation: str
    matched_resource_id: str
    matched_resource_type: str
    match_reason: str

class CVEAdapter:
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.db = IntelDatabase()

    async def find_cves_for_asset_graph(
        self,
        asset_graph: dict,
        max_per_resource: int = 5,
    ) -> list[CVEMatch]:
        matches = []
        for asset in asset_graph.get('assets', []):
            resource_type = asset.get('type', '')
            software = (
                asset.get('engine')
                or asset.get('runtime')
                or asset.get('engine_type')
                or ''
            )
            version = (
                asset.get('engine_version')
                or asset.get('runtime_version')
                or asset.get('cluster_version')
                or ''
            )
            entries = self.db.get_cves_for_resource(
                resource_type=resource_type,
                software=software,
                version=version,
                limit=max_per_resource,
            )
            for entry in entries:
                matches.append(CVEMatch(
                    cve_id=entry.cve_id,
                    description=entry.description,
                    cvss_v3_score=entry.cvss_v3_score,
                    cvss_v3_severity=entry.cvss_v3_severity,
                    epss_score=entry.epss_score,
                    epss_percentile=entry.epss_percentile,
                    in_kev=entry.in_kev,
                    kev_date_added=entry.kev_date_added,
                    affected_product=software or resource_type,
                    affected_version_range=entry.affected_versions,
                    technique_ids=entry.technique_ids,
                    poc_available=(
                        entry.poc_in_github
                        or entry.nuclei_template_exists
                        or entry.metasploit_module_exists
                    ),
                    poc_references=entry.references,
                    remediation=entry.remediation,
                    matched_resource_id=asset.get('id', ''),
                    matched_resource_type=resource_type,
                    match_reason=(
                        f'{resource_type} {software} {version}'
                        f' matched CVE database'
                    ),
                ))
        return matches
