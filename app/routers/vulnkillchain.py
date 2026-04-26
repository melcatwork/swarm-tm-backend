"""
VulnKillChain Router - CVE Search + MITRE ATT&CK Mapping
Migrated from standalone vulnkillchain-backend to unified swarm-tm backend
"""

from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List, Dict, Any
import httpx
from datetime import datetime

router = APIRouter(
    prefix="/api/cve",
    tags=["CVE Intelligence"]
)

# Data source URLs
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# MITRE ATT&CK tactic IDs (Enterprise)
ATTACK_TACTICS = {
    "TA0001": {"name": "Initial Access", "phase": 1},
    "TA0002": {"name": "Execution", "phase": 2},
    "TA0003": {"name": "Persistence", "phase": 3},
    "TA0004": {"name": "Privilege Escalation", "phase": 4},
    "TA0005": {"name": "Defense Evasion", "phase": 5},
    "TA0006": {"name": "Credential Access", "phase": 6},
    "TA0007": {"name": "Discovery", "phase": 7},
    "TA0008": {"name": "Lateral Movement", "phase": 8},
    "TA0009": {"name": "Collection", "phase": 9},
    "TA0010": {"name": "Command and Control", "phase": 10},
    "TA0011": {"name": "Exfiltration", "phase": 11},
    "TA0040": {"name": "Impact", "phase": 12},
}

# CVE to ATT&CK technique mapping - High-profile vulnerabilities with confirmed attack patterns
CVE_ATTACK_MAPPING = {
    # Log4Shell family - Remote code execution via JNDI injection
    "CVE-2021-44228": ["T1190", "T1059.007", "T1071.001", "T1105", "T1059"],  # Log4Shell
    "CVE-2021-45046": ["T1190", "T1059.007", "T1071.001"],  # Log4Shell bypass
    "CVE-2021-45105": ["T1190", "T1499"],  # Log4Shell DoS
    "CVE-2021-44832": ["T1190", "T1059.007"],  # Log4Shell RCE variant

    # ProxyLogon/ProxyShell - Microsoft Exchange
    "CVE-2021-26855": ["T1190", "T1133", "T1505.003"],  # ProxyLogon - SSRF
    "CVE-2021-27065": ["T1190", "T1505.003", "T1083"],  # ProxyLogon - Arbitrary file write
    "CVE-2021-34473": ["T1190", "T1083", "T1505.003"],  # ProxyShell - Path traversal
    "CVE-2021-34523": ["T1190", "T1068"],  # ProxyShell - Privilege escalation
    "CVE-2021-31207": ["T1190", "T1210"],  # ProxyShell - RCE

    # PrintNightmare - Windows Print Spooler
    "CVE-2021-34527": ["T1068", "T1210", "T1021.002"],  # PrintNightmare RCE
    "CVE-2021-1675": ["T1068", "T1547.012"],  # Print Spooler LPE

    # Zerologon - Windows Netlogon
    "CVE-2020-1472": ["T1210", "T1558", "T1003.006", "T1207"],  # Zerologon

    # EternalBlue/DoublePulsar - SMB
    "CVE-2017-0144": ["T1210", "T1021.002", "T1059", "T1543"],  # EternalBlue
    "CVE-2017-0145": ["T1210", "T1021.002"],  # SMBv1 RCE

    # BlueKeep - RDP
    "CVE-2019-0708": ["T1210", "T1021.001", "T1059"],  # BlueKeep RDP RCE

    # Cisco IOS XE Web UI
    "CVE-2023-20198": ["T1190", "T1078", "T1136.001"],  # Privilege escalation + account creation
    "CVE-2023-20273": ["T1190", "T1059"],  # Command injection

    # MOVEit Transfer SQL injection
    "CVE-2023-34362": ["T1190", "T1505.003", "T1005", "T1041"],  # SQL injection + webshell
    "CVE-2023-35036": ["T1190", "T1505.003"],  # Auth bypass
    "CVE-2023-35708": ["T1190", "T1505.003"],  # SQL injection

    # Chrome/V8 vulnerabilities
    "CVE-2023-4863": ["T1189", "T1203", "T1055"],  # WebP heap overflow
    "CVE-2023-5217": ["T1189", "T1203"],  # libvpx heap overflow
    "CVE-2023-2033": ["T1189", "T1203"],  # V8 type confusion
    "CVE-2022-1096": ["T1189", "T1203"],  # V8 type confusion

    # Microsoft Office
    "CVE-2023-36884": ["T1566.001", "T1203", "T1059"],  # Office RCE
    "CVE-2023-21716": ["T1566.001", "T1203"],  # Word heap corruption
    "CVE-2022-30190": ["T1566.001", "T1203", "T1218.001"],  # Follina - msdt
    "CVE-2017-11882": ["T1566.001", "T1203", "T1059"],  # Equation Editor

    # Palo Alto PAN-OS
    "CVE-2024-3400": ["T1190", "T1059.004", "T1041", "T1005"],  # Command injection + exfil
    "CVE-2024-3387": ["T1190", "T1059.004"],  # GlobalProtect RCE

    # Citrix
    "CVE-2023-3519": ["T1190", "T1059", "T1505.003"],  # NetScaler ADC/Gateway RCE
    "CVE-2023-4966": ["T1190", "T1552.001", "T1539"],  # Citrix Bleed - session hijacking
    "CVE-2019-19781": ["T1190", "T1083", "T1059"],  # Citrix ADC path traversal

    # Fortinet
    "CVE-2022-42475": ["T1190", "T1083", "T1552.001"],  # FortiOS SSL-VPN heap overflow
    "CVE-2023-27997": ["T1190", "T1059", "T1505.003"],  # FortiOS SSL-VPN RCE

    # VMware
    "CVE-2023-34048": ["T1190", "T1562.001", "T1059"],  # vCenter DCERPC RCE
    "CVE-2021-22005": ["T1190", "T1083", "T1505.003"],  # vCenter file upload
    "CVE-2021-21972": ["T1190", "T1059", "T1505.003"],  # vSphere Client RCE

    # Apache Struts
    "CVE-2017-5638": ["T1190", "T1059", "T1071.001"],  # Struts2 RCE
    "CVE-2018-11776": ["T1190", "T1059"],  # Struts2 RCE
    "CVE-2017-9805": ["T1190", "T1059"],  # Struts2 REST RCE

    # Spring Framework
    "CVE-2022-22965": ["T1190", "T1059", "T1505.003"],  # Spring4Shell
    "CVE-2022-22963": ["T1190", "T1059"],  # Spring Cloud RCE

    # Atlassian
    "CVE-2022-26134": ["T1190", "T1059"],  # Confluence OGNL injection
    "CVE-2023-22515": ["T1190", "T1136.001", "T1078"],  # Confluence privilege escalation
    "CVE-2023-22518": ["T1190", "T1005", "T1041"],  # Confluence data exfiltration

    # SolarWinds
    "CVE-2020-10148": ["T1190", "T1059", "T1105"],  # Orion API auth bypass
    "CVE-2021-35211": ["T1195.002", "T1071.001", "T1027"],  # SUNBURST supply chain

    # Ivanti Connect Secure (Pulse Secure)
    "CVE-2023-46805": ["T1190", "T1562.001"],  # Authentication bypass
    "CVE-2024-21887": ["T1190", "T1059", "T1505.003"],  # Command injection
    "CVE-2024-21893": ["T1190", "T1505.003"],  # SSRF

    # Adobe ColdFusion
    "CVE-2023-26360": ["T1190", "T1083", "T1552.001"],  # Arbitrary file read
    "CVE-2023-29298": ["T1190", "T1190", "T1059"],  # Deserialization RCE

    # Telerik UI
    "CVE-2019-18935": ["T1190", "T1059", "T1574.002"],  # Deserialization RCE

    # WordPress plugins
    "CVE-2023-38035": ["T1190", "T1059", "T1505.003"],  # BackupBuddy RCE

    # Android
    "CVE-2019-2215": ["T1068", "T1404"],  # Binder use-after-free

    # iOS
    "CVE-2023-41992": ["T1068", "T1404"],  # Kernel LPE
    "CVE-2023-41991": ["T1189", "T1203"],  # WebKit RCE

    # CISA KEV Notable Ransomware-associated
    "CVE-2023-27532": ["T1190", "T1552.001"],  # Veeam Backup credentials
    "CVE-2023-0669": ["T1190", "T1059"],  # Fortra GoAnywhere RCE
    "CVE-2023-28252": ["T1068", "T1055"],  # Windows CLFS LPE

    # GPU/Graphics drivers
    "CVE-2023-25516": ["T1068", "T1543"],  # NVIDIA GPU Display Driver

    # WinRAR
    "CVE-2023-38831": ["T1204.002", "T1059"],  # WinRAR path traversal

    # 3CX supply chain
    "CVE-2023-29059": ["T1195.002", "T1071.001", "T1005"],  # 3CX supply chain

    # Zyxel
    "CVE-2023-28771": ["T1190", "T1059"],  # Zyxel firewall command injection
}


@router.get("/health")
async def health_check():
    """Health check endpoint for CVE intelligence service"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "VulnKillChain CVE Intelligence"
    }


@router.get("/search")
async def search_cves(
    product: str = Query(..., description="Product name to search"),
    vendor: Optional[str] = Query(None, description="Vendor name"),
    limit: int = Query(10, ge=1, le=50)
) -> Dict[str, Any]:
    """
    Search for CVEs by product name
    Uses NVD API
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        params = {
            "keywordSearch": product,
            "resultsPerPage": limit
        }
        if vendor:
            params["keywordSearch"] = f"{vendor} {product}"

        try:
            response = await client.get(NVD_API_URL, params=params)
            response.raise_for_status()
            data = response.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}

                cves.append({
                    "id": cve_id,
                    "description": cve.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": cvss_data.get("baseScore", "N/A"),
                    "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                    "published": cve.get("published", ""),
                    "references": [
                        ref.get("url", "")
                        for ref in cve.get("references", [])[:5]
                    ]
                })

            return {
                "product": product,
                "vendor": vendor,
                "count": len(cves),
                "cves": cves
            }

        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"NVD API error: {str(e)}")


@router.get("/attack/{cve_id}")
async def get_attack_mapping(cve_id: str) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK mapping for a CVE
    Returns kill chain phases in Mermaid format
    Includes patches, mitigations, detection, and recovery
    """
    cve_id = cve_id.upper()

    # Get CVE details
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{NVD_API_URL}?cveId={cve_id}")
            response.raise_for_status()
            data = response.json()

            if not data.get("vulnerabilities"):
                raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

            cve = data["vulnerabilities"][0]["cve"]
            description = cve.get("descriptions", [{}])[0].get("value", "")

            # Extract references
            references = cve.get("references", [])

            # Extract patches, mitigations, detection, recovery from references
            patches = []
            mitigations = []
            detection_methods = []
            recovery_steps = []

            for ref in references:
                url = ref.get("url", "")
                ref_tags = ref.get("tags", [])

                # Patches
                if any(tag in ref_tags for tag in ["Patch", "Vendor Advisory"]):
                    if "patch" not in url.lower() and "fix" not in url.lower():
                        continue
                    patches.append({"url": url, "source": ref.get("source", "")})

                # Mitigations
                if "mitigation" in url.lower() or "workaround" in url.lower():
                    mitigations.append({"url": url, "source": ref.get("source", "")})

                # Detection
                if any(tag in ["Exploit", "Tool", "Vulnerability Analysis"] for tag in ref_tags):
                    detection_methods.append({"url": url, "source": ref.get("source", "")})

            # Also check reference URLs for keywords
            for ref in references:
                url = ref.get("url", "").lower()
                if "patch" in url or "fix" in url or "update" in url:
                    if not any(p["url"] == ref.get("url") for p in patches):
                        patches.append({"url": ref.get("url"), "source": ref.get("source", "")})
                if "mitigat" in url or "workaround" in url or "prevent" in url:
                    if not any(m["url"] == ref.get("url") for m in mitigations):
                        mitigations.append({"url": ref.get("url"), "source": ref.get("source", "")})
                if "detect" in url or "indicator" in url or "splunk" in url or "yara" in url or "snort" in url:
                    if not any(d["url"] == ref.get("url") for d in detection_methods):
                        detection_methods.append({"url": ref.get("url"), "source": ref.get("source", "")})
                if "recover" in url or "remediat" in url or "incident" in url:
                    recovery_steps.append({"url": ref.get("url"), "source": ref.get("source", "")})

            # Get metrics
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})

            cvss_info = {
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString")
            }

        except httpx.HTTPError:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

    # Get techniques from mapping (or infer from description)
    techniques = CVE_ATTACK_MAPPING.get(cve_id, [])

    # Infer techniques from CVE description (simple keyword matching)
    if not techniques:
        techniques = infer_attack_techniques(description)

    # Build kill chain phases
    kill_chain = []
    used_phases = set()

    for tech_id in techniques:
        # Map technique to tactic (simplified)
        tactic = technique_to_tactic(tech_id)
        if tactic and tactic["id"] not in used_phases:
            kill_chain.append({
                "phase": tactic["phase"],
                "tactic_id": tactic["id"],
                "tactic_name": tactic["name"],
                "technique_id": tech_id,
            })
            used_phases.add(tactic["id"])

    # Sort by phase
    kill_chain.sort(key=lambda x: x["phase"])

    # Generate Mermaid flowchart
    mermaid_graph = generate_mermaid_killchain(cve_id, kill_chain)

    return {
        "cve_id": cve_id,
        "description": description[:500],
        "cvss": cvss_info,
        "techniques": techniques,
        "kill_chain": kill_chain,
        "mermaid": mermaid_graph,
        "patches": patches[:5],
        "mitigations": mitigations[:5],
        "detection": detection_methods[:5],
        "recovery": recovery_steps[:5]
    }


@router.get("/cisa-kev/list")
async def get_cisa_kev(limit: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    """Get list of known exploited vulnerabilities from CISA KEV"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulnerabilities", [])[:limit]

            return {
                "count": len(vulns),
                "vulnerabilities": [
                    {
                        "cve_id": v.get("cveID"),
                        "vendor": v.get("vendorProject"),
                        "product": v.get("product"),
                        "date_added": v.get("dateAdded"),
                        "short_description": v.get("shortDescription", "")[:200],
                    }
                    for v in vulns
                ]
            }

        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"CISA KEV error: {str(e)}")


@router.get("/epss/{cve_id}")
async def get_epss(cve_id: str) -> Dict[str, Any]:
    """Get EPSS (Exploit Prediction Scoring System) score for a CVE"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(EPSS_API_URL, params={"cve": cve_id})
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "OK" and data.get("data"):
                return {
                    "cve_id": cve_id,
                    "epss_score": float(data["data"][0]["epss"]),
                    "percentile": float(data["data"][0]["percentile"]),
                    "date": data["data"][0]["date"]
                }
            else:
                raise HTTPException(status_code=404, detail=f"No EPSS data for {cve_id}")

        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"EPSS API error: {str(e)}")


def infer_attack_techniques(description: str) -> List[str]:
    """Comprehensive inference of ATT&CK techniques from CVE description"""
    description = description.lower()
    techniques = []

    # Expanded CVE to technique mappings with sub-techniques
    keyword_map = {
        # Initial Access (TA0001)
        "remote code execution": ["T1190", "T1059"],
        "rce": ["T1190", "T1059"],
        "arbitrary code": ["T1190", "T1059"],
        "exploit public": ["T1190"],
        "unauthenticated": ["T1190"],
        "phishing": ["T1566"],
        "spearphishing": ["T1566.001"],
        "drive-by": ["T1189"],
        "watering hole": ["T1189"],
        "supply chain": ["T1195"],
        "trusted relationship": ["T1199"],
        "vpn": ["T1133"],
        "remote desktop": ["T1133"],

        # Execution (TA0002)
        "command injection": ["T1059"],
        "code injection": ["T1059"],
        "script": ["T1059"],
        "powershell": ["T1059.001"],
        "shell": ["T1059"],
        "bash": ["T1059.004"],
        "python": ["T1059.006"],
        "javascript": ["T1059.007"],
        "wmi": ["T1047"],
        "scheduled task": ["T1053"],
        "cron": ["T1053.003"],
        "native api": ["T1106"],
        "rundll32": ["T1218.011"],
        "regsvr32": ["T1218.010"],

        # Persistence (TA0003)
        "backdoor": ["T1543", "T1546"],
        "registry": ["T1547.001"],
        "startup": ["T1547"],
        "service": ["T1543"],
        "account creation": ["T1136"],
        "web shell": ["T1505.003"],
        "bootkit": ["T1542"],
        "scheduled task": ["T1053"],

        # Privilege Escalation (TA0004)
        "privilege escalation": ["T1068"],
        "elevation": ["T1068"],
        "sudo": ["T1548.003"],
        "setuid": ["T1548.001"],
        "token manipulation": ["T1134"],
        "dll hijack": ["T1574.001"],
        "dylib hijack": ["T1574.004"],
        "process injection": ["T1055"],

        # Defense Evasion (TA0005)
        "bypass": ["T1562"],
        "obfuscation": ["T1027"],
        "obfuscate": ["T1027"],
        "encoded": ["T1027"],
        "masquerade": ["T1036"],
        "rootkit": ["T1014"],
        "disable": ["T1562"],
        "hidden": ["T1564"],
        "sandbox": ["T1497"],
        "virtualization": ["T1497"],
        "anti-virus": ["T1562.001"],
        "indicator removal": ["T1070"],
        "clear logs": ["T1070.001"],
        "timestomp": ["T1070.006"],
        "reflective": ["T1620"],

        # Credential Access (TA0006)
        "credential": ["T1110", "T1003"],
        "password": ["T1110", "T1555"],
        "brute force": ["T1110"],
        "credential dump": ["T1003"],
        "lsass": ["T1003.001"],
        "sam": ["T1003.002"],
        "ntds": ["T1003.003"],
        "mimikatz": ["T1003"],
        "keylog": ["T1056.001"],
        "input capture": ["T1056"],
        "network sniff": ["T1040"],
        "man-in-the-middle": ["T1557"],
        "mitm": ["T1557"],
        "kerberos": ["T1558"],
        "golden ticket": ["T1558.001"],
        "silver ticket": ["T1558.002"],

        # Discovery (TA0007)
        "directory traversal": ["T1083"],
        "path traversal": ["T1083"],
        "file inclusion": ["T1083"],
        "information disclosure": ["T1083", "T1082"],
        "enumeration": ["T1087", "T1069"],
        "network scan": ["T1046"],
        "port scan": ["T1046"],
        "system information": ["T1082"],
        "account discovery": ["T1087"],
        "domain trust": ["T1482"],

        # Lateral Movement (TA0008)
        "lateral movement": ["T1021"],
        "rdp": ["T1021.001"],
        "smb": ["T1021.002"],
        "ssh": ["T1021.004"],
        "remote service": ["T1021"],
        "pass the hash": ["T1550.002"],
        "pass the ticket": ["T1550.003"],

        # Collection (TA0009)
        "data exfiltration": ["T1005", "T1041"],
        "screen capture": ["T1113"],
        "clipboard": ["T1115"],
        "keylog": ["T1056.001"],
        "audio capture": ["T1123"],
        "video capture": ["T1125"],

        # Command and Control (TA0010)
        "command and control": ["T1071"],
        "c2": ["T1071"],
        "c&c": ["T1071"],
        "beacon": ["T1071"],
        "dns tunnel": ["T1071.004"],
        "http": ["T1071.001"],
        "https": ["T1071.001"],
        "proxy": ["T1090"],
        "remote access": ["T1219"],
        "encrypted channel": ["T1573"],

        # Exfiltration (TA0011)
        "exfiltration": ["T1041"],
        "data transfer": ["T1041"],
        "upload": ["T1567"],
        "cloud storage": ["T1567.002"],

        # Impact (TA0040)
        "ransomware": ["T1486"],
        "encryption": ["T1486"],
        "wiper": ["T1485"],
        "data destruction": ["T1485"],
        "denial of service": ["T1498"],
        "dos": ["T1499"],
        "ddos": ["T1498"],
        "defacement": ["T1491"],
        "resource hijack": ["T1496"],
        "cryptojacking": ["T1496"],

        # Vulnerability-specific patterns
        "sql injection": ["T1190"],
        "sqli": ["T1190"],
        "xss": ["T1189"],
        "cross-site scripting": ["T1189"],
        "csrf": ["T1189"],
        "xxe": ["T1190"],
        "xml external entity": ["T1190"],
        "ssrf": ["T1190"],
        "server-side request forgery": ["T1190"],
        "deserialization": ["T1190", "T1059"],
        "memory corruption": ["T1190"],
        "buffer overflow": ["T1190"],
        "heap overflow": ["T1190"],
        "stack overflow": ["T1190"],
        "use-after-free": ["T1190"],
        "double free": ["T1190"],
        "integer overflow": ["T1190"],
        "format string": ["T1190"],
        "race condition": ["T1190"],
        "idor": ["T1083"],
        "insecure direct object": ["T1083"],
        "authentication bypass": ["T1078"],
        "authorization bypass": ["T1548"],
    }

    # Score-based approach: count keyword matches
    technique_scores = {}

    for keyword, techs in keyword_map.items():
        if keyword in description:
            for tech in techs:
                technique_scores[tech] = technique_scores.get(tech, 0) + 1

    # Sort by score and take top techniques
    sorted_techniques = sorted(technique_scores.items(), key=lambda x: x[1], reverse=True)
    techniques = [tech for tech, score in sorted_techniques]

    return techniques[:8]  # Limit to 8 most relevant techniques


def technique_to_tactic(technique_id: str) -> Optional[Dict]:
    """Map a technique ID to its primary tactic - Comprehensive MITRE ATT&CK Enterprise v15"""
    # Extract base technique (handle sub-techniques like T1059.001)
    base_technique = technique_id.split('.')[0]

    # Comprehensive technique to tactic mapping (first 100 mappings shown, full mapping would continue)
    mapping = {
        # TA0001 - Initial Access
        "T1190": ("TA0001", "Initial Access"),
        "T1133": ("TA0001", "Initial Access"),
        "T1200": ("TA0001", "Initial Access"),
        "T1566": ("TA0001", "Initial Access"),
        "T1091": ("TA0001", "Initial Access"),
        "T1195": ("TA0001", "Initial Access"),
        "T1199": ("TA0001", "Initial Access"),
        "T1078": ("TA0001", "Initial Access"),
        "T1189": ("TA0001", "Initial Access"),
        "T1659": ("TA0001", "Initial Access"),
        "T1656": ("TA0001", "Initial Access"),

        # TA0002 - Execution
        "T1059": ("TA0002", "Execution"),
        "T1203": ("TA0002", "Execution"),
        "T1559": ("TA0002", "Execution"),
        "T1106": ("TA0002", "Execution"),
        "T1053": ("TA0002", "Execution"),
        "T1129": ("TA0002", "Execution"),
        "T1072": ("TA0002", "Execution"),
        "T1569": ("TA0002", "Execution"),
        "T1204": ("TA0002", "Execution"),
        "T1047": ("TA0002", "Execution"),

        # TA0003 - Persistence
        "T1098": ("TA0003", "Persistence"),
        "T1547": ("TA0003", "Persistence"),
        "T1136": ("TA0003", "Persistence"),
        "T1543": ("TA0003", "Persistence"),
        "T1546": ("TA0003", "Persistence"),
        "T1505": ("TA0003", "Persistence"),

        # TA0004 - Privilege Escalation
        "T1548": ("TA0004", "Privilege Escalation"),
        "T1134": ("TA0004", "Privilege Escalation"),
        "T1068": ("TA0004", "Privilege Escalation"),
        "T1574": ("TA0004", "Privilege Escalation"),
        "T1055": ("TA0004", "Privilege Escalation"),

        # TA0005 - Defense Evasion
        "T1027": ("TA0005", "Defense Evasion"),
        "T1070": ("TA0005", "Defense Evasion"),
        "T1036": ("TA0005", "Defense Evasion"),
        "T1562": ("TA0005", "Defense Evasion"),
        "T1564": ("TA0005", "Defense Evasion"),
        "T1014": ("TA0005", "Defense Evasion"),
        "T1218": ("TA0005", "Defense Evasion"),
        "T1497": ("TA0005", "Defense Evasion"),
        "T1620": ("TA0005", "Defense Evasion"),

        # TA0006 - Credential Access
        "T1110": ("TA0006", "Credential Access"),
        "T1003": ("TA0006", "Credential Access"),
        "T1555": ("TA0006", "Credential Access"),
        "T1056": ("TA0006", "Credential Access"),
        "T1040": ("TA0006", "Credential Access"),
        "T1557": ("TA0006", "Credential Access"),
        "T1558": ("TA0006", "Credential Access"),
        "T1552": ("TA0006", "Credential Access"),

        # TA0007 - Discovery
        "T1083": ("TA0007", "Discovery"),
        "T1087": ("TA0007", "Discovery"),
        "T1046": ("TA0007", "Discovery"),
        "T1082": ("TA0007", "Discovery"),
        "T1069": ("TA0007", "Discovery"),
        "T1057": ("TA0007", "Discovery"),
        "T1018": ("TA0007", "Discovery"),
        "T1482": ("TA0007", "Discovery"),

        # TA0008 - Lateral Movement
        "T1210": ("TA0008", "Lateral Movement"),
        "T1021": ("TA0008", "Lateral Movement"),
        "T1550": ("TA0008", "Lateral Movement"),
        "T1570": ("TA0008", "Lateral Movement"),

        # TA0009 - Collection
        "T1005": ("TA0009", "Collection"),
        "T1113": ("TA0009", "Collection"),
        "T1115": ("TA0009", "Collection"),
        "T1123": ("TA0009", "Collection"),
        "T1125": ("TA0009", "Collection"),

        # TA0010 - Command and Control
        "T1071": ("TA0010", "Command and Control"),
        "T1105": ("TA0010", "Command and Control"),
        "T1090": ("TA0010", "Command and Control"),
        "T1219": ("TA0010", "Command and Control"),
        "T1573": ("TA0010", "Command and Control"),

        # TA0011 - Exfiltration
        "T1041": ("TA0011", "Exfiltration"),
        "T1567": ("TA0011", "Exfiltration"),
        "T1048": ("TA0011", "Exfiltration"),

        # TA0040 - Impact
        "T1486": ("TA0040", "Impact"),
        "T1485": ("TA0040", "Impact"),
        "T1498": ("TA0040", "Impact"),
        "T1499": ("TA0040", "Impact"),
        "T1491": ("TA0040", "Impact"),
        "T1496": ("TA0040", "Impact"),
        "T1489": ("TA0040", "Impact"),

        # Sub-techniques
        "T1059.001": ("TA0002", "Execution"),
        "T1059.004": ("TA0002", "Execution"),
        "T1059.006": ("TA0002", "Execution"),
        "T1059.007": ("TA0002", "Execution"),
        "T1547.001": ("TA0003", "Persistence"),
        "T1547.012": ("TA0003", "Persistence"),
        "T1543.003": ("TA0003", "Persistence"),
        "T1136.001": ("TA0003", "Persistence"),
        "T1505.003": ("TA0003", "Persistence"),
        "T1548.001": ("TA0004", "Privilege Escalation"),
        "T1548.003": ("TA0004", "Privilege Escalation"),
        "T1055.001": ("TA0004", "Privilege Escalation"),
        "T1070.001": ("TA0005", "Defense Evasion"),
        "T1070.006": ("TA0005", "Defense Evasion"),
        "T1562.001": ("TA0005", "Defense Evasion"),
        "T1218.001": ("TA0005", "Defense Evasion"),
        "T1218.010": ("TA0005", "Defense Evasion"),
        "T1218.011": ("TA0005", "Defense Evasion"),
        "T1003.001": ("TA0006", "Credential Access"),
        "T1003.002": ("TA0006", "Credential Access"),
        "T1003.003": ("TA0006", "Credential Access"),
        "T1003.006": ("TA0006", "Credential Access"),
        "T1056.001": ("TA0006", "Credential Access"),
        "T1558.001": ("TA0006", "Credential Access"),
        "T1558.002": ("TA0006", "Credential Access"),
        "T1552.001": ("TA0006", "Credential Access"),
        "T1087.001": ("TA0007", "Discovery"),
        "T1069.001": ("TA0007", "Discovery"),
        "T1021.001": ("TA0008", "Lateral Movement"),
        "T1021.002": ("TA0008", "Lateral Movement"),
        "T1021.004": ("TA0008", "Lateral Movement"),
        "T1550.002": ("TA0008", "Lateral Movement"),
        "T1550.003": ("TA0008", "Lateral Movement"),
        "T1071.001": ("TA0010", "Command and Control"),
        "T1071.004": ("TA0010", "Command and Control"),
        "T1195.002": ("TA0001", "Initial Access"),
        "T1207": ("TA0005", "Defense Evasion"),
        "T1404": ("TA0004", "Privilege Escalation"),
        "T1539": ("TA0006", "Credential Access"),
        "T1566.001": ("TA0001", "Initial Access"),
        "T1574.001": ("TA0004", "Privilege Escalation"),
        "T1574.002": ("TA0003", "Persistence"),
        "T1574.004": ("TA0004", "Privilege Escalation"),
        "T1204.002": ("TA0002", "Execution"),
    }

    # Check for exact match first (including sub-techniques)
    if technique_id in mapping:
        tactic_id, tactic_name = mapping[technique_id]
        return {
            "id": tactic_id,
            "name": tactic_name,
            "phase": ATTACK_TACTICS.get(tactic_id, {}).get("phase", 0)
        }

    # Fall back to base technique if sub-technique not found
    if base_technique in mapping and base_technique != technique_id:
        tactic_id, tactic_name = mapping[base_technique]
        return {
            "id": tactic_id,
            "name": tactic_name,
            "phase": ATTACK_TACTICS.get(tactic_id, {}).get("phase", 0)
        }

    return None


def generate_mermaid_killchain(cve_id: str, kill_chain: List[Dict]) -> str:
    """Generate Mermaid flowchart for the kill chain with color-coded tactics using inline styles"""

    # Color palette mapping: tactic ID -> style attributes
    tactic_styles = {
        "TA0001": "fill:#00d4ff,stroke:#00a8cc,stroke-width:2px,color:#000",
        "TA0002": "fill:#0ea5e9,stroke:#0284c7,stroke-width:2px,color:#000",
        "TA0003": "fill:#8b5cf6,stroke:#7c3aed,stroke-width:2px,color:#fff",
        "TA0004": "fill:#a855f7,stroke:#9333ea,stroke-width:2px,color:#fff",
        "TA0005": "fill:#d946ef,stroke:#c026d3,stroke-width:2px,color:#fff",
        "TA0006": "fill:#f97316,stroke:#ea580c,stroke-width:2px,color:#000",
        "TA0007": "fill:#fbbf24,stroke:#f59e0b,stroke-width:2px,color:#000",
        "TA0008": "fill:#facc15,stroke:#eab308,stroke-width:2px,color:#000",
        "TA0009": "fill:#84cc16,stroke:#65a30d,stroke-width:2px,color:#000",
        "TA0010": "fill:#22c55e,stroke:#16a34a,stroke-width:2px,color:#000",
        "TA0011": "fill:#ef4444,stroke:#dc2626,stroke-width:2px,color:#fff",
        "TA0040": "fill:#dc2626,stroke:#b91c1c,stroke-width:2px,color:#fff",
    }

    lines = ["flowchart LR"]

    # Create nodes without class references
    for i, phase in enumerate(kill_chain, 1):
        tactic_id = phase.get("tactic_id", "")
        tactic_name = phase.get("tactic_name", "")
        technique_id = phase.get("technique_id", "")

        # Create node with tactic name and technique ID
        lines.append(f'    P{i}["{tactic_name}<br/>{technique_id}"]')

    # Add inline styles for each node
    for i, phase in enumerate(kill_chain, 1):
        tactic_id = phase.get("tactic_id", "")

        # Get style for this tactic
        style = tactic_styles.get(tactic_id, "fill:#666,stroke:#444,stroke-width:2px,color:#fff")

        # Apply inline style to the node
        lines.append(f"    style P{i} {style}")

    # Add connections between phases with thicker arrows
    for i in range(1, len(kill_chain)):
        lines.append(f"    P{i} ==> P{i+1}")

    # Style the arrow links for visibility
    for i in range(len(kill_chain) - 1):
        lines.append(f"    linkStyle {i} stroke:#000000,stroke-width:3px")

    return "\n".join(lines)


@router.get("/{cve_id}")
async def get_cve_details(cve_id: str):
    """
    Get detailed information about a specific CVE.

    Returns CVE description, CVSS score, severity, published date, and CWE info.
    """
    try:
        # Validate CVE ID format (CVE-YYYY-NNNNN)
        if not cve_id.startswith("CVE-"):
            return JSONResponse(
                status_code=400,
                content={"error": f"Invalid CVE ID format: {cve_id}"}
            )

        # Fetch CVE data from NVD
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            data = response.json()

        # Extract CVE details
        if not data.get("vulnerabilities"):
            return JSONResponse(
                status_code=404,
                content={"error": f"CVE not found: {cve_id}"}
            )

        cve_item = data["vulnerabilities"][0]["cve"]

        # Get CVSS score (prioritize v3.1, fallback to v3.0, then v2.0)
        cvss_score = 0.0
        severity = "Unknown"

        metrics = cve_item.get("metrics", {})
        if metrics.get("cvssMetricV31"):
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "Unknown")
        elif metrics.get("cvssMetricV30"):
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "Unknown")
        elif metrics.get("cvssMetricV2"):
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = "MEDIUM" if cvss_score >= 4.0 else "LOW"

        return {
            "cve_id": cve_id,
            "description": cve_item.get("descriptions", [{}])[0].get("value", "No description available"),
            "cvss_score": cvss_score,
            "severity": severity,
            "published_date": cve_item.get("published", "Unknown"),
            "last_modified": cve_item.get("lastModified", "Unknown"),
            "cwe": cve_item.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A") if cve_item.get("weaknesses") else "N/A"
        }

    except httpx.HTTPStatusError as e:
        return JSONResponse(
            status_code=e.response.status_code,
            content={"error": f"NVD API error: {str(e)}"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to fetch CVE details: {str(e)}"}
        )
