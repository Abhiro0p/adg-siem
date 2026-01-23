from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

# Lockheed Martin Cyber Kill Chain stages in order
KILL_CHAIN_ORDER: List[str] = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

# MITRE ATT&CK tactic → kill chain phase mapping
_TACTIC_TO_PHASE: Dict[str, str] = {
    "reconnaissance": "reconnaissance",
    "resource-development": "weaponization",
    "initial-access": "delivery",
    "execution": "exploitation",
    "persistence": "installation",
    "privilege-escalation": "exploitation",
    "defense-evasion": "exploitation",
    "credential-access": "exploitation",
    "discovery": "reconnaissance",
    "lateral-movement": "command_and_control",
    "collection": "actions_on_objectives",
    "command-and-control": "command_and_control",
    "exfiltration": "actions_on_objectives",
    "impact": "actions_on_objectives",
}

# Comprehensive MITRE ATT&CK technique → (tactic, kill_chain_stage, description)
TECHNIQUE_MAP: Dict[str, Tuple[str, str, str]] = {
    # Reconnaissance
    "T1595": ("reconnaissance", "reconnaissance", "Active Scanning"),
    "T1595.001": ("reconnaissance", "reconnaissance", "Scanning IP Blocks"),
    "T1595.002": ("reconnaissance", "reconnaissance", "Vulnerability Scanning"),
    "T1595.003": ("reconnaissance", "reconnaissance", "Wordlist Scanning"),
    "T1592": ("reconnaissance", "reconnaissance", "Gather Victim Host Information"),
    "T1592.001": ("reconnaissance", "reconnaissance", "Hardware"),
    "T1592.002": ("reconnaissance", "reconnaissance", "Software"),
    "T1592.004": ("reconnaissance", "reconnaissance", "Client Configurations"),
    "T1590": ("reconnaissance", "reconnaissance", "Gather Victim Network Information"),
    "T1590.001": ("reconnaissance", "reconnaissance", "Domain Properties"),
    "T1590.002": ("reconnaissance", "reconnaissance", "DNS"),
    "T1590.003": ("reconnaissance", "reconnaissance", "Network Trust Dependencies"),
    "T1590.004": ("reconnaissance", "reconnaissance", "Network Topology"),
    "T1590.005": ("reconnaissance", "reconnaissance", "IP Addresses"),
    "T1046": ("reconnaissance", "reconnaissance", "Network Service Discovery"),
    "T1040": ("credential-access", "reconnaissance", "Network Sniffing"),
    "T1049": ("discovery", "reconnaissance", "System Network Connections Discovery"),
    "T1018": ("discovery", "reconnaissance", "Remote System Discovery"),
    "T1033": ("discovery", "reconnaissance", "System Owner/User Discovery"),
    "T1082": ("discovery", "reconnaissance", "System Information Discovery"),
    "T1083": ("discovery", "reconnaissance", "File and Directory Discovery"),
    "T1087": ("discovery", "reconnaissance", "Account Discovery"),
    "T1087.001": ("discovery", "reconnaissance", "Local Account Discovery"),
    "T1087.002": ("discovery", "reconnaissance", "Domain Account Discovery"),
    "T1135": ("discovery", "reconnaissance", "Network Share Discovery"),
    "T1201": ("discovery", "reconnaissance", "Password Policy Discovery"),
    "T1069": ("discovery", "reconnaissance", "Permission Groups Discovery"),
    "T1069.001": ("discovery", "reconnaissance", "Local Groups"),
    "T1069.002": ("discovery", "reconnaissance", "Domain Groups"),
    "T1016": ("discovery", "reconnaissance", "System Network Configuration Discovery"),
    "T1057": ("discovery", "reconnaissance", "Process Discovery"),
    "T1007": ("discovery", "reconnaissance", "System Service Discovery"),
    "T1124": ("discovery", "reconnaissance", "System Time Discovery"),
    "T1580": ("discovery", "reconnaissance", "Cloud Infrastructure Discovery"),
    "T1619": ("discovery", "reconnaissance", "Cloud Storage Object Discovery"),
    "T1613": ("discovery", "reconnaissance", "Container and Resource Discovery"),
    # Delivery / Initial Access
    "T1105": ("command-and-control", "delivery", "Ingress Tool Transfer"),
    "T1566": ("initial-access", "delivery", "Phishing"),
    "T1566.001": ("initial-access", "delivery", "Spearphishing Attachment"),
    "T1566.002": ("initial-access", "delivery", "Spearphishing Link"),
    "T1566.003": ("initial-access", "delivery", "Spearphishing via Service"),
    "T1190": ("initial-access", "delivery", "Exploit Public-Facing Application"),
    "T1133": ("initial-access", "delivery", "External Remote Services"),
    "T1078": ("initial-access", "delivery", "Valid Accounts"),
    "T1078.001": ("initial-access", "delivery", "Default Accounts"),
    "T1078.002": ("initial-access", "delivery", "Domain Accounts"),
    "T1078.003": ("initial-access", "delivery", "Local Accounts"),
    "T1078.004": ("initial-access", "delivery", "Cloud Accounts"),
    "T1199": ("initial-access", "delivery", "Trusted Relationship"),
    "T1091": ("initial-access", "delivery", "Replication Through Removable Media"),
    "T1200": ("initial-access", "delivery", "Hardware Additions"),
    # Exploitation / Execution
    "T1059": ("execution", "exploitation", "Command and Scripting Interpreter"),
    "T1059.001": ("execution", "exploitation", "PowerShell"),
    "T1059.002": ("execution", "exploitation", "AppleScript"),
    "T1059.003": ("execution", "exploitation", "Windows Command Shell"),
    "T1059.004": ("execution", "exploitation", "Unix Shell"),
    "T1059.006": ("execution", "exploitation", "Python"),
    "T1059.007": ("execution", "exploitation", "JavaScript"),
    "T1059.008": ("execution", "exploitation", "Network Device CLI"),
    "T1203": ("execution", "exploitation", "Exploitation for Client Execution"),
    "T1204": ("execution", "exploitation", "User Execution"),
    "T1204.001": ("execution", "exploitation", "Malicious Link"),
    "T1204.002": ("execution", "exploitation", "Malicious File"),
    "T1047": ("execution", "exploitation", "Windows Management Instrumentation"),
    "T1053": ("execution", "exploitation", "Scheduled Task/Job"),
    "T1053.005": ("execution", "exploitation", "Scheduled Task"),
    "T1569": ("execution", "exploitation", "System Services"),
    "T1569.002": ("execution", "exploitation", "Service Execution"),
    "T1072": ("execution", "exploitation", "Software Deployment Tools"),
    # Credential Access
    "T1110": ("credential-access", "exploitation", "Brute Force"),
    "T1110.001": ("credential-access", "exploitation", "Password Guessing"),
    "T1110.002": ("credential-access", "exploitation", "Password Cracking"),
    "T1110.003": ("credential-access", "exploitation", "Password Spraying"),
    "T1110.004": ("credential-access", "exploitation", "Credential Stuffing"),
    "T1555": ("credential-access", "exploitation", "Credentials from Password Stores"),
    "T1555.003": ("credential-access", "exploitation", "Credentials from Web Browsers"),
    "T1558": ("credential-access", "exploitation", "Steal or Forge Kerberos Tickets"),
    "T1558.003": ("credential-access", "exploitation", "Kerberoasting"),
    "T1212": ("credential-access", "exploitation", "Exploitation for Credential Access"),
    "T1187": ("credential-access", "exploitation", "Forced Authentication"),
    "T1606": ("credential-access", "exploitation", "Forge Web Credentials"),
    "T1528": ("credential-access", "exploitation", "Steal Application Access Token"),
    "T1539": ("credential-access", "exploitation", "Steal Web Session Cookie"),
    "T1552": ("credential-access", "exploitation", "Unsecured Credentials"),
    "T1552.001": ("credential-access", "exploitation", "Credentials in Files"),
    "T1552.004": ("credential-access", "exploitation", "Private Keys"),
    # Persistence / Installation
    "T1547": ("persistence", "installation", "Boot or Logon Autostart Execution"),
    "T1547.001": ("persistence", "installation", "Registry Run Keys / Startup Folder"),
    "T1053.003": ("persistence", "installation", "Cron"),
    "T1136": ("persistence", "installation", "Create Account"),
    "T1136.001": ("persistence", "installation", "Local Account"),
    "T1136.002": ("persistence", "installation", "Domain Account"),
    "T1543": ("persistence", "installation", "Create or Modify System Process"),
    "T1543.003": ("persistence", "installation", "Windows Service"),
    "T1546": ("persistence", "installation", "Event Triggered Execution"),
    "T1505": ("persistence", "installation", "Server Software Component"),
    "T1505.003": ("persistence", "installation", "Web Shell"),
    "T1078.003b": ("persistence", "installation", "Valid Accounts - Local"),
    # Command & Control
    "T1071": ("command-and-control", "command_and_control", "Application Layer Protocol"),
    "T1071.001": ("command-and-control", "command_and_control", "Web Protocols"),
    "T1071.002": ("command-and-control", "command_and_control", "File Transfer Protocols"),
    "T1071.003": ("command-and-control", "command_and_control", "Mail Protocols"),
    "T1071.004": ("command-and-control", "command_and_control", "DNS"),
    "T1021": ("lateral-movement", "command_and_control", "Remote Services"),
    "T1021.001": ("lateral-movement", "command_and_control", "Remote Desktop Protocol"),
    "T1021.002": ("lateral-movement", "command_and_control", "SMB/Windows Admin Shares"),
    "T1021.004": ("lateral-movement", "command_and_control", "SSH"),
    "T1041": ("exfiltration", "command_and_control", "Exfiltration Over C2 Channel"),
    "T1572": ("command-and-control", "command_and_control", "Protocol Tunneling"),
    "T1090": ("command-and-control", "command_and_control", "Proxy"),
    "T1090.001": ("command-and-control", "command_and_control", "Internal Proxy"),
    "T1090.002": ("command-and-control", "command_and_control", "External Proxy"),
    "T1090.003": ("command-and-control", "command_and_control", "Multi-hop Proxy"),
    "T1132": ("command-and-control", "command_and_control", "Data Encoding"),
    "T1573": ("command-and-control", "command_and_control", "Encrypted Channel"),
    "T1008": ("command-and-control", "command_and_control", "Fallback Channels"),
    # Exfiltration / Actions on Objectives
    "T1005": ("collection", "actions_on_objectives", "Data from Local System"),
    "T1114": ("collection", "actions_on_objectives", "Email Collection"),
    "T1083b": ("collection", "actions_on_objectives", "File and Directory Discovery (targeted)"),
    "T1074": ("collection", "actions_on_objectives", "Data Staged"),
    "T1560": ("collection", "actions_on_objectives", "Archive Collected Data"),
    "T1048": ("exfiltration", "actions_on_objectives", "Exfiltration Over Alternative Protocol"),
    "T1567": ("exfiltration", "actions_on_objectives", "Exfiltration Over Web Service"),
    "T1567.002": ("exfiltration", "actions_on_objectives", "Exfiltration to Cloud Storage"),
    "T1537": ("exfiltration", "actions_on_objectives", "Transfer Data to Cloud Account"),
    "T1486": ("impact", "actions_on_objectives", "Data Encrypted for Impact"),
    "T1489": ("impact", "actions_on_objectives", "Service Stop"),
    "T1490": ("impact", "actions_on_objectives", "Inhibit System Recovery"),
    "T1491": ("impact", "actions_on_objectives", "Defacement"),
    "T1498": ("impact", "actions_on_objectives", "Network Denial of Service"),
    "T1499": ("impact", "actions_on_objectives", "Endpoint Denial of Service"),
}

# Convenience lookup: technique → stage only
_TECHNIQUE_TO_STAGE: Dict[str, str] = {t: v[1] for t, v in TECHNIQUE_MAP.items()}
# Technique → tactic
_TECHNIQUE_TO_TACTIC: Dict[str, str] = {t: v[0] for t, v in TECHNIQUE_MAP.items()}
# Technique → description
_TECHNIQUE_TO_DESC: Dict[str, str] = {t: v[2] for t, v in TECHNIQUE_MAP.items()}


def kill_chain_for(techniques: Iterable[str]) -> List[str]:
    """Return ordered kill-chain stages for the given MITRE technique IDs."""
    seen: set[str] = set()
    for technique in techniques:
        stage = _TECHNIQUE_TO_STAGE.get(technique)
        if stage:
            seen.add(stage)
    return [stage for stage in KILL_CHAIN_ORDER if stage in seen]


def tactic_for(technique: str) -> Optional[str]:
    return _TECHNIQUE_TO_TACTIC.get(technique)


def describe_technique(technique: str) -> Optional[str]:
    return _TECHNIQUE_TO_DESC.get(technique)


def enrich_techniques(techniques: Iterable[str]) -> List[Dict[str, str]]:
    """Return full enrichment dicts for a list of technique IDs."""
    result = []
    for t in techniques:
        entry = TECHNIQUE_MAP.get(t)
        if entry:
            result.append({
                "technique": t,
                "tactic": entry[0],
                "kill_chain": entry[1],
                "description": entry[2],
                "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}",
            })
        else:
            result.append({"technique": t, "tactic": "unknown", "kill_chain": "unknown", "description": ""})
    return result
