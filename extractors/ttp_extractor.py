import re
from mitreattack.stix20 import MitreAttackData
from rich.console import Console

def extract_ttps(text, console, mitre_attack_data=None):
    ttps = []

    # Basic patterns for TTPs
    ttp_pattern = r'\bT[A-Z0-9]{4,}(?:\.[A-Z0-9]{0,3})?\b'

    matches = re.findall(ttp_pattern, text)
    if len(matches) == 0:
        return ttps
    
    seen = set()

    for match in matches:
        normalized = match.strip().upper()
        if normalized not in seen:
            info = get_ttp_info(normalized, mitre_attack_data)
            ttps.append({'type': 'TTP', 'value': normalized, 'name': info['name'], 'phase': info['phase'], 'ref': info['ref']})
            seen.add(normalized)

    phase_order = [
        "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
        "privilege-escalation", "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"
    ]
    
    return sorted(
                ttps,
                key=lambda x: (phase_order.index(x['phase']), x['name'])
            )

def get_ttp_info(ttp, mitre_attack_data) -> dict:
    info = mitre_attack_data.get_object_by_attack_id(ttp, "attack-pattern")

    return {
        'name': info['name'],
        'phase': info['kill_chain_phases'][0]['phase_name'],
        'ref': info['external_references'][0]['url']
    }