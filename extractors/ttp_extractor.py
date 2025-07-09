import re
from attackcti import attack_client
from collections import defaultdict
from mitreattack.stix20 import MitreAttackData
from rich.console import Console

def extract_ttps(text, console):
    ttps = []

    # Basic patterns for TTPs
    ttp_pattern = r'\bT[A-Z0-9]{4,}(?:\.[A-Z0-9]{0,3})?\b'

    matches = re.findall(ttp_pattern, text)
    if len(matches) == 0:
        return ttps
    
    with console.status("[bold yellow]Loading TTP mappings...", spinner="dots"):
        mitre_attack_data = MitreAttackData("data/enterprise-attack.json")
    
    seen = set()

    for match in matches:
        normalized = match.strip().upper()
        if normalized not in seen:
            info = get_ttp_info(normalized, mitre_attack_data)
            ttps.append({'type': 'TTP', 'value': normalized, 'name': info['name'], 'phase': info['phase'], 'ref': info['ref']})
            seen.add(normalized)

    return sorted(ttps, key=lambda x: (x['phase'], x['name']))

def get_ttp_info(ttp, mitre_attack_data) -> dict:
    info = mitre_attack_data.get_object_by_attack_id(ttp, "attack-pattern")

    return {
        'name': info['name'],
        'phase': info['kill_chain_phases'][0]['phase_name'],
        'ref': info['external_references'][0]['url']
    }