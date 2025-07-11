# parser.py
from extractors.ioc_extractor import extract_iocs
from extractors.ttp_extractor import extract_ttps
from extractors.group_extractor import extract_groups
from mitreattack.stix20 import MitreAttackData
from rich.console import Console

class ThreatReportParser:
    def __init__(self, report_path, console: Console):
        with open(report_path, 'r', encoding='utf-8') as f:
            self.text = f.read()
        with console.status("[bold yellow]Loading TTP mappings...", spinner="dots"):
            self.mitre_attack_data = MitreAttackData("data/enterprise-attack.json")

    def extract_iocs(self, console, lookup=True):
        return extract_iocs(self.text, console, lookup=lookup)
    
    def extract_ttps(self, console):
        return extract_ttps(self.text, console, mitre_attack_data=self.mitre_attack_data)
    
    def extract_possible_groups(self, console, ttps):
        return extract_groups(self.text, console, ttps, attack_data=self.mitre_attack_data)