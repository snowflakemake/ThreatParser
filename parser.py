# parser.py
from extractors.ioc_extractor import extract_iocs
from extractors.ttp_extractor import extract_ttps

class ThreatReportParser:
    def __init__(self, report_path):
        with open(report_path, 'r', encoding='utf-8') as f:
            self.text = f.read()

    def extract_iocs(self, console, lookup=True):
        return extract_iocs(self.text, console, lookup=lookup)
    
    def extract_ttps(self, console):
        return extract_ttps(self.text, console)