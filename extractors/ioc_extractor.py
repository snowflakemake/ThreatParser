# extractors/ioc_extractor.py
import re
import tldextract

def extract_iocs(text, console, lookup=True):
    iocs = []

    # Basic patterns
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    domain_file_pattern = r'\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]))+[a-zA-Z]{2,}\b'
    url_pattern = r'https?://[^\s]+'
    email_pattern = r'\b\S+@\S+\.\S+\b'

    patterns = {
        'ip': ip_pattern, 
        'hash': hash_pattern,
        'domain': domain_file_pattern,
        'url': url_pattern,
        'email': email_pattern
        }
    
    seen = set()

    for ioc_type, pattern in patterns.items():
        if ioc_type == 'domain':
            # For domains, we need to validate them
            matches = re.findall(pattern, text)
            for match in matches:
                normalized = match.replace('[.]', '.')
                if is_valid_domain(normalized) and normalized not in seen:
                    iocs.append({'type': ioc_type, 'value': normalized})
                else:
                    # If it's not a valid domain, we can still add it as a file name
                    iocs.append({'type': 'file', 'value': normalized})
                seen.add(normalized)
        elif ioc_type == 'hash':
            matches = re.findall(pattern, text)
            for match in matches:
                normalized = match.lower()
                if lookup:
                    hash_lookup = lookup_hash(normalized)
                    if hash_lookup == -1:
                        console.print("[bold red]VirusTotal API key not found. Will run without sending hashes to VirusTotal.[/bold red]")
                        lookup = False
                        hash_lookup = None
                if normalized not in seen:
                    if hash_lookup:
                        iocs.append({'type': 'hash', 'value': normalized, 'lookup': hash_lookup.get('data', {}).get('attributes', {}).get('signature_info', {}).get('product', 'Unknown')})
                    else:
                        iocs.append({'type': 'hash', 'value': normalized})
                    seen.add(normalized)
        else:
            matches = re.findall(pattern, text)
            for match in matches:
                normalized = match.replace('[.]', '.')
                if normalized not in seen:
                    iocs.append({'type': ioc_type, 'value': normalized})
                    seen.add(normalized)

    return sorted(iocs, key=lambda x: x['type'])

def is_valid_domain(text: str):
    try:
        extracted = tldextract.extract(text)
        return bool(extracted.domain and extracted.suffix)
    except Exception:
        return False
    
def lookup_hash(file_hash):
    import os
    from dotenv import load_dotenv
    import requests

    # Load variables from .env
    load_dotenv()

    # Access the key
    API_KEY = os.getenv("VT_API_KEY")

    if not API_KEY:
        return -1
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None