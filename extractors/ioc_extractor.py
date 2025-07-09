# extractors/ioc_extractor.py
import re
import tldextract

def extract_iocs(text):
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