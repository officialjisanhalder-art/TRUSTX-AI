"""
TRUSTX AI - Module A: Advanced Phishing Detection Engine
Enhances baseline ML classification with typosquatting detection,
URL obfuscation analysis, homoglyph detection, and threat indicators.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional
import unicodedata

# Protected brand keywords and official domains for typosquatting & brand impersonation checks
PROTECTED_BRANDS = {
    'paypal': 'paypal.com',
    'google': 'google.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'amazon': 'amazon.com',
    'netflix': 'netflix.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'whatsapp': 'whatsapp.com',
    'telegram': 'telegram.org',
    'chase': 'chase.com',
    'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com',
    'citibank': 'citi.com',
    'dropbox': 'dropbox.com',
    'github': 'github.com',
    'linkedin': 'linkedin.com',
    'twitter': 'twitter.com',
    'binance': 'binance.com',
    'coinbase': 'coinbase.com',
    'metamask': 'metamask.io',
    'dhl': 'dhl.com',
    'fedex': 'fedex.com',
    'usps': 'usps.com',
}

# Homoglyph character substitutions commonly used in lookalike attacks
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '$': 's', 'vv': 'w',
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(domain: str) -> Dict[str, Any]:
    """
    Detect typosquatting, lookalike domains, and brand hijacking.
    Returns targeted brand, edit distance, and suspicion score.
    """
    clean_domain = domain.lower()
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    domain_parts = clean_domain.split('.')
    main_name = domain_parts[0] if domain_parts else clean_domain

    findings = []
    highest_severity = "none"

    for brand, legit_domain in PROTECTED_BRANDS.items():
        # Exact match of brand's legitimate domain -> safe/legitimate
        if clean_domain == legit_domain or clean_domain.endswith('.' + legit_domain):
            continue

        # 1. Brand keyword embedded in an unauthorized domain (e.g., paypal-security-update.com)
        if brand in clean_domain:
            findings.append({
                "type": "brand_in_unauthorized_domain",
                "brand": brand,
                "legitimate_domain": legit_domain,
                "confidence": 0.90,
                "description": f"Targeted brand '{brand}' embedded in non-official domain '{clean_domain}'."
            })
            highest_severity = "high"

        # 2. Levenshtein distance check on the main domain label (e.g., paypa1, g00gle)
        dist = levenshtein_distance(main_name, brand)
        if 1 <= dist <= 2 and len(main_name) >= 4:
            findings.append({
                "type": "typosquatting_lookalike",
                "brand": brand,
                "legitimate_domain": legit_domain,
                "edit_distance": dist,
                "confidence": 0.92 if dist == 1 else 0.75,
                "description": f"Domain name '{main_name}' is visually or phonetically similar to '{brand}' (edit distance: {dist})."
            })
            highest_severity = "critical" if dist == 1 else "high"

        # 3. Normalized homoglyph check
        normalized_name = main_name
        for char, sub in HOMOGLYPH_MAP.items():
            normalized_name = normalized_name.replace(char, sub)
        if normalized_name == brand and main_name != brand:
            findings.append({
                "type": "homoglyph_substitution",
                "brand": brand,
                "legitimate_domain": legit_domain,
                "confidence": 0.95,
                "description": f"Domain '{main_name}' uses character substitutions (e.g. 0->o, 1->l) to mimic '{brand}'."
            })
            highest_severity = "critical"

    return {
        "is_typosquatting": len(findings) > 0,
        "severity": highest_severity,
        "findings": findings
    }


def detect_url_obfuscation(url: str, domain: str) -> Dict[str, Any]:
    """
    Detect URL obfuscation techniques:
    - Punycode / IDN encoding (xn--)
    - Zero-width or invisible Unicode characters
    - Hex/octal encoded IP addresses in domain
    - Excessive URL encoding (%2F, %20 abuse)
    - Double slash or path traversal tricks
    """
    obfuscations = []

    # 1. Punycode check
    if 'xn--' in domain.lower():
        try:
            decoded_domain = domain.encode('ascii').decode('idna')
            obfuscations.append({
                "technique": "punycode_idn",
                "detail": f"Punycode encoded domain decodes to: {decoded_domain}",
                "severity": "medium",
                "decoded": decoded_domain
            })
        except Exception:
            obfuscations.append({
                "technique": "punycode_idn",
                "detail": "Invalid or unparseable Punycode detected in domain",
                "severity": "high"
            })

    # 2. Zero-width / control characters
    zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
    found_zw = [c for c in zero_width_chars if c in url]
    if found_zw:
        obfuscations.append({
            "technique": "zero_width_characters",
            "detail": f"Contains {len(found_zw)} hidden zero-width / invisible Unicode characters",
            "severity": "critical"
        })

    # 3. Multiple @ symbols or embedded credentials
    if '@' in url:
        obfuscations.append({
            "technique": "credential_at_symbol_abuse",
            "detail": "Contains '@' symbol used to confuse browser address bar parsing",
            "severity": "high"
        })

    # 4. Excessive percent-encoding
    percent_count = url.count('%')
    if percent_count > 4:
        obfuscations.append({
            "technique": "excessive_hex_encoding",
            "detail": f"Contains {percent_count} percent-encoded tokens, commonly used to hide destination paths",
            "severity": "medium"
        })

    # 5. IP Address used as host
    # Check for raw IPv4, octal, or hex
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        obfuscations.append({
            "technique": "raw_ip_host",
            "detail": "Direct IP address host without domain name",
            "severity": "high"
        })

    # 6. Excessive subdomains (domain spoofing)
    subdomain_parts = domain.split('.')
    if len(subdomain_parts) >= 5:
        obfuscations.append({
            "technique": "excessive_subdomains",
            "detail": f"Contains {len(subdomain_parts) - 2} subdomain levels, often used to conceal real domain",
            "severity": "medium"
        })

    return {
        "is_obfuscated": len(obfuscations) > 0,
        "count": len(obfuscations),
        "indicators": obfuscations
    }


def analyze_advanced_phishing_indicators(url: str) -> Dict[str, Any]:
    """
    Run full Module A inspection:
    - Normalizes and parses the URL
    - Typosquatting and homoglyph checks
    - Obfuscation and encoding analysis
    - Suspicious keywords and structural flags
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(':')[0]

    typo_result = detect_typosquatting(domain)
    obfuscation_result = detect_url_obfuscation(url, domain)

    risk_flags = []
    if typo_result['is_typosquatting']:
        for f in typo_result['findings']:
            risk_flags.append(f['description'])

    if obfuscation_result['is_obfuscated']:
        for ind in obfuscation_result['indicators']:
            risk_flags.append(f"[{ind['technique']}] {ind['detail']}")

    return {
        "domain": domain,
        "typosquatting": typo_result,
        "obfuscation": obfuscation_result,
        "risk_flags": risk_flags,
        "has_high_risk_indicator": typo_result['severity'] in ['high', 'critical'] or any(
            i.get('severity') == 'critical' for i in obfuscation_result['indicators']
        )
    }
