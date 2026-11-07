"""
TRUSTX AI - Module E: Visual Brand Impersonation Detection Service
Analyzes page content, claimed organization identities, login element signatures,
and visual brand references to identify unauthorized brand clones.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional
import requests

# Known high-value targeted brand reference profiles
BRAND_PROFILES = {
    'paypal': {
        'name': 'PayPal',
        'category': 'Financial / Payments',
        'official_domains': ['paypal.com', 'paypal-community.com'],
        'login_keywords': ['log in to paypal', 'pay with paypal', 'paypal balance', 'send money'],
        'logo_hints': ['paypal_logo', 'paypal.svg', 'paypal-white', 'pp-logo']
    },
    'google': {
        'name': 'Google Workspace / Account',
        'category': 'Identity Provider',
        'official_domains': ['google.com', 'accounts.google.com'],
        'login_keywords': ['sign in with google', 'to continue to gmail', 'choose an account'],
        'logo_hints': ['google_logo', 'google-logo.svg', 'google_icon']
    },
    'microsoft': {
        'name': 'Microsoft 365 / Outlook',
        'category': 'Identity / Enterprise',
        'official_domains': ['microsoft.com', 'login.microsoftonline.com', 'live.com'],
        'login_keywords': ['sign in to your microsoft account', 'office 365', 'outlook.com'],
        'logo_hints': ['ms-symbol', 'microsoft_logo', 'azure-logo']
    },
    'apple': {
        'name': 'Apple ID / iCloud',
        'category': 'Consumer Identity',
        'official_domains': ['apple.com', 'icloud.com'],
        'login_keywords': ['sign in with apple id', 'icloud sign in', 'apple account'],
        'logo_hints': ['apple-logo', 'apple_id']
    },
    'chase': {
        'name': 'Chase Bank',
        'category': 'Banking',
        'official_domains': ['chase.com'],
        'login_keywords': ['chase online', 'sign in to your chase account'],
        'logo_hints': ['chase-logo', 'chase.svg']
    },
    'bankofamerica': {
        'name': 'Bank of America',
        'category': 'Banking',
        'official_domains': ['bankofamerica.com', 'bofa.com'],
        'login_keywords': ['bank of america log in', 'online banking id'],
        'logo_hints': ['bofa-logo', 'bank-of-america']
    }
}


def analyze_brand_impersonation(url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
    """
    Safely inspect page content and identify potential visual / brand impersonation:
    1. Fetches lightweight DOM if html_content is not provided.
    2. Identifies claimed organization / brand logos and form fields.
    3. Compares claimed identity against the actual host domain.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    clean_domain = urllib.parse.urlparse(url).netloc.split(':')[0].lower()
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    report = {
        "domain": clean_domain,
        "is_impersonating": False,
        "targeted_brand": None,
        "confidence": 0.0,
        "cloned_login_detected": False,
        "form_fields_found": [],
        "evidence": [],
        "recommendation": None
    }

    # Fetch HTML safely if not passed
    if not html_content:
        try:
            resp = requests.get(
                url,
                timeout=4.0,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TRUSTX-AI-BrandGuard/1.0'}
            )
            html_content = resp.text[:150000]  # First 150KB
        except Exception:
            html_content = ""

    if not html_content:
        report["evidence"].append("HTML page content unreachable for visual DOM inspection.")
        return report

    html_lower = html_content.lower()

    # 1. Detect Login Form Signatures (password fields, submit actions)
    has_password_field = bool(re.search(r'<input[^>]*type=[\'"]password[\'"]', html_lower))
    has_form_submit = bool(re.search(r'<form[^>]*action=', html_lower))

    if has_password_field:
        report["cloned_login_detected"] = True
        report["form_fields_found"].append("Password input credential collector")

    # 2. Match against protected brand profiles
    for brand_key, profile in BRAND_PROFILES.items():
        is_official = any(
            clean_domain == off or clean_domain.endswith('.' + off)
            for off in profile['official_domains']
        )
        if is_official:
            # Domain is genuinely official!
            continue

        # Check for brand keywords in page title or content
        title_match = bool(re.search(rf'<title>[^<]*{brand_key}[^<]*</title>', html_lower))
        keyword_matches = [kw for kw in profile['login_keywords'] if kw in html_lower]
        logo_matches = [lh for lh in profile['logo_hints'] if lh in html_lower]

        evidence_count = (2 if title_match else 0) + len(keyword_matches) + (2 if logo_matches else 0)

        if evidence_count >= 2:
            report["is_impersonating"] = True
            report["targeted_brand"] = profile['name']
            report["confidence"] = min(0.95, 0.45 + (evidence_count * 0.15))

            report["evidence"].append(
                f"Page prominently displays brand identity for '{profile['name']}' ({profile['category']}), "
                f"but is hosted on completely unauthorized domain '{clean_domain}'."
            )

            if has_password_field:
                report["evidence"].append(
                    f"Credential harvesting form detected targeting {profile['name']} account credentials."
                )

            report["recommendation"] = (
                f"DO NOT authenticate here. This page appears to be an unauthorized lookalike clone of {profile['name']}. "
                f"Only access {profile['name']} via their official domain: {profile['official_domains'][0]}"
            )
            break

    return report
