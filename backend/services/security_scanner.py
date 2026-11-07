"""
TRUSTX AI - Module D: Website Security Assessment Scanner
Conducts safe, non-invasive HTTP/HTTPS security header inspections,
cookie security flag evaluations, and redirect chain analyses.
"""

import requests
import urllib.parse
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger('trustx-security-scanner')

# Standard modern security headers and their recommended states
RECOMMENDED_HEADERS = {
    'Strict-Transport-Security': {
        'name': 'HSTS (HTTP Strict Transport Security)',
        'description': 'Enforces secure HTTPS connections and prevents SSL stripping attacks.',
        'severity_if_missing': 'medium',
        'penalty': 8
    },
    'Content-Security-Policy': {
        'name': 'CSP (Content Security Policy)',
        'description': 'Prevents Cross-Site Scripting (XSS), data injection, and malicious script execution.',
        'severity_if_missing': 'medium',
        'penalty': 8
    },
    'X-Frame-Options': {
        'name': 'X-Frame-Options',
        'description': 'Prevents clickjacking attacks by controlling whether the site can be framed.',
        'severity_if_missing': 'low',
        'penalty': 5
    },
    'X-Content-Type-Options': {
        'name': 'X-Content-Type-Options',
        'description': 'Blocks MIME-type sniffing which can lead to executable drive-by downloads.',
        'severity_if_missing': 'low',
        'penalty': 4
    },
    'Referrer-Policy': {
        'name': 'Referrer-Policy',
        'description': 'Protects user privacy by controlling how much referrer data is shared.',
        'severity_if_missing': 'low',
        'penalty': 3
    },
    'Permissions-Policy': {
        'name': 'Permissions-Policy',
        'description': 'Restricts browser features like camera, microphone, and geolocation APIs.',
        'severity_if_missing': 'info',
        'penalty': 2
    }
}


def analyze_website_security(url: str, max_redirects: int = 5) -> Dict[str, Any]:
    """
    Perform a safe, non-invasive HTTP security assessment:
    1. Follow and trace redirect chains.
    2. Audit security response headers.
    3. Inspect cookie security flags (Secure, HttpOnly, SameSite).
    4. Detect server technology disclosures.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    report = {
        "target_url": url,
        "final_url": url,
        "status_code": None,
        "enforces_https": False,
        "redirect_chain": [],
        "headers_audit": {
            "present": [],
            "missing": [],
            "score": 100
        },
        "cookies_audit": {
            "total_cookies": 0,
            "secure_cookies": 0,
            "httponly_cookies": 0,
            "samesite_cookies": 0,
            "issues": []
        },
        "server_technology": None,
        "weaknesses": [],
        "is_accessible": False,
        "error": None
    }

    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TRUSTX-AI-SecurityAudit/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

        # Perform initial request tracking redirect history
        resp = session.get(url, headers=headers, timeout=5.0, allow_redirects=True, stream=True)
        report["is_accessible"] = True
        report["status_code"] = resp.status_code
        report["final_url"] = resp.url

        # Check HTTPS enforcement
        if resp.url.startswith('https://'):
            report["enforces_https"] = True

        # 1. Trace Redirect Chain
        for r in resp.history:
            report["redirect_chain"].append({
                "from_url": r.url,
                "status_code": r.status_code,
                "to_url": r.headers.get('Location', '')
            })

        # Check for cross-domain redirects (e.g. siteA redirects to siteB)
        start_host = urllib.parse.urlparse(url).netloc.lower()
        final_host = urllib.parse.urlparse(resp.url).netloc.lower()
        if start_host and final_host and start_host != final_host:
            report["weaknesses"].append({
                "severity": "medium",
                "code": "CROSS_DOMAIN_REDIRECT",
                "detail": f"Initial domain '{start_host}' silently redirected to completely different domain '{final_host}'."
            })

        # 2. Audit Security Headers
        resp_headers = resp.headers
        header_score = 100

        for h_key, h_info in RECOMMENDED_HEADERS.items():
            val = resp_headers.get(h_key)
            if val:
                report["headers_audit"]["present"].append({
                    "header": h_key,
                    "value": val[:120],  # truncated for clean display
                    "name": h_info["name"]
                })
            else:
                report["headers_audit"]["missing"].append({
                    "header": h_key,
                    "name": h_info["name"],
                    "description": h_info["description"],
                    "severity": h_info["severity_if_missing"]
                })
                header_score -= h_info["penalty"]

        report["headers_audit"]["score"] = max(0, header_score)

        # 3. Cookie Security Audit
        cookies = session.cookies
        report["cookies_audit"]["total_cookies"] = len(cookies)
        for c in cookies:
            is_secure = c.secure
            # In requests, httponly is stored in _rest or attributes
            is_httponly = getattr(c, 'has_nonstandard_attr', lambda x: False)('HttpOnly') or 'httponly' in [k.lower() for k in getattr(c, '_rest', {}).keys()]
            samesite = getattr(c, '_rest', {}).get('SameSite', None) or getattr(c, '_rest', {}).get('samesite', None)

            if is_secure:
                report["cookies_audit"]["secure_cookies"] += 1
            else:
                report["cookies_audit"]["issues"].append(f"Cookie '{c.name}' missing 'Secure' flag.")

            if is_httponly:
                report["cookies_audit"]["httponly_cookies"] += 1
            else:
                report["cookies_audit"]["issues"].append(f"Cookie '{c.name}' missing 'HttpOnly' flag (exposed to client scripts).")

            if samesite:
                report["cookies_audit"]["samesite_cookies"] += 1

        # 4. Information Disclosure / Server Headers
        server_token = resp_headers.get('Server')
        x_powered = resp_headers.get('X-Powered-By')
        if server_token or x_powered:
            disclosed = []
            if server_token:
                disclosed.append(f"Server: {server_token}")
            if x_powered:
                disclosed.append(f"X-Powered-By: {x_powered}")
            report["server_technology"] = " | ".join(disclosed)
            report["weaknesses"].append({
                "severity": "low",
                "code": "SERVER_INFO_DISCLOSURE",
                "detail": f"Discloses exact software version in HTTP headers: {report['server_technology']}"
            })

    except requests.exceptions.SSLError as e:
        report["error"] = f"SSL Error during HTTP request: {str(e)}"
    except requests.exceptions.ConnectionError:
        report["error"] = "Website host refused connection or is offline."
    except requests.exceptions.Timeout:
        report["error"] = "HTTP connection timed out."
    except Exception as e:
        report["error"] = str(e)

    return report
