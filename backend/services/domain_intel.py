"""
TRUSTX AI - Module B: Domain and DNS Intelligence Service
Performs authoritative DNS lookups (A, AAAA, MX, NS, TXT) and
RDAP (Registration Data Access Protocol) queries to assess domain provenance.
"""

import socket
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

logger = logging.getLogger('trustx-domain-intel')

# Fast-flux / dynamic DNS / bulletproof hosting patterns often linked to disposable campaigns
SUSPICIOUS_NS_PATTERNS = [
    'duckdns.org', 'no-ip.com', 'ddns.net', 'zapto.org',
    'hopto.org', 'bounceme.net', 'freedns.afraid.org'
]


def resolve_dns_records(domain: str) -> Dict[str, Any]:
    """
    Resolve DNS records: A, AAAA, MX, NS, TXT.
    Uses dnspython if installed, with standard socket fallback.
    """
    results = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "ttl": None,
        "dns_resolved": False,
        "error": None
    }

    if not HAS_DNS:
        # Fallback to standard socket
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            results["a_records"] = ips
            results["dns_resolved"] = True
        except Exception as e:
            results["error"] = str(e)
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. A Records
    try:
        answers = resolver.resolve(domain, 'A')
        results["a_records"] = [str(rdata) for rdata in answers]
        results["ttl"] = answers.rrset.ttl if answers.rrset else None
        results["dns_resolved"] = True
    except Exception:
        pass

    # 2. AAAA Records
    try:
        answers = resolver.resolve(domain, 'AAAA')
        results["aaaa_records"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    # 3. MX Records
    try:
        answers = resolver.resolve(domain, 'MX')
        results["mx_records"] = [
            {"preference": rdata.preference, "exchange": str(rdata.exchange).rstrip('.')}
            for rdata in answers
        ]
    except Exception:
        pass

    # 4. NS Records
    try:
        answers = resolver.resolve(domain, 'NS')
        results["ns_records"] = [str(rdata).rstrip('.').lower() for rdata in answers]
    except Exception:
        pass

    # 5. TXT Records
    try:
        answers = resolver.resolve(domain, 'TXT')
        results["txt_records"] = [
            b"".join(rdata.strings).decode('utf-8', errors='ignore')
            for rdata in answers
        ]
    except Exception:
        pass

    # Fallback to socket if dnspython returned empty A records
    if not results["a_records"]:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            results["a_records"] = ips
            results["dns_resolved"] = True
        except Exception:
            pass

    return results


def fetch_rdap_info(domain: str) -> Dict[str, Any]:
    """
    Query RDAP (Registration Data Access Protocol) for domain provenance.
    Extracts creation, expiration, last updated dates, and registrar.
    """
    clean_domain = domain.lower().strip()
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    rdap_result = {
        "queried_domain": clean_domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "domain_age_days": -1,
        "days_until_expiry": -1,
        "status": [],
        "success": False,
        "source": "rdap.org"
    }

    try:
        # RDAP bootstrap endpoint with a strict 3.5s timeout
        url = f"https://rdap.org/domain/{clean_domain}"
        headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "TRUSTX-AI/1.0"}
        resp = requests.get(url, headers=headers, timeout=3.5, allow_redirects=True)

        if resp.status_code == 200:
            data = resp.json()
            rdap_result["success"] = True

            # Extract events (registration, expiration, last changed)
            events = data.get("events", [])
            for ev in events:
                action = ev.get("eventAction")
                date_str = ev.get("eventDate")
                if not date_str:
                    continue

                # Parse ISO date
                try:
                    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    if action == "registration":
                        rdap_result["creation_date"] = dt.isoformat()
                        rdap_result["domain_age_days"] = max(0, (datetime.utcnow() - dt).days)
                    elif action == "expiration":
                        rdap_result["expiration_date"] = dt.isoformat()
                        rdap_result["days_until_expiry"] = max(0, (dt - datetime.utcnow()).days)
                    elif action in ("last changed", "last update"):
                        rdap_result["updated_date"] = dt.isoformat()
                except Exception:
                    pass

            # Extract registrar entity
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                rdap_result["registrar"] = item[3]
                                break

            # Domain status codes
            rdap_result["status"] = data.get("status", [])

    except Exception as e:
        logger.debug(f"RDAP lookup failed for {clean_domain}: {e}")
        rdap_result["error"] = str(e)

    return rdap_result


def analyze_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Perform complete Module B investigation:
    DNS records + RDAP registration + Suspicious Infrastructure Checks.
    """
    clean_domain = domain.lower().split(':')[0]
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    dns_data = resolve_dns_records(clean_domain)
    rdap_data = fetch_rdap_info(clean_domain)

    # Infrastructure Risk Assessment
    risk_factors = []
    trust_bonuses = []

    # 1. Domain Age Analysis
    age_days = rdap_data.get("domain_age_days", -1)
    if 0 <= age_days < 14:
        risk_factors.append({
            "code": "CRITICAL_NEW_DOMAIN",
            "message": f"Brand new domain registered {age_days} days ago (very high risk for phishing campaigns)",
            "impact": -35
        })
    elif 14 <= age_days < 60:
        risk_factors.append({
            "code": "YOUNG_DOMAIN",
            "message": f"Young domain registered {age_days} days ago (< 60 days)",
            "impact": -15
        })
    elif age_days >= 365 * 2:
        trust_bonuses.append({
            "code": "ESTABLISHED_DOMAIN",
            "message": f"Well-established domain ({round(age_days / 365, 1)} years old)",
            "impact": +15
        })

    # 2. Nameserver Assessment
    for ns in dns_data.get("ns_records", []):
        for suspicious_ns in SUSPICIOUS_NS_PATTERNS:
            if suspicious_ns in ns:
                risk_factors.append({
                    "code": "SUSPICIOUS_NAMESERVER",
                    "message": f"Uses free dynamic DNS provider: {ns}",
                    "impact": -20
                })

    # 3. DNS Health & Mail Record Check
    has_mx = len(dns_data.get("mx_records", [])) > 0
    has_a = len(dns_data.get("a_records", [])) > 0

    if not has_a:
        risk_factors.append({
            "code": "NO_A_RECORD",
            "message": "Domain does not resolve to an active IPv4 address",
            "impact": -10
        })

    return {
        "domain": clean_domain,
        "dns": dns_data,
        "rdap": rdap_data,
        "has_mx_record": has_mx,
        "risk_factors": risk_factors,
        "trust_bonuses": trust_bonuses,
        "is_young_domain": 0 <= age_days < 60,
        "domain_age_days": age_days,
    }
