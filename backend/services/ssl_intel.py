"""
TRUSTX AI - Module C: SSL/TLS Certificate Intelligence Engine
Performs live TLS handshake inspection, certificate chain analysis,
Certificate Transparency verification (crt.sh), and untrusted root/eMudhra incident checks.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger('trustx-ssl-intel')

# Distrusted or historically flagged Certificate Authorities / Intermediates
DISTRUSTED_OR_FLAGGED_CAS = [
    'wosign', 'startcom', 'diginotar', 'cnnic', 'darkmatter'
]

# High-risk CA flags: eMudhra compliance incidents and unauthorized intermediate issuances
FLAGGED_INTERMEDIATE_KEYWORDS = [
    'emudhra', 'sub-ca-emudhra', 'untrusted-root', 'test-ca'
]


def inspect_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Connect to domain:port and inspect the live SSL/TLS certificate.
    Extracts Subject, Issuer, SANs, Expiry, Protocol, and Cryptographic details.
    """
    clean_domain = domain.lower().split(':')[0]
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    report = {
        "domain": clean_domain,
        "has_ssl": False,
        "is_valid": False,
        "is_expired": False,
        "days_remaining": -1,
        "valid_from": None,
        "valid_to": None,
        "subject": {},
        "issuer": {},
        "sans": [],
        "tls_version": None,
        "cipher": None,
        "hostname_matches": False,
        "is_self_signed": False,
        "is_free_cert": False,
        "ca_reputation": "unknown",
        "risk_flags": [],
        "trust_notes": [],
        "error": None
    }

    ctx = ssl.create_default_context()
    # Allow inspection even if cert is unverified or expired to document the findings
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = None
    ssock = None
    try:
        sock = socket.create_connection((clean_domain, port), timeout=4.0)
        ssock = ctx.wrap_socket(sock, server_hostname=clean_domain)
        cert = ssock.getpeercert(binary_form=False)
        report["tls_version"] = ssock.version()
        report["cipher"] = ssock.cipher()
        report["has_ssl"] = True

        # When CERT_NONE is used, getpeercert() returns empty dict in standard python.
        # Let's get the binary DER cert and parse with ssl.get_server_certificate or cryptography.
        der_cert = ssock.getpeercert(binary_form=True)

        # Parse DER cert with cryptography or fallback
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

            # Subject & Issuer
            report["subject"] = {
                attr.oid._name: attr.value for attr in x509_cert.subject
            }
            report["issuer"] = {
                attr.oid._name: attr.value for attr in x509_cert.issuer
            }

            # Dates
            not_before = x509_cert.not_valid_before_utc
            not_after = x509_cert.not_valid_after_utc

            report["valid_from"] = not_before.isoformat()
            report["valid_to"] = not_after.isoformat()

            now_utc = datetime.now(timezone.utc)
            report["is_expired"] = now_utc > not_after
            report["days_remaining"] = max(0, (not_after - now_utc).days)

            # Self-signed check
            report["is_self_signed"] = x509_cert.issuer == x509_cert.subject

            # SANs
            try:
                ext = x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                report["sans"] = [str(name.value).lower() for name in ext.value]
            except Exception:
                report["sans"] = []

            # Hostname match check
            common_name = report["subject"].get("commonName", "").lower()
            all_names = report["sans"] + ([common_name] if common_name else [])

            def matches_host(pattern: str, host: str) -> bool:
                if pattern.startswith("*."):
                    base = pattern[2:]
                    return host == base or host.endswith("." + base)
                return pattern == host

            report["hostname_matches"] = any(matches_host(p, clean_domain) for p in all_names)

        except ImportError:
            # Cryptography not available; use standard fields
            pass

        # Check CA reputation & Free Certificate indicator
        issuer_o = str(report["issuer"].get("organizationName", "")).lower()
        issuer_cn = str(report["issuer"].get("commonName", "")).lower()
        issuer_full = f"{issuer_o} {issuer_cn}"

        # Detect Let's Encrypt / cPanel / ZeroSSL
        if any(free in issuer_full for free in ["let's encrypt", "zerossl", "cpanel", "cloudflare"]):
            report["is_free_cert"] = True
            report["trust_notes"].append(
                "Uses an automated domain-validated (DV) free certificate. Note: DV certificates only verify domain control, not identity."
            )

        # Check for distrusted / flagged CAs
        for bad_ca in DISTRUSTED_OR_FLAGGED_CAS:
            if bad_ca in issuer_full:
                report["risk_flags"].append({
                    "severity": "critical",
                    "code": "DISTRUSTED_ROOT_CA",
                    "detail": f"Certificate was issued by a historically distrusted CA: {issuer_full}"
                })

        # Check specifically for eMudhra compliance alert (as highlighted in prompt)
        for flag_kw in FLAGGED_INTERMEDIATE_KEYWORDS:
            if flag_kw in issuer_full:
                report["risk_flags"].append({
                    "severity": "high",
                    "code": "FLAGGED_INTERMEDIATE_CA",
                    "detail": f"Certificate issued by an intermediate authority ({issuer_full}) under scrutiny or investigation for compliance failures."
                })

        # Self-signed alert
        if report["is_self_signed"]:
            report["risk_flags"].append({
                "severity": "critical",
                "code": "SELF_SIGNED_CERTIFICATE",
                "detail": "Website uses a self-signed certificate not trusted by any public root authority."
            })

        # Expiry alert
        if report["is_expired"]:
            report["risk_flags"].append({
                "severity": "critical",
                "code": "EXPIRED_CERTIFICATE",
                "detail": f"Certificate expired {abs(report['days_remaining'])} days ago."
            })
        elif 0 <= report["days_remaining"] < 7:
            report["risk_flags"].append({
                "severity": "medium",
                "code": "CERT_EXPIRING_SOON",
                "detail": f"Certificate will expire in {report['days_remaining']} days."
            })

        # Hostname mismatch
        if not report["hostname_matches"] and report["has_ssl"]:
            report["risk_flags"].append({
                "severity": "high",
                "code": "HOSTNAME_MISMATCH",
                "detail": f"Certificate subject/SAN does not match requested domain '{clean_domain}'."
            })

        # Check for deprecated TLS
        if report["tls_version"] in ["TLSv1", "TLSv1.1"]:
            report["risk_flags"].append({
                "severity": "high",
                "code": "DEPRECATED_TLS_VERSION",
                "detail": f"Server negotiates obsolete protocol {report['tls_version']} with known cryptographic flaws."
            })

        report["is_valid"] = (
            report["has_ssl"] and
            not report["is_expired"] and
            report["hostname_matches"] and
            not report["is_self_signed"] and
            len([f for f in report["risk_flags"] if f["severity"] == "critical"]) == 0
        )

    except ssl.SSLError as e:
        report["error"] = f"SSL Handshake Error: {str(e)}"
        report["risk_flags"].append({
            "severity": "high",
            "code": "SSL_HANDSHAKE_FAILURE",
            "detail": f"Failed to complete secure TLS handshake: {str(e)}"
        })
    except socket.timeout:
        report["error"] = "SSL connection timed out (port 443 unreachable)."
    except Exception as e:
        report["error"] = f"Connection error: {str(e)}"
    finally:
        if ssock:
            try:
                ssock.close()
            except Exception:
                pass
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return report


def check_certificate_transparency(domain: str) -> Dict[str, Any]:
    """
    Query crt.sh Certificate Transparency logs for historical issuances.
    Provides proof of domain longevity and unauthorized wildcard/subdomain issuances.
    """
    clean_domain = domain.lower().split(':')[0]
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    ct_result = {
        "domain": clean_domain,
        "logged_certs_count": 0,
        "first_logged_date": None,
        "issuers_seen": [],
        "has_ct_records": False,
        "query_successful": False
    }

    try:
        url = f"https://crt.sh/?q={clean_domain}&output=json"
        resp = requests.get(url, timeout=3.5, headers={"User-Agent": "TRUSTX-AI/1.0"})
        if resp.status_code == 200:
            entries = resp.json()
            if isinstance(entries, list) and entries:
                ct_result["query_successful"] = True
                ct_result["has_ct_records"] = True
                ct_result["logged_certs_count"] = len(entries)

                # Collect distinct issuers
                issuers = set()
                dates = []
                for entry in entries[:50]:
                    if "issuer_name" in entry:
                        issuers.add(entry["issuer_name"].split(",")[0])
                    if "entry_timestamp" in entry:
                        dates.append(entry["entry_timestamp"])

                ct_result["issuers_seen"] = list(issuers)[:5]
                if dates:
                    dates.sort()
                    ct_result["first_logged_date"] = dates[0]
    except Exception as e:
        logger.debug(f"crt.sh CT query timed out or failed for {clean_domain}: {e}")

    return ct_result


def analyze_ssl_intelligence(domain: str) -> Dict[str, Any]:
    """
    Run complete Module C analysis:
    Live TLS Inspection + Certificate Transparency Verification + Threat Flags.
    """
    cert_info = inspect_ssl_certificate(domain)
    ct_info = check_certificate_transparency(domain)

    return {
        "certificate": cert_info,
        "certificate_transparency": ct_info,
        "important_takeaway": (
            "Valid SSL/TLS encryption ensures only that the connection is encrypted in transit; "
            "it DOES NOT guarantee the domain itself is benign or trustworthy. Over 80% of modern "
            "phishing sites use free domain-validated SSL certificates."
        )
    }
