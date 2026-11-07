"""
TRUSTX AI - Module G: AI Security Investigation Agent
Master investigation orchestrator coordinating all security modules concurrently,
correlating evidence, calculating the unified Trust Score, and generating
grounded, explainable threat intelligence reports.
"""

import sys
import os
import urllib.parse
import hashlib
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional

# Add paths
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(os.path.dirname(BACKEND_DIR), 'model')
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if MODEL_DIR not in sys.path:
    sys.path.insert(0, MODEL_DIR)

try:
    from backend.services.phishing_detector import analyze_advanced_phishing_indicators
    from backend.services.domain_intel import analyze_domain_intelligence
    from backend.services.ssl_intel import analyze_ssl_intelligence
    from backend.services.security_scanner import analyze_website_security
    from backend.services.threat_intel import analyze_threat_intelligence
    from backend.services.trust_engine import TrustScoreEngine
except ImportError:
    from services.phishing_detector import analyze_advanced_phishing_indicators
    from services.domain_intel import analyze_domain_intelligence
    from services.ssl_intel import analyze_ssl_intelligence
    from services.security_scanner import analyze_website_security
    from services.threat_intel import analyze_threat_intelligence
    from services.trust_engine import TrustScoreEngine
from shap_explainer import ShapExplainer

# Shared singleton instance of ShapExplainer
_explainer = None


def get_explainer():
    global _explainer
    if _explainer is None:
        try:
            _explainer = ShapExplainer()
        except Exception as e:
            print(f"Warning: could not load ShapExplainer: {e}")
    return _explainer


def investigate_url(url: str, client_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Run the complete 10-step investigation workflow:
    Coordinates Modules A, B, C, D, F and TrustScoreEngine concurrently.
    """
    start_time = time.time()

    # 1. Normalise URL & Domain
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.split(':')[0]
    if domain.startswith('www.'):
        clean_domain = domain[4:]
    else:
        clean_domain = domain

    # Check for basic whitelist / blacklist
    import sqlite3
    db_path = os.path.join(BACKEND_DIR, 'trustx.db')
    is_whitelisted = False
    is_blacklisted = False

    if os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            if c.execute('SELECT 1 FROM whitelist WHERE ? LIKE "%" || domain', (clean_domain,)).fetchone():
                is_whitelisted = True
            if c.execute('SELECT 1 FROM blacklist WHERE ? LIKE "%" || domain', (clean_domain,)).fetchone():
                is_blacklisted = True
            conn.close()
        except Exception:
            pass

    # 2. Run Modules Concurrently for high-speed responsiveness
    expl = get_explainer()

    with ThreadPoolExecutor(max_workers=5) as executor:
        f_ml = executor.submit(lambda: expl.predict(url) if expl else None)
        f_phish = executor.submit(lambda: analyze_advanced_phishing_indicators(url))
        f_domain = executor.submit(lambda: analyze_domain_intelligence(clean_domain))
        f_ssl = executor.submit(lambda: analyze_ssl_intelligence(clean_domain))
        f_sec = executor.submit(lambda: analyze_website_security(url))
        f_intel = executor.submit(lambda: analyze_threat_intelligence(url, clean_domain))

        ml_result = f_ml.result()
        phish_result = f_phish.result()
        domain_result = f_domain.result()
        ssl_result = f_ssl.result()
        sec_result = f_sec.result()
        intel_result = f_intel.result()

    # 3. Calculate Unified Trust Score
    trust_report = TrustScoreEngine.calculate_trust_score(
        url=url,
        ml_prediction=ml_result,
        phishing_analysis=phish_result,
        domain_intel=domain_result,
        ssl_intel=ssl_result,
        security_assessment=sec_result,
        threat_intel=intel_result,
        is_whitelisted=is_whitelisted,
        is_blacklisted=is_blacklisted
    )

    # 4. Synthesize Evidence-Grounded AI Explanation & Recommendations
    ai_analysis = generate_ai_verdict(
        domain=clean_domain,
        trust_report=trust_report,
        phish_result=phish_result,
        domain_result=domain_result,
        ssl_result=ssl_result,
        sec_result=sec_result,
        intel_result=intel_result
    )

    elapsed_ms = round((time.time() - start_time) * 1000, 1)

    # 5. Assemble Comprehensive Master Report
    investigation_id = hashlib.sha256(f"{url}_{time.time()}".encode()).hexdigest()[:12]

    return {
        "investigation_id": investigation_id,
        "target_url": url,
        "domain": clean_domain,
        "investigated_at": datetime.utcnow().isoformat() + "Z",
        "duration_ms": elapsed_ms,
        "trust_score": trust_report["trust_score"],
        "risk_level": trust_report["risk_level"],
        "risk_label": trust_report["risk_label"],
        "confidence": trust_report["confidence"],
        "summary": trust_report["summary"],
        "ai_explanation": ai_analysis["explanation"],
        "risks_faced": ai_analysis["risks_faced"],
        "actionable_recommendations": ai_analysis["recommendations"],
        "modules": {
            "module_a_phishing": {
                "ml_prediction": ml_result,
                "indicators": phish_result
            },
            "module_b_domain_dns": domain_result,
            "module_c_ssl_tls": ssl_result,
            "module_d_security_audit": sec_result,
            "module_f_threat_intel": intel_result,
            "trust_engine_breakdown": {
                "penalties": trust_report["penalties"],
                "bonuses": trust_report["bonuses"]
            }
        }
    }


def generate_ai_verdict(
    domain: str,
    trust_report: Dict[str, Any],
    phish_result: Dict[str, Any],
    domain_result: Dict[str, Any],
    ssl_result: Dict[str, Any],
    sec_result: Dict[str, Any],
    intel_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate deterministic, evidence-grounded security narrative and actionable advice.
    Strictly cites factual indicators without hallucinations.
    """
    score = trust_report["trust_score"]
    level = trust_report["risk_level"]

    evidence_points = []
    risks = []
    actions = []

    # Evidence Gathering
    if phish_result.get("typosquatting", {}).get("is_typosquatting"):
        for f in phish_result["typosquatting"]["findings"]:
            evidence_points.append(f"Visual Brand Spoofing: {f['description']}")
            risks.append("Credential theft and financial account takeover via impersonated brand login.")

    if phish_result.get("obfuscation", {}).get("is_obfuscated"):
        for ind in phish_result["obfuscation"]["indicators"]:
            evidence_points.append(f"URL Obfuscation: {ind['detail']}")
            risks.append("Evasion of conventional spam and endpoint security filters.")

    age = domain_result.get("domain_age_days", -1)
    if 0 <= age < 14:
        evidence_points.append(f"Domain is brand new (created {age} days ago).")
        risks.append("Ephemeral infrastructure commonly abandoned after phishing campaigns.")

    cert = ssl_result.get("certificate", {})
    if cert.get("risk_flags"):
        for rf in cert["risk_flags"]:
            evidence_points.append(f"Certificate Alert: {rf['detail']}")
            risks.append("Man-in-the-Middle (MitM) interception or rogue certificate authority.")

    if intel_result.get("urlhaus", {}).get("is_flagged"):
        evidence_points.append(f"Listed on URLhaus threat repository: {intel_result['urlhaus'].get('threat')}")
        risks.append("Active malware distribution or phishing campaign confirmed by threat feeds.")

    # Synthesis & Recommendations
    if level == "critical":
        explanation = (
            f"TRUSTX AI investigation confirmed high-confidence malicious indicators for '{domain}'. "
            f"The site exhibits direct threat signatures: {'; '.join(evidence_points[:3]) if evidence_points else 'multiple correlated phishing indicators'}."
        )
        actions.extend([
            "DO NOT enter passwords, credit card numbers, or personal information on this page.",
            "Close the browser tab immediately.",
            "If credentials were submitted previously, change passwords immediately from the official portal."
        ])
    elif level == "high":
        explanation = (
            f"Significant risk indicators detected for '{domain}'. "
            f"Observed anomalies: {'; '.join(evidence_points[:3]) if evidence_points else 'elevated risk score and missing security foundations'}."
        )
        actions.extend([
            "Avoid downloading files or authenticating on this website.",
            "Verify the official web address independently through a trusted search engine."
        ])
    elif level == "medium":
        explanation = (
            f"Moderate risk observed on '{domain}'. While not conclusively flagged on blacklists, "
            f"the domain has security weaknesses or young registration provenance."
        )
        actions.extend([
            "Proceed with heightened vigilance.",
            "Check for valid HTTPS lock icon and verify the destination URL carefully."
        ])
    else:
        explanation = (
            f"'{domain}' demonstrated strong trust indicators. The domain has established provenance, "
            f"valid cryptographic TLS certificates, and clean threat intelligence records."
        )
        actions.extend([
            "Standard safe browsing practices apply.",
            "Ensure connection remains over HTTPS when submitting sensitive data."
        ])

    return {
        "explanation": explanation,
        "risks_faced": risks if risks else ["No acute threats detected under current observations."],
        "recommendations": actions
    }
