"""
TRUSTX AI - Central Unified Trust Score Engine
Correlates findings across ML phishing probability, domain intelligence,
SSL/TLS validation, security headers, redirects, and threat intelligence.

Produces an explainable 0 to 100 Trust Score with confidence metrics and penalty breakdown.
"""

from typing import Dict, Any, List, Optional
import math


class TrustScoreEngine:
    """
    Unified Trust Score Calculator (0 - 100).
    Higher score represents higher trustworthiness.
    
    Tiers:
    - 80 to 100: Low Observed Risk (Trusted)
    - 50 to 79:  Moderate Risk
    - 25 to 49:  High Risk
    - 0 to 24:   Critical Risk
    """

    @staticmethod
    def calculate_trust_score(
        url: str,
        ml_prediction: Optional[Dict[str, Any]] = None,
        phishing_analysis: Optional[Dict[str, Any]] = None,
        domain_intel: Optional[Dict[str, Any]] = None,
        ssl_intel: Optional[Dict[str, Any]] = None,
        security_assessment: Optional[Dict[str, Any]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        is_whitelisted: bool = False,
        is_blacklisted: bool = False,
    ) -> Dict[str, Any]:
        """
        Calculate unified trust score, classification, confidence, and audit trail.
        """
        # Baseline starting score
        score = 85.0
        confidence_points = 50.0  # Base confidence
        penalties = []
        bonuses = []

        # ---------------- 1. Hard Overrides ----------------
        if is_blacklisted:
            return {
                "trust_score": 5.0,
                "risk_level": "critical",
                "risk_label": "Critical Threat (Blacklisted)",
                "confidence": 99.0,
                "penalties": [{"category": "blacklist", "reason": "Domain is on explicit threat blacklist", "points": -95}],
                "bonuses": [],
                "summary": "This domain is confirmed malicious by blacklist records. Immediate navigation blocked."
            }

        if is_whitelisted:
            return {
                "trust_score": 98.0,
                "risk_level": "safe",
                "risk_label": "Verified Trusted Entity",
                "confidence": 98.0,
                "penalties": [],
                "bonuses": [{"category": "whitelist", "reason": "Pre-verified official trusted organization", "points": +15}],
                "summary": "Domain is an established, pre-verified reputable authority."
            }

        # ---------------- 2. External Threat Intelligence ----------------
        if threat_intel and threat_intel.get("urlhaus", {}).get("is_flagged"):
            p_val = 75
            score -= p_val
            penalties.append({
                "category": "threat_intel",
                "reason": f"Active threat listed on URLhaus: {threat_intel['urlhaus'].get('threat', 'Malware/Phishing')}",
                "points": -p_val
            })
            confidence_points += 25

        if threat_intel and threat_intel.get("community", {}).get("community_verdict") == "phishing":
            p_val = 30
            score -= p_val
            penalties.append({
                "category": "community_reports",
                "reason": f"Multiple community phishing reports submitted ({threat_intel['community'].get('phishing_reports')} reports)",
                "points": -p_val
            })
            confidence_points += 15

        # ---------------- 3. ML Model Phishing Inference ----------------
        if ml_prediction:
            phishing_prob = ml_prediction.get("phishing_probability", 0.0) / 100.0  # 0.0 to 1.0
            confidence_points += 20

            if phishing_prob > 0.85:
                p_val = round(phishing_prob * 45, 1)
                score -= p_val
                penalties.append({
                    "category": "machine_learning",
                    "reason": f"AI model detected extreme phishing pattern indicators ({round(phishing_prob*100, 1)}% probability)",
                    "points": -p_val
                })
            elif phishing_prob > 0.50:
                p_val = round(phishing_prob * 30, 1)
                score -= p_val
                penalties.append({
                    "category": "machine_learning",
                    "reason": f"AI model flagged suspicious structural URL anomalies ({round(phishing_prob*100, 1)}% probability)",
                    "points": -p_val
                })
            elif phishing_prob < 0.15:
                b_val = 5.0
                score += b_val
                bonuses.append({
                    "category": "machine_learning",
                    "reason": f"AI model confirmed clean lexical patterns ({round((1-phishing_prob)*100, 1)}% safe probability)",
                    "points": +b_val
                })

        # ---------------- 4. Typosquatting & Obfuscation (Module A) ----------------
        if phishing_analysis:
            typo = phishing_analysis.get("typosquatting", {})
            if typo.get("is_typosquatting"):
                for finding in typo.get("findings", []):
                    p_val = 40 if finding.get("type") in ["homoglyph_substitution", "typosquatting_lookalike"] else 25
                    score -= p_val
                    penalties.append({
                        "category": "brand_protection",
                        "reason": finding.get("description", "Potential brand impersonation / typosquatting"),
                        "points": -p_val
                    })
                confidence_points += 20

            obf = phishing_analysis.get("obfuscation", {})
            if obf.get("is_obfuscated"):
                for ind in obf.get("indicators", []):
                    p_val = 25 if ind.get("severity") == "critical" else 15
                    score -= p_val
                    penalties.append({
                        "category": "url_obfuscation",
                        "reason": f"{ind.get('technique')}: {ind.get('detail')}",
                        "points": -p_val
                    })
                confidence_points += 10

        # ---------------- 5. Domain & DNS Intelligence (Module B) ----------------
        if domain_intel:
            confidence_points += 15
            for rf in domain_intel.get("risk_factors", []):
                p_val = abs(rf.get("impact", 10))
                score -= p_val
                penalties.append({
                    "category": "domain_dns",
                    "reason": rf.get("message"),
                    "points": -p_val
                })
            for tb in domain_intel.get("trust_bonuses", []):
                b_val = abs(tb.get("impact", 5))
                score += b_val
                bonuses.append({
                    "category": "domain_dns",
                    "reason": tb.get("message"),
                    "points": +b_val
                })

        # ---------------- 6. SSL/TLS Certificate Analysis (Module C) ----------------
        if ssl_intel:
            cert = ssl_intel.get("certificate", {})
            confidence_points += 15

            if not cert.get("has_ssl"):
                p_val = 15
                score -= p_val
                penalties.append({
                    "category": "ssl_tls",
                    "reason": "Missing SSL/TLS encryption (plain HTTP connection)",
                    "points": -p_val
                })
            else:
                for rf in cert.get("risk_flags", []):
                    p_val = 40 if rf.get("severity") == "critical" else 20
                    score -= p_val
                    penalties.append({
                        "category": "ssl_tls",
                        "reason": f"[{rf.get('code')}] {rf.get('detail')}",
                        "points": -p_val
                    })

                # Modest bonus for valid SSL, but explicitly NOT full immunity
                if cert.get("is_valid") and not cert.get("is_self_signed"):
                    b_val = 5.0
                    score += b_val
                    bonuses.append({
                        "category": "ssl_tls",
                        "reason": f"Valid {cert.get('tls_version', 'TLS')} connection with matched hostname",
                        "points": +b_val
                    })

        # ---------------- 7. Website Security Assessment (Module D) ----------------
        if security_assessment and security_assessment.get("is_accessible"):
            confidence_points += 10
            # Redirect weakness
            for w in security_assessment.get("weaknesses", []):
                if w.get("code") == "CROSS_DOMAIN_REDIRECT":
                    p_val = 20
                    score -= p_val
                    penalties.append({
                        "category": "redirects",
                        "reason": w.get("detail"),
                        "points": -p_val
                    })

            # Missing headers penalty (mild)
            h_missing = len(security_assessment.get("headers_audit", {}).get("missing", []))
            if h_missing >= 4:
                p_val = 8
                score -= p_val
                penalties.append({
                    "category": "security_headers",
                    "reason": f"Missing {h_missing} foundational security headers (e.g. HSTS, CSP, X-Frame-Options)",
                    "points": -p_val
                })

        # Clamp Final Trust Score to [0, 100]
        final_score = max(0.0, min(100.0, round(score, 1)))
        final_confidence = max(20.0, min(99.0, round(confidence_points, 1)))

        # Assign Risk Tiers
        if final_score >= 80.0:
            risk_level = "safe"
            risk_label = "Low Observed Risk (Trusted)"
        elif final_score >= 50.0:
            risk_level = "medium"
            risk_label = "Moderate Risk (Proceed with Caution)"
        elif final_score >= 25.0:
            risk_level = "high"
            risk_label = "High Risk (Suspicious Website)"
        else:
            risk_level = "critical"
            risk_label = "Critical Risk (Malicious / Phishing Threat)"

        return {
            "trust_score": final_score,
            "risk_level": risk_level,
            "risk_label": risk_label,
            "confidence": final_confidence,
            "penalties": penalties,
            "bonuses": bonuses,
            "penalties_total": sum(abs(p['points']) for p in penalties),
            "summary": f"Calculated Trust Score: {final_score}/100. Level: {risk_label}."
        }
