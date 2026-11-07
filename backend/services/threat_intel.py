"""
TRUSTX AI - Module F: Collaborative Threat Intelligence Service
Integrates community threat reports, external threat feeds (URLhaus),
and domain reputation scoring.
"""

import requests
import hashlib
import sqlite3
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger('trustx-threat-intel')

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'trustx.db')


def query_urlhaus(url_or_domain: str) -> Dict[str, Any]:
    """
    Check if a URL or host is flagged in abuse.ch URLhaus threat database.
    """
    result = {
        "is_flagged": False,
        "threat": None,
        "urlhaus_status": None,
        "tags": [],
        "reporter": None,
        "checked": False
    }

    try:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {'url': url_or_domain}
        resp = requests.post(api_url, data=data, timeout=3.0, headers={'User-Agent': 'TRUSTX-AI/1.0'})

        if resp.status_code == 200:
            res_json = resp.json()
            result["checked"] = True
            query_status = res_json.get("query_status")

            if query_status == "ok":
                result["is_flagged"] = True
                result["threat"] = res_json.get("threat")
                result["urlhaus_status"] = res_json.get("url_status")
                result["tags"] = res_json.get("tags") or []
                result["reporter"] = res_json.get("reporter")
    except Exception as e:
        logger.debug(f"URLhaus lookup error: {e}")

    return result


def query_community_threat_intel(url: str, domain: str) -> Dict[str, Any]:
    """
    Query local collaborative threat database for community reports,
    report frequency, and consensus verification.
    """
    clean_domain = domain.lower()
    url_hash = hashlib.md5(url.encode()).hexdigest()

    result = {
        "report_count": 0,
        "phishing_reports": 0,
        "false_positive_reports": 0,
        "community_verdict": "neutral",
        "latest_reports": []
    }

    if not os.path.exists(DB_PATH):
        return result

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        # Query reports matching this URL or domain
        cursor = conn.cursor()
        rows = cursor.execute(
            '''SELECT report_type, description, reported_at, status 
               FROM reported_urls 
               WHERE url_hash = ? OR url LIKE ? 
               ORDER BY reported_at DESC LIMIT 10''',
            (url_hash, f"%{clean_domain}%")
        ).fetchall()

        result["report_count"] = len(rows)
        for r in rows:
            rtype = r['report_type']
            if rtype == 'phishing':
                result["phishing_reports"] += 1
            elif rtype == 'false_positive':
                result["false_positive_reports"] += 1

            result["latest_reports"].append({
                "type": rtype,
                "description": r['description'],
                "reported_at": r['reported_at'],
                "status": r['status']
            })

        if result["phishing_reports"] > result["false_positive_reports"] and result["phishing_reports"] >= 2:
            result["community_verdict"] = "phishing"
        elif result["false_positive_reports"] > result["phishing_reports"]:
            result["community_verdict"] = "likely_safe"

        conn.close()
    except Exception as e:
        logger.error(f"Error querying community threat intel: {e}")

    return result


def analyze_threat_intelligence(url: str, domain: str) -> Dict[str, Any]:
    """
    Run complete Module F threat correlation:
    URLhaus + Community Reports + Blacklist/Whitelist state.
    """
    clean_domain = domain.lower().split(':')[0]
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]

    urlhaus_data = query_urlhaus(url)
    community_data = query_community_threat_intel(url, clean_domain)

    is_known_threat = urlhaus_data["is_flagged"] or community_data["community_verdict"] == "phishing"

    return {
        "urlhaus": urlhaus_data,
        "community": community_data,
        "is_known_threat": is_known_threat,
        "summary": "Flagged by threat intelligence databases" if is_known_threat else "No active blacklist or URLhaus threat matches"
    }
