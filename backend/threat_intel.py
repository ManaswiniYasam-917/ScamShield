import os
import requests
from urllib.parse import urlparse
from database import check_domain_reputation

GOOGLE_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".buzz", ".surf",
    ".stream", ".gq", ".cf", ".ml", ".ga", ".fit", ".rest", ".monster"
}

def check_url(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    
    # 1. Local Threat Intelligence & Community Blacklist Check
    local_match = check_domain_reputation(host)
    if local_match:
        if local_match.get("reputation") == "malicious":
            return {
                "status": "malicious",
                "source": local_match.get("source", "ScamShield Threat Cloud"),
                "category": local_match.get("category", "Known Phishing"),
                "confidence": local_match.get("confidence", 95),
                "details": f"Flagged in {local_match.get('source')}: {local_match.get('category')} (Confidence: {local_match.get('confidence')}%)"
            }
        elif local_match.get("reputation") == "trusted":
            return {
                "status": "trusted",
                "source": local_match.get("source", "ScamShield Global Whitelist"),
                "category": "Verified Safe",
                "confidence": 100,
                "details": f"Verified benign domain in global trust list: {local_match.get('category')}"
            }

    # 2. Check High Risk Abuse TLDs
    matched_tld = next((tld for tld in HIGH_RISK_TLDS if host.endswith(tld)), None)
    tld_note = f" (Domain uses high-abuse top-level domain {matched_tld})" if matched_tld else ""

    # 3. Google Safe Browsing Check (Optional cloud feed)
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if key:
        payload = {
            "client": {"clientId": "scamshield-advanced-enterprise", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            resp = requests.post(GOOGLE_ENDPOINT, params={"key": key}, json=payload, timeout=4)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    kinds = sorted({m.get("threatType", "known threat") for m in matches})
                    return {
                        "status": "malicious",
                        "source": "Google Safe Browsing v4",
                        "details": f"Confirmed malicious threat match: {', '.join(kinds)}{tld_note}"
                    }
                return {
                    "status": "clean",
                    "source": "Google Safe Browsing v4",
                    "details": f"No active threat signatures matched in Google cloud feeds.{tld_note}"
                }
            elif resp.status_code == 429:
                return {"status": "rate_limited", "details": f"Safe Browsing API rate limited.{tld_note}"}
        except Exception:
            pass

    if matched_tld:
        return {
            "status": "elevated_risk",
            "source": "TLD Intelligence Engine",
            "details": f"Domain registered under high-abuse TLD '{matched_tld}', historically correlated with disposable scam campaigns."
        }

    return {
        "status": "clean",
        "source": "ScamShield Threat Cloud",
        "details": "No active threat signatures or blacklists matched this domain."
    }
