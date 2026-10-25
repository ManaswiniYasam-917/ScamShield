import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from threat_intel import check_url as check_threat_intel
from ml_detector import predict as predict_ml
from dl_detector import predict_dl
from brand_detector import check_brand_spoofing
from content_analyzer import analyze_ssl_certificate, inspect_dns_records, inspect_web_content

try:
    import whois
except Exception:
    whois = None

SUSPICIOUS_WORDS = [
    "login", "verify", "bonus", "discount", "offer", "cheap",
    "free", "deal", "clearance", "wallet", "gift", "prize",
    "secure", "banking", "update", "account", "confirm", "claim"
]

def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value

def analyze_website(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if not host or "." not in host or any(ch.isspace() for ch in host):
        raise ValueError("Invalid URL or hostname format.")

    rule_score = 0
    signals = []

    def add_signal(points: int, text: str, risk: bool = True):
        nonlocal rule_score
        if risk:
            rule_score += points
        signals.append({"text": text, "risk": risk})

    # --- 1. Basic URL & Lexical Structure Checks ---
    if parsed.scheme != "https":
        add_signal(18, "Unencrypted connection: Website uses plain HTTP instead of HTTPS.")
    else:
        add_signal(0, "Connection uses HTTPS protocol encryption.", False)

    if len(url) > 90:
        add_signal(10, f"Abnormally long URL string ({len(url)} characters), common in link obfuscation.")
    if "@" in url:
        add_signal(25, "URL contains user-info '@' delimiter used for credential spoofing tricks.")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        add_signal(30, "Raw IPv4 address used as host instead of a registered domain name.")
    if host.count("-") >= 2:
        add_signal(12, f"Domain contains {host.count('-')} hyphens, frequently associated with fake domain permutations.")
    if len(host.split(".")) >= 4:
        add_signal(12, "Unusually high number of subdomain hierarchies detected.")
    if any(ord(c) > 127 for c in host):
        add_signal(25, "Domain contains internationalized non-ASCII characters (homoglyph risk).")

    hits = [w for w in SUSPICIOUS_WORDS if w in (host + parsed.path + parsed.query).lower()]
    if hits:
        add_signal(min(20, len(hits) * 5), "High-risk financial/promotional keywords present: " + ", ".join(hits) + ".")

    # --- 2. WHOIS Domain Age ---
    domain_age_days = None
    if whois is not None:
        try:
            info = whois.whois(host)
            created = info.creation_date
            if isinstance(created, list):
                created = next((v for v in created if v), None)
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                domain_age_days = max(0, (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days)
                if domain_age_days < 14:
                    add_signal(30, f"Critical Domain Age: Domain was registered only {domain_age_days} days ago.")
                elif domain_age_days < 90:
                    add_signal(15, f"Young Domain: Domain is less than 3 months old ({domain_age_days} days).")
                else:
                    add_signal(0, f"Established domain age: {domain_age_days} days ({round(domain_age_days/365, 1)} years old).", False)
            else:
                add_signal(0, "WHOIS registry returned no public creation date.", False)
        except Exception:
            add_signal(0, "WHOIS lookup query throttled or private; no age penalty applied.", False)
    else:
        add_signal(0, "WHOIS service unconfigured in local runtime.", False)

    # --- 3. SSL/TLS Certificate Analysis ---
    ssl_info = {}
    if parsed.scheme == "https":
        ssl_info = analyze_ssl_certificate(host)
        if ssl_info.get("valid"):
            issuer = ssl_info.get("issuer", "Unknown")
            days = ssl_info.get("days_remaining")
            days_msg = f", expires in {days} days" if days is not None else ""
            add_signal(0, f"Valid TLS Certificate: Issued by {issuer}{days_msg}.", False)
        else:
            add_signal(25, f"SSL/TLS Security Warning: {ssl_info.get('error', 'Handshake failed')}.")
    else:
        ssl_info = {"valid": False, "error": "No HTTPS"}

    # --- 4. DNS Records Inspection ---
    dns_info = inspect_dns_records(host)
    if dns_info.get("resolved_ips"):
        add_signal(0, f"DNS resolution active ({len(dns_info['resolved_ips'])} IPv4 records found).", False)
    else:
        add_signal(15, "Domain failed to resolve standard DNS A records.")

    # --- 5. Brand Impersonation & Typosquatting ---
    brand_spoof = check_brand_spoofing(url)
    if brand_spoof.get("detected"):
        add_signal(brand_spoof.get("risk_score", 35), brand_spoof.get("details", "Brand impersonation detected."))
    elif brand_spoof.get("is_legitimate_brand"):
        add_signal(0, brand_spoof.get("details", "Authentic verified brand domain."), False)

    # --- 6. Live Web Content & HTML Heuristics ---
    content_info = inspect_web_content(url, host)
    for sig in content_info.get("signals", []):
        add_signal(0 if not sig["risk"] else 15, sig["text"], sig["risk"])
    rule_score += content_info.get("risk_penalty", 0)

    # --- 7. Threat Intelligence & Blacklists ---
    threat_intel = check_threat_intel(url)
    if threat_intel.get("status") == "malicious":
        add_signal(55, f"Threat Cloud Match: {threat_intel.get('details', 'Known malicious database record')}.")
    elif threat_intel.get("status") == "elevated_risk":
        add_signal(20, threat_intel.get("details", "High-abuse TLD registered."))

    # --- 8. Machine Learning Ensemble ---
    ml_res = predict_ml(url)
    ml_prob = ml_res.get("probability_percent", 0.0) if ml_res.get("available") else 0.0
    if ml_res.get("available"):
        if ml_prob >= 50.0:
            add_signal(int(ml_prob * 0.3), f"Machine Learning Model flagged URL as suspicious ({ml_prob}% probability).")
        else:
            add_signal(0, f"Machine Learning Model evaluated URL as low risk ({ml_prob}% malicious probability).", False)

    # --- 9. PyTorch Deep Learning 1D-CNN + BiGRU ---
    dl_res = predict_dl(url)
    dl_score = dl_res.get("score_percent", 0.0) if dl_res.get("available") else 0.0
    if dl_res.get("available"):
        if dl_score >= 50.0:
            add_signal(int(dl_score * 0.3), f"Deep Learning Character Neural Network flagged URL ({dl_score}% confidence).")
        else:
            add_signal(0, f"Deep Learning Neural Network evaluated benign character structure ({dl_score}% risk).", False)

    # --- 10. Multi-Engine Fusion & Composite Score ---
    # Normalizing rule score to 0..100
    norm_rule = min(100, max(0, rule_score))
    
    # Composite weighting:
    # If ML/DL models are available: 35% Rules + 35% ML + 30% DL
    # If threat intel is malicious, automatic floor of 85.
    if ml_res.get("available") and dl_res.get("available"):
        composite = (norm_rule * 0.34) + (ml_prob * 0.33) + (dl_score * 0.33)
    elif ml_res.get("available"):
        composite = (norm_rule * 0.50) + (ml_prob * 0.50)
    else:
        composite = norm_rule

    # Brand spoofing gives a significant direct floor
    if brand_spoof.get("detected"):
        composite = max(composite, 65.0)

    # Threat intel malicious match gives critical floor
    if threat_intel.get("status") == "malicious":
        composite = max(composite, 92.0)

    # Authentic verified brand domains receive a steep discount unless proven compromised
    if brand_spoof.get("is_legitimate_brand") and threat_intel.get("status") != "malicious":
        composite = min(composite, 15.0)

    final_score = int(round(min(100, max(0, composite))))

    if final_score >= 80:
        classification = "Critical Threat"
        risk_tier = "CRITICAL"
    elif final_score >= 60:
        classification = "High Risk"
        risk_tier = "HIGH"
    elif final_score >= 30:
        classification = "Moderate Risk"
        risk_tier = "MODERATE"
    else:
        classification = "Lower URL Risk"
        risk_tier = "LOW"

    # --- 11. Explainable AI (XAI) Synthesis ---
    xai = {
        "overall_confidence": final_score,
        "risk_tier": risk_tier,
        "engines": {
            "heuristics_score": norm_rule,
            "ml_ensemble_prob": ml_prob,
            "dl_neural_score": dl_score
        },
        "top_contributing_factors": [s["text"] for s in signals if s.get("risk")][:5],
        "top_ml_features": ml_res.get("top_features", []),
        "action_recommendation": (
            "DO NOT ENTER PERSONAL CREDENTIALS, PASSWORDS, OR PAYMENT INFORMATION. This website exhibits strong signatures of fraud or brand impersonation."
            if final_score >= 60 else
            "Exercise caution before transacting. Review website contact details, WHOIS records, and domain spelling carefully."
            if final_score >= 30 else
            "No immediate malicious signatures detected. Always practice good cyber hygiene and verify checkout security."
        )
    }

    return {
        "url": url,
        "domain": host,
        "score": final_score,
        "classification": classification,
        "risk_tier": risk_tier,
        "signals": signals,
        "domain_age_days": domain_age_days,
        "https_certificate": "Verified" if ssl_info.get("valid") else "Invalid / Absent",
        "http_status": content_info.get("http_status"),
        "title": content_info.get("page_title"),
        "threat_intel": threat_intel,
        "brand_spoof": brand_spoof,
        "ssl": ssl_info,
        "dns": dns_info,
        "ml": ml_res,
        "dl": dl_res,
        "xai": xai
    }
