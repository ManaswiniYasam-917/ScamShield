import re
from urllib.parse import urlparse

HIGH_VALUE_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "walmart": ["walmart.com"],
    "ebay": ["ebay.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "roblox": ["roblox.com"],
    "target": ["target.com"],
    "bestbuy": ["bestbuy.com"]
}

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b', '@': 'a'
}

def levenshtein_distance(s1: str, s2: str) -> int:
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

def normalize_homoglyphs(text: str) -> tuple[str, bool]:
    has_homoglyphs = False
    normalized = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            normalized.append(HOMOGLYPH_MAP[char])
            if ord(char) > 127:
                has_homoglyphs = True
        else:
            normalized.append(char)
    return "".join(normalized), has_homoglyphs

def check_brand_spoofing(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    full_url = url.lower()
    
    if not host:
        return {"detected": False, "impersonated_brand": "", "risk_score": 0, "details": "No host"}

    norm_host, had_homoglyphs = normalize_homoglyphs(host)

    for brand, legit_domains in HIGH_VALUE_BRANDS.items():
        # Check if the host IS an authentic brand domain
        is_legit = any(host == leg or host.endswith("." + leg) for leg in legit_domains)
        if is_legit:
            return {
                "detected": False,
                "is_legitimate_brand": True,
                "impersonated_brand": brand.title(),
                "risk_score": 0,
                "details": f"Verified authentic domain for {brand.title()}."
            }

        # Check for Subdomain Spoofing or Compound Typos
        # e.g. "paypal.com.account-update.xyz" or "login-paypal-security.com"
        for leg in legit_domains:
            leg_name = leg.split(".")[0]
            if len(leg_name) >= 3 and (leg in host or f"{leg_name}-" in host or f"-{leg_name}" in host or f".{leg_name}." in host):
                return {
                    "detected": True,
                    "is_legitimate_brand": False,
                    "impersonated_brand": brand.title(),
                    "attack_type": "Subdomain / Compound Name Spoofing",
                    "risk_score": 40,
                    "legitimate_domain": leg,
                    "details": f"Critical Brand Impersonation: Domain closely mimics authentic brand '{brand.title()} ({leg})' via deceptive compound labeling."
                }

        # Check Levenshtein Distance & Homoglyphs against main brand name
        # Extract domain sublabels (e.g. 'paypa1' from 'paypa1-account-verification.com')
        host_parts = norm_host.split(".")
        if len(host_parts) >= 2:
            main_label = host_parts[-2]
            sublabels = [main_label] + main_label.split("-")
            for sub in sublabels:
                if len(sub) >= 3:
                    dist = levenshtein_distance(sub, brand)
                    if dist == 0 and sub != main_label:
                        return {
                            "detected": True,
                            "is_legitimate_brand": False,
                            "impersonated_brand": brand.title(),
                            "attack_type": "Compound Subdomain / Brand Keyword Hijacking",
                            "risk_score": 40,
                            "legitimate_domain": legit_domains[0],
                            "details": f"Brand Impersonation Detected: Target keyword '{brand}' found in deceptive compound domain label '{main_label}'."
                        }
                    elif dist == 1 or (dist == 2 and len(brand) >= 6):
                        return {
                            "detected": True,
                            "is_legitimate_brand": False,
                            "impersonated_brand": brand.title(),
                            "attack_type": "Typosquatting / Character Substitution",
                            "risk_score": 35,
                            "legitimate_domain": legit_domains[0],
                            "details": f"Typosquatting Detected: Subdomain label '{sub}' is dangerously close to '{brand}' (edit distance: {dist})."
                        }

    if had_homoglyphs:
        return {
            "detected": True,
            "is_legitimate_brand": False,
            "impersonated_brand": "Unknown / Internationalized Attack",
            "attack_type": "IDN Homoglyph Attack",
            "risk_score": 30,
            "details": "Non-ASCII Cyrillic/Greek homoglyph characters discovered in domain name to disguise fake URL."
        }

    return {
        "detected": False,
        "is_legitimate_brand": False,
        "impersonated_brand": "",
        "risk_score": 0,
        "details": "No known corporate brand spoofing detected."
    }
