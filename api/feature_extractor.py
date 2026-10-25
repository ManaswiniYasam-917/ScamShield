import re
import math
import ipaddress
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_at_symbols",
    "num_percent_signs",
    "num_digits",
    "digit_ratio",
    "uppercase_ratio",
    "url_entropy",
    "host_entropy",
    "is_https",
    "is_ip_host",
    "subdomain_count",
    "has_port",
    "has_double_slash_path",
    "has_tld_in_path",
    "suspicious_word_count",
    "suspicious_word_density",
    "is_shortener",
    "has_non_ascii",
    "vowel_consonant_ratio"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "update",
    "account", "banking", "bank", "confirm", "confirmation", "wallet",
    "crypto", "gift", "prize", "claim", "bonus", "discount", "free",
    "checkout", "billing", "payment", "support", "signin", "auth",
    "validate", "unlock", "alert", "notification", "recover", "passcode"
]

SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "t.co", "cutt.ly", "rb.gy", "shorturl.at"
}

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_url_features(url: str) -> list[float]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_text = url.lower()

    # 1-4. Lengths
    url_len = len(url)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    # 5-12. Character Counts
    num_dots = host.count(".")
    num_hyphens = host.count("-") + path.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_questions = url.count("?")
    num_equals = url.count("=")
    num_ats = url.count("@")
    num_percents = url.count("%")

    # 13-15. Digits & Case
    num_digits = sum(c.isdigit() for c in url)
    letters_count = sum(c.isalpha() for c in url)
    digit_ratio = round(num_digits / max(1, url_len), 4)
    num_upper = sum(c.isupper() for c in url)
    uppercase_ratio = round(num_upper / max(1, url_len), 4)

    # 16-17. Entropies
    url_entropy = calculate_shannon_entropy(url)
    host_entropy = calculate_shannon_entropy(host)

    # 18-21. Network & Scheme
    is_https = 1.0 if parsed.scheme == "https" else 0.0
    try:
        is_ip = 1.0 if bool(ipaddress.ip_address(host)) else 0.0
    except ValueError:
        is_ip = 0.0

    parts = host.split(".")
    subdomain_count = max(0, len(parts) - 2) if not is_ip else 0
    has_port = 1.0 if parsed.port is not None else 0.0

    # 22-23. Structural Anomaly
    has_double_slash_path = 1.0 if "//" in path else 0.0
    common_tlds = [".com", ".net", ".org", ".info", ".xyz", ".top", ".club"]
    has_tld_in_path = 1.0 if any(tld in path.lower() for tld in common_tlds) else 0.0

    # 24-25. Semantic keywords
    combined_body = (host + " " + path.replace("/", " ") + " " + query).lower()
    word_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in combined_body)
    words = re.findall(r"[a-z]+", combined_body)
    total_words = len(words)
    suspicious_word_density = round(word_hits / max(1, total_words), 4)

    # 26-28. Obfuscation & Linguistic
    is_shortener = 1.0 if host in SHORTENER_DOMAINS else 0.0
    has_non_ascii = 1.0 if any(ord(c) > 127 for c in host) else 0.0

    vowels = sum(c in "aeiou" for c in host.lower())
    consonants = sum(c.isalpha() and c not in "aeiou" for c in host.lower())
    vowel_consonant_ratio = round(vowels / max(1, consonants), 4)

    return [
        float(url_len),
        float(host_len),
        float(path_len),
        float(query_len),
        float(num_dots),
        float(num_hyphens),
        float(num_underscores),
        float(num_slashes),
        float(num_questions),
        float(num_equals),
        float(num_ats),
        float(num_percents),
        float(num_digits),
        float(digit_ratio),
        float(uppercase_ratio),
        float(url_entropy),
        float(host_entropy),
        float(is_https),
        float(is_ip),
        float(subdomain_count),
        float(has_port),
        float(has_double_slash_path),
        float(has_tld_in_path),
        float(word_hits),
        float(suspicious_word_density),
        float(is_shortener),
        float(has_non_ascii),
        float(vowel_consonant_ratio)
    ]
