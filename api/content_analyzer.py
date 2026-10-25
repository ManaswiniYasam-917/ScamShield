import socket
import ssl
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_ssrf_safe(hostname: str) -> bool:
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            for priv in PRIVATE_NETWORKS:
                if ip_obj in priv:
                    return False
        return True
    except Exception:
        return False

def analyze_ssl_certificate(host: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3.5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Expiry check
                not_after_str = cert.get("notAfter", "")
                days_left = None
                if not_after_str:
                    try:
                        exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (exp_date - datetime.now(timezone.utc)).days
                    except Exception:
                        pass

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_org = issuer.get("organizationName", issuer.get("commonName", "Unknown Issuer"))

                return {
                    "valid": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else "Unknown",
                    "issuer": issuer_org,
                    "days_remaining": days_left,
                    "expired": days_left is not None and days_left < 0,
                    "short_lived": days_left is not None and days_left < 30
                }
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": "Certificate untrusted or self-signed", "details": str(exc)}
    except Exception as exc:
        return {"valid": False, "error": "Connection failed / TLS handshake error", "details": str(exc)}

def inspect_dns_records(host: str) -> dict:
    dns_data = {"resolved_ips": [], "has_mx": False, "mx_records": []}
    try:
        # Resolve A records
        ips = socket.gethostbyname_ex(host)[2]
        dns_data["resolved_ips"] = ips[:4]
    except Exception:
        pass
        
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, 'MX', lifetime=2)
        dns_data["has_mx"] = len(answers) > 0
        dns_data["mx_records"] = [str(r.exchange).rstrip('.') for r in answers][:3]
    except Exception:
        pass

    return dns_data

def inspect_web_content(url: str, host: str) -> dict:
    result = {
        "http_status": None,
        "page_title": None,
        "signals": [],
        "risk_penalty": 0,
        "scam_indicators": {
            "credential_harvesting": False,
            "extreme_discounts": False,
            "urgency_triggers": False,
            "missing_policies": False
        }
    }

    if not is_ssrf_safe(host):
        result["signals"].append({"text": "Target host resolves to a private or restricted loopback IP address (SSRF blocked).", "risk": True})
        result["risk_penalty"] += 30
        return result

    try:
        resp = requests.get(
            url,
            timeout=4.5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        )
        result["http_status"] = resp.status_code
        content_type = resp.headers.get("Content-Type", "").lower()

        if "text/html" in content_type:
            soup = BeautifulSoup(resp.text[:600_000], "html.parser")
            if soup.title:
                result["page_title"] = soup.title.get_text(" ", strip=True)[:180]

            text = soup.get_text(" ", strip=True).lower()

            # 1. Credential harvesting forms check
            password_inputs = soup.find_all("input", {"type": "password"})
            if password_inputs:
                if not url.lower().startswith("https://"):
                    result["signals"].append({"text": "Critical: Password input detected over unencrypted HTTP connection.", "risk": True})
                    result["risk_penalty"] += 35
                    result["scam_indicators"]["credential_harvesting"] = True
                else:
                    for pw in password_inputs:
                        form = pw.find_parent("form")
                        if form and form.get("action"):
                            action = form["action"].lower()
                            if action.startswith("http") and not action.startswith(f"https://{host}") and not action.startswith(f"//{host}"):
                                result["signals"].append({"text": "High Risk: Login form submits credentials to a foreign external origin.", "risk": True})
                                result["risk_penalty"] += 30
                                result["scam_indicators"]["credential_harvesting"] = True
                                break

            # 2. Extreme urgent psychological cues
            urgency_patterns = [
                "account will be suspended", "immediate action required", "unauthorized login attempt",
                "verify within 24 hours", "final warning", "account deactivated", "security breach alert"
            ]
            urgent_hits = [p for p in urgency_patterns if p in text]
            if urgent_hits:
                result["signals"].append({"text": f"Aggressive panic/urgency phrasing detected: '{', '.join(urgent_hits[:2])}'.", "risk": True})
                result["risk_penalty"] += 15
                result["scam_indicators"]["urgency_triggers"] = True

            # 3. Flash sale & extreme discount hooks
            discount_patterns = ["90% off", "95% off", "free gift card", "exclusive prize winner", "congratulations! you won"]
            discount_hits = [p for p in discount_patterns if p in text]
            if discount_hits:
                result["signals"].append({"text": f"Unrealistic promotional/discount hooks detected: '{', '.join(discount_hits)}'.", "risk": True})
                result["risk_penalty"] += 15
                result["scam_indicators"]["extreme_discounts"] = True

            # 4. Legitimacy policies
            has_contact = any(w in text for w in ["contact us", "customer service", "support@", "help center"])
            has_refund = any(w in text for w in ["refund policy", "return policy", "returns & refunds"])
            has_terms = any(w in text for w in ["terms of service", "terms & conditions", "privacy policy"])

            if not has_contact and not has_terms:
                result["signals"].append({"text": "No corporate contact information or privacy policy links found.", "risk": True})
                result["risk_penalty"] += 10
                result["scam_indicators"]["missing_policies"] = True
            else:
                result["signals"].append({"text": "Standard legal/contact policy pages detected on site.", "risk": False})

    except Exception:
        result["signals"].append({"text": "Live page connection timed out or was firewalled by target host.", "risk": False})

    return result
