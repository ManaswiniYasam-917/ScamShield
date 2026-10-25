import os
import sqlite3
import json
import hashlib
import secrets
import tempfile
from datetime import datetime, timezone

def get_db_path() -> str:
    # 1. Check for any cloud/serverless environment variable (Vercel, AWS Lambda, etc.)
    cloud_vars = [
        "VERCEL", "VERCEL_ENV", "VERCEL_URL", "VERCEL_REGION",
        "NOW_REGION", "AWS_LAMBDA_FUNCTION_NAME", "LAMBDA_TASK_ROOT"
    ]
    if any(os.getenv(k) for k in cloud_vars):
        tmp_dir = os.path.join(tempfile.gettempdir(), "scamshield")
        os.makedirs(tmp_dir, exist_ok=True)
        return os.path.join(tmp_dir, "scamshield.db")

    # 2. Check if local backend/api directory is writable
    local_dir = os.path.join(os.path.dirname(__file__), "data")
    try:
        os.makedirs(local_dir, exist_ok=True)
        test_file = os.path.join(local_dir, ".write_test")
        with open(test_file, "w") as f:
            f.write("1")
        os.remove(test_file)
        return os.path.join(local_dir, "scamshield.db")
    except Exception:
        # Fallback to temp directory on any permission/read-only restriction
        tmp_dir = os.path.join(tempfile.gettempdir(), "scamshield")
        os.makedirs(tmp_dir, exist_ok=True)
        return os.path.join(tmp_dir, "scamshield.db")

DB_PATH = get_db_path()
DB_DIR = os.path.dirname(DB_PATH)

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"{salt}:{key.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt, key_hex = stored_password.split(":")
        new_key = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return secrets.compare_digest(new_key.hex(), key_hex)
    except Exception:
        return False

def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

_DB_INITIALIZED = False

def ensure_db_ready():
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    try:
        with connect() as conn:
            c = conn.execute("SELECT COUNT(*) as c FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
            if not c or c["c"] == 0:
                init_db()
            else:
                _DB_INITIALIZED = True
    except Exception:
        init_db()

def init_db():
    global _DB_INITIALIZED
    with connect() as conn:
        # 1. Scans table with advanced AI/ML/DL telemetry
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scanned_at TEXT NOT NULL,
                url TEXT NOT NULL,
                domain TEXT,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                risk_tier TEXT DEFAULT 'LOW',
                signals_json TEXT NOT NULL,
                domain_age_days INTEGER,
                http_status INTEGER,
                threat_status TEXT DEFAULT 'not_checked',
                threat_details TEXT DEFAULT '',
                ml_prediction TEXT DEFAULT 'not_analyzed',
                ml_probability REAL DEFAULT 0.0,
                dl_score REAL DEFAULT 0.0,
                brand_detected TEXT DEFAULT '',
                ssl_info_json TEXT DEFAULT '{}',
                dns_info_json TEXT DEFAULT '{}',
                xai_factors_json TEXT DEFAULT '[]',
                report_hash TEXT DEFAULT ''
            )
        """)

        # Graceful column migration for any existing databases
        existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()}
        migration_cols = {
            "user_id": "INTEGER",
            "risk_tier": "TEXT DEFAULT 'LOW'",
            "ml_prediction": "TEXT DEFAULT 'not_analyzed'",
            "ml_probability": "REAL DEFAULT 0.0",
            "dl_score": "REAL DEFAULT 0.0",
            "brand_detected": "TEXT DEFAULT ''",
            "ssl_info_json": "TEXT DEFAULT '{}'",
            "dns_info_json": "TEXT DEFAULT '{}'",
            "xai_factors_json": "TEXT DEFAULT '[]'",
            "report_hash": "TEXT DEFAULT ''",
            "threat_status": "TEXT DEFAULT 'not_checked'",
            "threat_details": "TEXT DEFAULT ''"
        }
        for col, col_type in migration_cols.items():
            if col not in existing_cols:
                try:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {col_type}")
                except Exception:
                    pass

        # 2. Users table with RBAC (admin, analyst, user)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                api_key TEXT UNIQUE,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        # 3. Community Threat Reports table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS community_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                reporter_name TEXT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'high',
                evidence_notes TEXT,
                upvotes INTEGER DEFAULT 1,
                status TEXT DEFAULT 'verified',
                created_at TEXT NOT NULL
            )
        """)

        # 4. Domain Reputation Watchlist / Blacklist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                reputation TEXT NOT NULL,
                source TEXT DEFAULT 'ScamShield Intel',
                category TEXT DEFAULT 'Phishing',
                confidence INTEGER DEFAULT 95,
                added_at TEXT NOT NULL
            )
        """)

        # 5. Audit Log Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Seed Default Users if empty
        user_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        if user_count == 0:
            now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            demo_users = [
                ("admin@scamshield.io", hash_password("Admin@12345"), "Security Operations Lead", "admin", "scam_ak_admin_" + secrets.token_hex(12), now),
                ("analyst@scamshield.io", hash_password("Analyst@12345"), "Cyber Threat Analyst", "analyst", "scam_ak_analyst_" + secrets.token_hex(12), now),
                ("user@scamshield.io", hash_password("User@12345"), "Verified Consumer", "user", "scam_ak_user_" + secrets.token_hex(12), now),
            ]
            conn.executemany("""
                INSERT INTO users (email, password_hash, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, demo_users)

        # Seed Known Blacklisted & Trusted domains if empty
        rep_count = conn.execute("SELECT COUNT(*) as c FROM domain_reputation").fetchone()["c"]
        if rep_count == 0:
            now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            initial_rep = [
                ("paypal-account-verify-support.com", "malicious", "PhishTank Threat Feed", "Credential Phishing", 99, now),
                ("amazon-prime-renewal-billing.xyz", "malicious", "ScamShield Threat Cloud", "Fake Checkout & Billing", 98, now),
                ("appleid-login-verification-icloud.net", "malicious", "OpenPhish Intelligence", "Apple ID Theft", 97, now),
                ("netflix-subscription-billing-update.top", "malicious", "ScamShield Neural Intel", "Subscription Scam", 96, now),
                ("secure-chase-banking-alert.club", "malicious", "Banking Protection Network", "Financial Impersonation", 99, now),
                ("binance-wallets-gift-claim.site", "malicious", "Crypto Anti-Fraud Net", "Crypto Drainer", 98, now),
                ("google.com", "trusted", "Global Tranco Top 1M", "Benign Search & Cloud", 100, now),
                ("amazon.com", "trusted", "Global Tranco Top 1M", "Benign E-Commerce", 100, now),
                ("paypal.com", "trusted", "Global Tranco Top 1M", "Benign Financial", 100, now),
                ("apple.com", "trusted", "Global Tranco Top 1M", "Benign Technology", 100, now),
                ("microsoft.com", "trusted", "Global Tranco Top 1M", "Benign Technology", 100, now),
            ]
            conn.executemany("""
                INSERT OR IGNORE INTO domain_reputation (domain, reputation, source, category, confidence, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, initial_rep)

        # Seed initial community reports if empty
        rep_count2 = conn.execute("SELECT COUNT(*) as c FROM community_reports").fetchone()["c"]
        if rep_count2 == 0:
            now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            initial_reports = [
                (1, "SOC Lead Alex", "https://amazon-prime-renewal-billing.xyz/claim", "amazon-prime-renewal-billing.xyz", "Fake E-Commerce", "Received fake SMS invoice asking to confirm prime renewal with credit card CVV.", "critical", "Harvests CVV and OTP directly in fake form", 42, "verified", now),
                (2, "Analyst Sarah", "https://paypal-account-verify-support.com/auth", "paypal-account-verify-support.com", "Credential Phishing", "Impersonates PayPal login screen with Russian hosting and no valid corporate SSL.", "high", "Cloned login page targeting email and password", 28, "verified", now),
                (3, "Consumer Mark", "http://cheap-shoes-clearance-outlet.shop", "cheap-shoes-clearance-outlet.shop", "Counterfeit Store", "Sells luxury footwear at 95% discount. Credit card charged recurring overseas subscription.", "medium", "Registered 3 days ago, no return policy, stolen imagery", 19, "verified", now),
                (2, "Analyst Sarah", "https://binance-wallets-gift-claim.site/airdrop", "binance-wallets-gift-claim.site", "Crypto Drainer", "Malicious Web3 drainer asking user to connect Metamask to claim 500 USDT.", "critical", "Automated contract approval payload identified", 54, "verified", now),
            ]
            conn.executemany("""
                INSERT INTO community_reports (user_id, reporter_name, url, domain, threat_category, description, severity, evidence_notes, upvotes, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, initial_reports)

        conn.commit()
        _DB_INITIALIZED = True

# --- Scan DB Queries ---

def insert_scan(result: dict, user_id: int = None) -> int:
    ensure_db_ready()
    with connect() as conn:
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        report_hash = hashlib.sha256(f"{result['url']}-{now}-{result['score']}".encode()).hexdigest()[:16]
        
        cur = conn.execute("""
            INSERT INTO scans (
                user_id, scanned_at, url, domain, score, classification, risk_tier,
                signals_json, domain_age_days, http_status, threat_status, threat_details,
                ml_prediction, ml_probability, dl_score, brand_detected,
                ssl_info_json, dns_info_json, xai_factors_json, report_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            now,
            result["url"],
            result.get("domain", ""),
            result.get("score", 0),
            result.get("classification", "Unknown"),
            result.get("risk_tier", "LOW"),
            json.dumps(result.get("signals", []), ensure_ascii=False),
            result.get("domain_age_days"),
            result.get("http_status"),
            result.get("threat_intel", {}).get("status", "not_checked"),
            result.get("threat_intel", {}).get("details", ""),
            result.get("ml", {}).get("prediction", "not_analyzed"),
            result.get("ml", {}).get("probability_percent", 0.0),
            result.get("dl", {}).get("score_percent", 0.0),
            result.get("brand_spoof", {}).get("impersonated_brand", ""),
            json.dumps(result.get("ssl", {}), ensure_ascii=False),
            json.dumps(result.get("dns", {}), ensure_ascii=False),
            json.dumps(result.get("xai", {}), ensure_ascii=False),
            report_hash
        ))
        conn.commit()
        return cur.lastrowid

def list_scans(limit=25, user_id=None):
    ensure_db_ready()
    with connect() as conn:
        if user_id:
            rows = conn.execute("""
                SELECT id, user_id, scanned_at, url, domain, score, classification, risk_tier,
                       domain_age_days, http_status, threat_status, ml_prediction, ml_probability,
                       dl_score, brand_detected, report_hash
                FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?
            """, (user_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, user_id, scanned_at, url, domain, score, classification, risk_tier,
                       domain_age_days, http_status, threat_status, ml_prediction, ml_probability,
                       dl_score, brand_detected, report_hash
                FROM scans ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
    return [dict(r) for r in rows]

def get_scan(scan_id: int):
    ensure_db_ready()
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    item = dict(row)
    for json_col in ["signals_json", "ssl_info_json", "dns_info_json", "xai_factors_json"]:
        plain_key = json_col.replace("_json", "")
        if plain_key == "signals":
            plain_key = "signals"
        try:
            item[plain_key] = json.loads(item.pop(json_col) or "[]")
        except Exception:
            item[plain_key] = [] if "signals" in json_col or "factors" in json_col else {}
    return item

def scan_stats():
    ensure_db_ready()
    with connect() as conn:
        row = conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN score >= 35 THEN 1 ELSE 0 END) as flagged,
                SUM(CASE WHEN score >= 65 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN score >= 85 THEN 1 ELSE 0 END) as critical_threat,
                COUNT(DISTINCT domain) as domains,
                AVG(score) as avg_score
            FROM scans
        """).fetchone()

        daily = conn.execute("""
            SELECT 
                substr(scanned_at, 1, 10) as day,
                COUNT(*) as scans,
                SUM(CASE WHEN score >= 35 THEN 1 ELSE 0 END) as flagged,
                SUM(CASE WHEN score >= 65 THEN 1 ELSE 0 END) as high_risk
            FROM scans
            GROUP BY substr(scanned_at, 1, 10)
            ORDER BY day DESC LIMIT 7
        """).fetchall()

        top = conn.execute("""
            SELECT domain, MAX(score) as max_score, COUNT(*) as scans, MAX(risk_tier) as tier
            FROM scans WHERE score >= 35
            GROUP BY domain
            ORDER BY max_score DESC, scans DESC LIMIT 6
        """).fetchall()

        threat = conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN threat_status = 'malicious' THEN 1 ELSE 0 END) as malicious
            FROM scans WHERE threat_status != 'not_checked'
        """).fetchone()

        ai_stats = conn.execute("""
            SELECT
                SUM(CASE WHEN ml_prediction = 'suspicious' THEN 1 ELSE 0 END) as ml_flagged,
                SUM(CASE WHEN dl_score >= 60.0 THEN 1 ELSE 0 END) as dl_flagged,
                COUNT(CASE WHEN brand_detected != '' AND brand_detected IS NOT NULL THEN 1 END) as brand_spoofs
            FROM scans
        """).fetchone()

        rep_stats = conn.execute("""
            SELECT 
                COUNT(*) as total_intel,
                SUM(CASE WHEN reputation = 'malicious' THEN 1 ELSE 0 END) as malicious_count,
                SUM(CASE WHEN reputation = 'trusted' THEN 1 ELSE 0 END) as trusted_count
            FROM domain_reputation
        """).fetchone()

    return {
        "total_scans": row["total"] or 0,
        "flagged_scans": row["flagged"] or 0,
        "high_risk_scans": row["high_risk"] or 0,
        "critical_threat_scans": row["critical_threat"] or 0,
        "average_risk_score": round(row["avg_score"] or 0, 1),
        "unique_domains": row["domains"] or 0,
        "daily": [dict(x) for x in reversed(daily)],
        "top_flagged_domains": [dict(x) for x in top],
        "threat_intelligence": {
            "checked": threat["total"] or 0,
            "malicious": threat["malicious"] or 0,
            "database_entries": rep_stats["total_intel"] or 0
        },
        "ai_engine_telemetry": {
            "ml_flagged": ai_stats["ml_flagged"] or 0,
            "dl_flagged": ai_stats["dl_flagged"] or 0,
            "brand_spoofs_detected": ai_stats["brand_spoofs"] or 0
        }
    }

# --- User & Auth Queries ---

def create_user(email: str, password: str, full_name: str, role: str = "user"):
    ensure_db_ready()
    with connect() as conn:
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        api_key = f"scam_ak_{role}_" + secrets.token_hex(16)
        pwd_hash = hash_password(password)
        try:
            cur = conn.execute("""
                INSERT INTO users (email, password_hash, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email.lower().strip(), pwd_hash, full_name.strip(), role, api_key, now))
            conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

def get_user_by_email(email: str):
    ensure_db_ready()
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
    return dict(row) if row else None

def get_user_by_id(user_id: int):
    ensure_db_ready()
    with connect() as conn:
        row = conn.execute("SELECT id, email, full_name, role, api_key, is_active, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None

def get_user_by_api_key(api_key: str):
    ensure_db_ready()
    with connect() as conn:
        row = conn.execute("SELECT id, email, full_name, role, is_active FROM users WHERE api_key = ?", (api_key.strip(),)).fetchone()
    return dict(row) if row else None

def list_all_users():
    ensure_db_ready()
    with connect() as conn:
        rows = conn.execute("SELECT id, email, full_name, role, is_active, created_at FROM users ORDER BY id ASC").fetchall()
    return [dict(r) for r in rows]

# --- Community Reports Queries ---

def add_community_report(url: str, domain: str, threat_category: str, description: str, severity: str, evidence_notes: str, user_id=None, reporter_name="Anonymous"):
    ensure_db_ready()
    with connect() as conn:
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        cur = conn.execute("""
            INSERT INTO community_reports (
                user_id, reporter_name, url, domain, threat_category, description, severity, evidence_notes, upvotes, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'verified', ?)
        """, (user_id, reporter_name, url, domain, threat_category, description, severity, evidence_notes, now))
        conn.commit()
        return cur.lastrowid

def list_community_reports(limit=30):
    ensure_db_ready()
    with connect() as conn:
        rows = conn.execute("""
            SELECT * FROM community_reports ORDER BY upvotes DESC, id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]

def upvote_community_report(report_id: int):
    ensure_db_ready()
    with connect() as conn:
        conn.execute("UPDATE community_reports SET upvotes = upvotes + 1 WHERE id = ?", (report_id,))
        conn.commit()
        row = conn.execute("SELECT upvotes FROM community_reports WHERE id = ?", (report_id,)).fetchone()
    return row["upvotes"] if row else 0

# --- Domain Reputation Queries ---

def check_domain_reputation(domain: str):
    if not domain:
        return None
    ensure_db_ready()
    d = domain.lower().strip()
    with connect() as conn:
        row = conn.execute("SELECT * FROM domain_reputation WHERE domain = ?", (d,)).fetchone()
    return dict(row) if row else None

def add_audit_log(action: str, target: str = "", details: str = "", user_id: int = None, ip_address: str = ""):
    ensure_db_ready()
    with connect() as conn:
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("""
            INSERT INTO audit_logs (user_id, action, target, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, action, target, details, ip_address, now))
        conn.commit()

def get_recent_audit_logs(limit=25):
    ensure_db_ready()
    with connect() as conn:
        rows = conn.execute("""
            SELECT a.*, u.email as user_email, u.role as user_role
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY a.id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]

# Auto-initialize
try:
    ensure_db_ready()
except Exception:
    pass
