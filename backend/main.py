import os
import concurrent.futures
from typing import Optional, List
from fastapi import FastAPI, APIRouter, HTTPException, Query, Depends, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from database import (
    init_db, ensure_db_ready, insert_scan, list_scans, get_scan, scan_stats,
    create_user, get_user_by_id, list_all_users,
    add_community_report, list_community_reports, upvote_community_report,
    check_domain_reputation, add_audit_log, get_recent_audit_logs, connect
)
from auth import (
    create_access_token, get_current_user, require_auth, require_role, authenticate_user
)
from detector import analyze_website
from brand_detector import check_brand_spoofing
from qr_scanner import decode_qr_image
from reports import make_report

app = FastAPI(
    title="ScamShield Enterprise Cyber Defense API",
    version="3.0.0",
    description="Multi-Engine AI / ML / DL Scam & Phishing Detection Platform."
)

# Enterprise CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Request / Response Pydantic Models ---

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=6, max_length=128)
    full_name: str = Field(min_length=2, max_length=100)

class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str

class DemoLoginRequest(BaseModel):
    role: str = Field(default="admin", pattern="^(admin|analyst|user)$")

class ScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

class BatchScanRequest(BaseModel):
    urls: List[str] = Field(min_length=1, max_length=50)

class BrandCheckRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

class CommunityReportRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    threat_category: str = Field(default="Fake E-Commerce")
    description: str = Field(default="")
    severity: str = Field(default="high")
    evidence_notes: str = Field(default="")

# Create router for all endpoints
router = APIRouter()

# --- Root & Telemetry Endpoints ---

@router.get("/")
def api_root():
    return {
        "name": "ScamShield Enterprise Cyber Defense API",
        "version": "3.0.0",
        "status": "operational",
        "engines": ["Rule Heuristics", "Scikit-Learn ML Ensemble", "Neural Inference Engine", "Quishing QR Shield", "Threat Cloud"],
        "docs": "/docs"
    }

@router.get("/health")
def health():
    ml_exists = os.path.exists(os.path.join(os.path.dirname(__file__), "model.joblib"))
    dl_exists = (
        os.path.exists(os.path.join(os.path.dirname(__file__), "dl_weights.joblib")) or
        os.path.exists(os.path.join(os.path.dirname(__file__), "dl_model.pt"))
    )
    safe_browsing = bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))
    return {
        "status": "ok",
        "database": "sqlite_cloud",
        "engines": {
            "ml_ensemble_available": ml_exists,
            "dl_neural_available": dl_exists,
            "threat_cloud_configured": True,
            "google_safe_browsing_configured": safe_browsing,
            "qr_scanner_ready": True
        }
    }

# --- Authentication Endpoints ---

@router.post("/auth/register")
def register(req: RegisterRequest):
    user_id = create_user(req.email, req.password, req.full_name, role="user")
    if not user_id:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    user = get_user_by_id(user_id)
    token = create_access_token(user["id"], user["email"], user["role"])
    add_audit_log("user_registered", user["email"], "Self-service registration", user_id=user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user
    }

@router.post("/auth/login")
def login(req: LoginRequest):
    user = authenticate_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_access_token(user["id"], user["email"], user["role"])
    add_audit_log("user_logged_in", user["email"], "JWT Session generated", user_id=user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "api_key": user["api_key"]
        }
    }

@router.post("/auth/demo-login")
def demo_login(req: DemoLoginRequest):
    role_emails = {
        "admin": "admin@scamshield.io",
        "analyst": "analyst@scamshield.io",
        "user": "user@scamshield.io"
    }
    email = role_emails.get(req.role, "admin@scamshield.io")
    from database import get_user_by_email
    user = get_user_by_email(email)
    if not user:
        pwd = "Admin@12345" if req.role == "admin" else "Analyst@12345" if req.role == "analyst" else "User@12345"
        uid = create_user(email, pwd, f"Demo {req.role.title()}", role=req.role)
        user = get_user_by_id(uid)

    token = create_access_token(user["id"], user["email"], user["role"])
    add_audit_log("demo_login", user["email"], f"1-Click role switch to {req.role}", user_id=user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "api_key": user.get("api_key", "")
        }
    }

@router.get("/auth/me")
def get_me(user: dict = Depends(require_auth)):
    return user

# --- Core Scan Endpoints ---

@router.post("/scan")
def scan_single(req: ScanRequest, user: Optional[dict] = Depends(get_current_user)):
    clean_url = req.url.strip()
    if not clean_url:
        raise HTTPException(status_code=400, detail="Please provide a valid website address.")
    try:
        result = analyze_website(clean_url)
        user_id = user["id"] if user else None
        scan_id = insert_scan(result, user_id=user_id)
        result["id"] = scan_id
        result["report_url"] = f"/api/reports/{scan_id}.pdf"
        
        add_audit_log(
            "url_scanned",
            result.get("domain", clean_url),
            f"Score: {result['score']}, Risk: {result['risk_tier']}",
            user_id=user_id
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(exc)}")

@router.post("/scan/batch")
def scan_batch(req: BatchScanRequest, user: Optional[dict] = Depends(get_current_user)):
    raw_urls = [u.strip() for u in req.urls if u.strip()][:50]
    if not raw_urls:
        raise HTTPException(status_code=400, detail="No valid URLs provided in batch request.")

    user_id = user["id"] if user else None
    results = []

    def _scan_one(url):
        try:
            res = analyze_website(url)
            sid = insert_scan(res, user_id=user_id)
            res["id"] = sid
            res["report_url"] = f"/api/reports/{sid}.pdf"
            return res
        except Exception as e:
            return {"url": url, "error": str(e), "score": 0, "classification": "Scan Failed", "risk_tier": "ERROR"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(_scan_one, raw_urls))

    total = len(results)
    flagged = sum(1 for r in results if r.get("score", 0) >= 35)
    high_risk = sum(1 for r in results if r.get("score", 0) >= 65)

    add_audit_log("batch_scan_executed", f"{total} URLs", f"Flagged: {flagged}", user_id=user_id)

    return {
        "total_scanned": total,
        "flagged_count": flagged,
        "high_risk_count": high_risk,
        "items": results
    }

@router.post("/scan/qr")
async def scan_qr_code(file: UploadFile = File(...), user: Optional[dict] = Depends(get_current_user)):
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty image file received.")
        
        qr_res = decode_qr_image(content)
        if not qr_res.get("success") or not qr_res.get("payload"):
            return {
                "success": False,
                "message": qr_res.get("details", "No readable QR code pattern detected in image."),
                "scan_result": None
            }

        extracted_url = qr_res["payload"]
        scan_res = analyze_website(extracted_url)
        user_id = user["id"] if user else None
        scan_id = insert_scan(scan_res, user_id=user_id)
        scan_res["id"] = scan_id
        scan_res["report_url"] = f"/api/reports/{scan_id}.pdf"

        add_audit_log("qr_scanned", scan_res.get("domain", extracted_url), f"Decoded URL: {extracted_url}", user_id=user_id)

        return {
            "success": True,
            "decoded_url": extracted_url,
            "qr_metadata": qr_res,
            "scan_result": scan_res
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"QR analysis error: {str(exc)}")

@router.post("/brand/check")
def check_brand(req: BrandCheckRequest):
    return check_brand_spoofing(req.url)

# --- History & Reports ---

@router.get("/scans")
def get_history(limit: int = Query(default=25, ge=1, le=100), user_only: bool = False, user: Optional[dict] = Depends(get_current_user)):
    uid = user["id"] if (user_only and user) else None
    items = list_scans(limit=limit, user_id=uid)
    return {"items": items}

@router.get("/scans/{scan_id}")
def get_scan_details(scan_id: int):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@router.get("/reports/{scan_id}.pdf")
def download_pdf_report(scan_id: int):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan report record not found.")
    pdf_bytes = make_report(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ScamShield-Audit-Report-{scan_id}.pdf"}
    )

# --- Community Intelligence ---

@router.get("/threats/community")
def get_community_threats(limit: int = Query(default=30, ge=1, le=100)):
    return {"items": list_community_reports(limit=limit)}

@router.post("/threats/report")
def submit_community_report(req: CommunityReportRequest, user: Optional[dict] = Depends(get_current_user)):
    user_id = user["id"] if user else None
    name = user["full_name"] if user else "Anonymous User"
    from urllib.parse import urlparse
    parsed = urlparse(req.url)
    domain = parsed.hostname or req.url
    
    rep_id = add_community_report(
        url=req.url,
        domain=domain,
        threat_category=req.threat_category,
        description=req.description,
        severity=req.severity,
        evidence_notes=req.evidence_notes,
        user_id=user_id,
        reporter_name=name
    )
    add_audit_log("community_scam_reported", domain, req.threat_category, user_id=user_id)
    return {"success": True, "report_id": rep_id, "message": "Scam report successfully submitted and verified."}

@router.post("/threats/{report_id}/vote")
def vote_community_report(report_id: int):
    upvotes = upvote_community_report(report_id)
    return {"success": True, "upvotes": upvotes}

# --- SOC Admin & Analytics ---

@router.get("/stats")
def stats():
    return scan_stats()

@router.get("/admin/overview")
def admin_overview(user: Optional[dict] = Depends(get_current_user)):
    return scan_stats()

@router.get("/admin/audit-logs")
def admin_audit_logs(limit: int = Query(default=30, ge=1, le=100)):
    return {"logs": get_recent_audit_logs(limit=limit)}

@router.get("/admin/users")
def admin_users(user: dict = Depends(require_role(["admin"]))):
    return {"users": list_all_users()}

# Mount router on BOTH prefix "/api" AND root ""
app.include_router(router, prefix="/api")
app.include_router(router)
