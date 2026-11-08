"""
TRUSTX AI - FastAPI Backend Application
Main application entry point with all API endpoints.
"""

import os
import sys
import json
import re
import time
import logging
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager
from collections import defaultdict

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# Add model and services directories to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(os.path.dirname(BASE_DIR), 'model')
if MODEL_DIR not in sys.path:
    sys.path.insert(0, MODEL_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from shap_explainer import ShapExplainer
from services.investigation_agent import investigate_url
from services.qr_scanner import decode_qr_image_bytes
from services.threat_graph import generate_threat_graph
from services.threat_intel import query_urlhaus, query_community_threat_intel

# ===================== Logging =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('trustx.log', mode='a'),
    ]
)
logger = logging.getLogger('trustx-api')

# ===================== Database =====================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trustx.db')


def init_db():
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            url_hash TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            phishing_probability REAL NOT NULL,
            safe_probability REAL NOT NULL,
            shap_top_features TEXT,
            features TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reported_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            url_hash TEXT UNIQUE NOT NULL,
            report_type TEXT NOT NULL,
            description TEXT,
            reporter_ip TEXT,
            reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigation_reports (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            trust_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS community_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_hash TEXT NOT NULL,
            vote_type TEXT NOT NULL,
            voter_ip TEXT,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(url_hash, voter_ip)
        )
    ''')
    
    # Insert default whitelisted domains
    trusted_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
        'linkedin.com', 'twitter.com', 'youtube.com', 'reddit.com',
        'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
        'trustx.ai', 'onrender.com', 'render.com', 'vercel.app',
        'trustx-frontend-uiij.onrender.com', 'trustx-api.onrender.com',
        'localhost', '127.0.0.1',
    ]
    
    for domain in trusted_domains:
        try:
            cursor.execute(
                'INSERT OR IGNORE INTO whitelist (domain) VALUES (?)',
                (domain,)
            )
        except sqlite3.IntegrityError:
            pass
    
    # Insert known phishing domains
    known_phishing = [
        'phishing-example.tk', 'login-verify.ml', 'account-update.ga',
        'secure-banking.cf', 'credential-confirm.gq',
    ]
    
    for domain in known_phishing:
        try:
            cursor.execute(
                'INSERT OR IGNORE INTO blacklist (domain, reason) VALUES (?, ?)',
                (domain, 'Known phishing domain')
            )
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ===================== Rate Limiter =====================
class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_ip: str) -> bool:
        """Check if a request from the given IP is allowed."""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > window_start
        ]
        
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        
        self.requests[client_ip].append(now)
        return True
    
    def get_remaining(self, client_ip: str) -> int:
        """Get remaining requests for the client."""
        now = time.time()
        window_start = now - self.window_seconds
        self.requests[client_ip] = [
            t for t in self.requests[client_ip] if t > window_start
        ]
        return max(0, self.max_requests - len(self.requests[client_ip]))


rate_limiter = RateLimiter(max_requests=30, window_seconds=60)

# ===================== Models =====================
explainer: Optional[ShapExplainer] = None


# ===================== App Lifespan =====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global explainer
    
    # Startup
    logger.info("Starting TRUSTX AI Backend...")
    init_db()
    
    try:
        explainer = ShapExplainer()
        logger.info("ML Model loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        logger.warning("API will run without ML model. Train the model first.")
    
    yield
    
    # Shutdown
    logger.info("Shutting down TRUSTX AI Backend...")


# ===================== FastAPI App =====================
app = FastAPI(
    title="TRUSTX AI API",
    description="Intelligent Web Security & Collaborative Threat Intelligence Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for model visualizations/plots
# NOTE: mount must use a different prefix than /plots/list route to avoid conflicts
PLOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'docs', 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)
app.mount("/static/plots", StaticFiles(directory=PLOTS_DIR), name="plots")


# ===================== Request/Response Models =====================
class URLInput(BaseModel):
    """Input model for URL prediction."""
    url: str = Field(..., min_length=3, max_length=2048, description="URL to analyze")
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate and sanitize the URL."""
        v = v.strip()
        # Basic URL pattern check
        if not re.match(r'^https?://|^[a-zA-Z0-9]', v):
            raise ValueError('Invalid URL format')
        # Prevent XSS attempts
        dangerous_patterns = ['<script', 'javascript:', 'data:', 'vbscript:']
        for pattern in dangerous_patterns:
            if pattern.lower() in v.lower():
                raise ValueError('URL contains potentially dangerous content')
        return v


class PredictionResponse(BaseModel):
    """Response model for predictions."""
    url: str
    prediction: str
    is_phishing: bool
    confidence: float
    phishing_probability: float
    safe_probability: float
    risk_level: str
    shap_explanation: dict
    scan_id: Optional[int] = None
    source: Optional[str] = None


class ReportInput(BaseModel):
    """Input model for reporting URLs."""
    url: str = Field(..., min_length=3, max_length=2048)
    report_type: str = Field(..., description="Type: 'phishing' or 'false_positive'")
    description: Optional[str] = Field(None, max_length=500)


class HistoryResponse(BaseModel):
    """Response model for scan history."""
    id: int
    url: str
    prediction: str
    confidence: float
    risk_level: str
    phishing_probability: float
    scanned_at: str


# ===================== Middleware =====================
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to all requests."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Skip rate limiting for docs
    if request.url.path in ['/docs', '/redoc', '/openapi.json', '/']:
        return await call_next(request)
    
    if not rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded. Please try again later.",
                "retry_after": 60,
            }
        )
    
    response = await call_next(request)
    
    # Add rate limit headers
    remaining = rate_limiter.get_remaining(client_ip)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Limit"] = str(rate_limiter.max_requests)
    
    return response


# ===================== API Endpoints =====================
@app.get("/", tags=["Health"])
async def root():
    """Health check endpoint."""
    return {
        "name": "TRUSTX AI API",
        "version": "2.0.0",
        "status": "running",
        "model_loaded": explainer is not None,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check."""
    return {
        "status": "healthy",
        "model_loaded": explainer is not None,
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/predict", response_model=PredictionResponse, tags=["Prediction"])
async def predict_url(input_data: URLInput, request: Request):
    """
    Analyze a URL for phishing detection.
    
    Returns prediction, confidence score, risk level, and SHAP explanation.
    """
    url = input_data.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    logger.info(f"Prediction request for URL: {url} from {client_ip}")
    
    domain = _extract_domain(url)

    # 1. Absolute Priority: Official TRUSTX Platform & Enterprise Infrastructure Whitelist
    if is_official_trusted_domain(domain):
        return PredictionResponse(
            url=url,
            prediction='safe',
            is_phishing=False,
            confidence=99.9,
            phishing_probability=0.1,
            safe_probability=99.9,
            risk_level='safe',
            shap_explanation={
                'method': 'official_whitelist',
                'top_features': [{
                    'feature': 'official_trusted_domain',
                    'description': 'Verified Official TRUSTX AI Platform & Certified Trusted Infrastructure',
                    'shap_value': -1.0,
                    'feature_value': 1,
                    'impact': 'decreases_phishing',
                    'abs_impact': 1.0,
                }],
                'all_features': [],
            },
            source='whitelist',
        )

    # Check blacklist first
    conn = get_db()
    
    blacklisted = conn.execute(
        'SELECT * FROM blacklist WHERE ? LIKE "%" || domain', (domain,)
    ).fetchone()
    
    if blacklisted:
        conn.close()
        result = {
            'url': url,
            'prediction': 'phishing',
            'is_phishing': True,
            'confidence': 99.0,
            'phishing_probability': 99.0,
            'safe_probability': 1.0,
            'risk_level': 'critical',
            'shap_explanation': {
                'method': 'blacklist',
                'top_features': [{'feature': 'blacklisted_domain', 'description': 'Domain is blacklisted', 'shap_value': 1.0, 'impact': 'increases_phishing', 'abs_impact': 1.0}],
                'all_features': [],
            },
            'source': 'blacklist',
        }
        return PredictionResponse(**result)
    
    # Check whitelist
    whitelisted = conn.execute(
        'SELECT * FROM whitelist WHERE ? LIKE "%" || domain', (domain,)
    ).fetchone()
    
    if whitelisted:
        conn.close()
        result = {
            'url': url,
            'prediction': 'safe',
            'is_phishing': False,
            'confidence': 95.0,
            'phishing_probability': 5.0,
            'safe_probability': 95.0,
            'risk_level': 'safe',
            'shap_explanation': {
                'method': 'whitelist',
                'top_features': [{'feature': 'whitelisted_domain', 'description': 'Domain is trusted/whitelisted', 'shap_value': -1.0, 'impact': 'decreases_phishing', 'abs_impact': 1.0}],
                'all_features': [],
            },
            'source': 'whitelist',
        }
        return PredictionResponse(**result)
    
    conn.close()
    
    # ML model prediction
    if explainer is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Please train the model first."
        )
    
    try:
        result = explainer.predict(url)
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")
    
    # Store in history
    try:
        conn = get_db()
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        shap_top = json.dumps(result['shap_explanation'].get('top_features', [])[:5])
        features_json = json.dumps(result.get('features', {}))
        
        cursor = conn.execute(
            '''INSERT INTO scan_history 
               (url, url_hash, prediction, confidence, risk_level, 
                phishing_probability, safe_probability, shap_top_features, 
                features, ip_address, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (url, url_hash, result['prediction'], result['confidence'],
             result['risk_level'], result['phishing_probability'],
             result['safe_probability'], shap_top, features_json,
             client_ip, user_agent)
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        result['scan_id'] = scan_id
    except Exception as e:
        logger.error(f"Database error: {e}")
    
    # Remove raw features from response (too large)
    result.pop('features', None)
    result['source'] = 'model'
    
    return PredictionResponse(**result)


@app.get("/history", tags=["History"])
async def get_history(
    limit: int = 50,
    offset: int = 0,
    risk_level: Optional[str] = None,
    prediction: Optional[str] = None,
):
    """
    Get scan history with optional filtering.
    
    Parameters:
    - limit: Number of records to return (max 100)
    - offset: Offset for pagination
    - risk_level: Filter by risk level (safe, low, medium, high, critical)
    - prediction: Filter by prediction (safe, phishing)
    """
    limit = min(limit, 100)
    
    conn = get_db()
    
    query = 'SELECT * FROM scan_history WHERE 1=1'
    params = []
    
    if risk_level:
        query += ' AND risk_level = ?'
        params.append(risk_level)
    
    if prediction:
        query += ' AND prediction = ?'
        params.append(prediction)
    
    query += ' ORDER BY scanned_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    
    rows = conn.execute(query, params).fetchall()
    
    # Get total count
    count_query = 'SELECT COUNT(*) FROM scan_history WHERE 1=1'
    count_params = []
    if risk_level:
        count_query += ' AND risk_level = ?'
        count_params.append(risk_level)
    if prediction:
        count_query += ' AND prediction = ?'
        count_params.append(prediction)
    
    total = conn.execute(count_query, count_params).fetchone()[0]
    
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            'id': row['id'],
            'url': row['url'],
            'prediction': row['prediction'],
            'confidence': row['confidence'],
            'risk_level': row['risk_level'],
            'phishing_probability': row['phishing_probability'],
            'safe_probability': row['safe_probability'],
            'shap_top_features': json.loads(row['shap_top_features']) if row['shap_top_features'] else [],
            'scanned_at': row['scanned_at'],
        })
    
    return {
        'total': total,
        'limit': limit,
        'offset': offset,
        'history': history,
    }


@app.post("/report", tags=["Report"])
async def report_url(report: ReportInput, request: Request):
    """
    Report a URL as phishing or false positive.
    """
    client_ip = request.client.host if request.client else "unknown"
    url_hash = hashlib.md5(report.url.encode()).hexdigest()
    
    conn = get_db()
    
    try:
        conn.execute(
            '''INSERT OR REPLACE INTO reported_urls 
               (url, url_hash, report_type, description, reporter_ip)
               VALUES (?, ?, ?, ?, ?)''',
            (report.url, url_hash, report.report_type,
             report.description, client_ip)
        )
        conn.commit()
        
        logger.info(f"URL reported: {report.url} as {report.report_type}")
        
        return {
            "status": "success",
            "message": f"URL reported as {report.report_type}. Thank you for your contribution.",
            "url": report.url,
        }
    except Exception as e:
        logger.error(f"Report error: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit report")
    finally:
        conn.close()


@app.get("/stats", tags=["Analytics"])
async def get_stats():
    """
    Get aggregated statistics for the dashboard.
    """
    conn = get_db()
    
    # Total scans
    total_scans = conn.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
    
    # Predictions breakdown
    predictions = conn.execute(
        'SELECT prediction, COUNT(*) as count FROM scan_history GROUP BY prediction'
    ).fetchall()
    prediction_counts = {row['prediction']: row['count'] for row in predictions}
    
    # Risk level breakdown
    risk_levels = conn.execute(
        'SELECT risk_level, COUNT(*) as count FROM scan_history GROUP BY risk_level'
    ).fetchall()
    risk_counts = {row['risk_level']: row['count'] for row in risk_levels}
    
    # Recent scan trend (last 7 days)
    seven_days_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    daily_scans = conn.execute(
        '''SELECT DATE(scanned_at) as date, COUNT(*) as count,
           SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) as phishing_count
           FROM scan_history 
           WHERE scanned_at >= ? 
           GROUP BY DATE(scanned_at)
           ORDER BY date''',
        (seven_days_ago,)
    ).fetchall()
    
    trend = [
        {'date': row['date'], 'total': row['count'], 'phishing': row['phishing_count']}
        for row in daily_scans
    ]
    
    # Average confidence
    avg_confidence = conn.execute(
        'SELECT AVG(confidence) FROM scan_history'
    ).fetchone()[0] or 0
    
    # Top reported URLs
    top_reported = conn.execute(
        '''SELECT url, report_type, COUNT(*) as count 
           FROM reported_urls GROUP BY url ORDER BY count DESC LIMIT 5'''
    ).fetchall()
    
    conn.close()
    
    # Load model metadata if available
    model_metadata = {}
    meta_path = os.path.join(MODEL_DIR, 'saved_models', 'model_metadata.json')
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            model_metadata = json.load(f)
    
    return {
        'total_scans': total_scans,
        'predictions': prediction_counts,
        'risk_levels': risk_counts,
        'daily_trend': trend,
        'avg_confidence': round(avg_confidence, 2),
        'top_reported': [
            {'url': r['url'], 'type': r['report_type'], 'count': r['count']}
            for r in top_reported
        ],
        'model_info': model_metadata,
    }


@app.get("/model-info", tags=["Model"])
async def get_model_info():
    """Get information about the loaded ML model."""
    meta_path = os.path.join(MODEL_DIR, 'saved_models', 'model_metadata.json')
    
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
        return metadata
    
    return {"message": "No model metadata available. Train the model first."}


@app.get("/plots/list", tags=["Model"])
async def list_plots():
    """
    List all available training visualization plots.
    Returns filenames that can be fetched from /plots/{filename}
    """
    plots_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'docs', 'plots'
    )
    if not os.path.exists(plots_path):
        return {"plots": []}
    
    plot_files = [
        f for f in os.listdir(plots_path)
        if f.endswith(('.png', '.jpg', '.svg'))
    ]
    
    return {
        "plots": sorted(plot_files),
        "base_url": "/static/plots",
    }


@app.get("/blacklist", tags=["Security"])
async def get_blacklist(limit: int = 100):
    """
    Get the list of blacklisted phishing domains.
    """
    conn = get_db()
    rows = conn.execute(
        'SELECT id, domain, reason, added_at FROM blacklist ORDER BY added_at DESC LIMIT ?',
        (min(limit, 500),)
    ).fetchall()
    conn.close()
    return {
        'count': len(rows),
        'blacklist': [
            {'id': r['id'], 'domain': r['domain'], 'reason': r['reason'], 'added_at': r['added_at']}
            for r in rows
        ]
    }


@app.post("/blacklist", tags=["Security"])
async def add_to_blacklist(domain: str, reason: str = "Manually added"):
    """
    Add a domain to the blacklist.
    """
    conn = get_db()
    try:
        conn.execute(
            'INSERT OR IGNORE INTO blacklist (domain, reason) VALUES (?, ?)',
            (domain.lower().strip(), reason)
        )
        conn.commit()
        return {"status": "success", "message": f"Domain '{domain}' added to blacklist."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@app.get("/whitelist", tags=["Security"])
async def get_whitelist(limit: int = 100):
    """
    Get the list of trusted/whitelisted domains.
    """
    conn = get_db()
    rows = conn.execute(
        'SELECT id, domain, added_at FROM whitelist ORDER BY domain ASC LIMIT ?',
        (min(limit, 500),)
    ).fetchall()
    conn.close()
    return {
        'count': len(rows),
        'whitelist': [
            {'id': r['id'], 'domain': r['domain'], 'added_at': r['added_at']}
            for r in rows
        ]
    }


@app.post("/whitelist", tags=["Security"])
async def add_to_whitelist(domain: str):
    """
    Add a domain to the trusted whitelist.
    """
    conn = get_db()
    try:
        conn.execute(
            'INSERT OR IGNORE INTO whitelist (domain) VALUES (?)',
            (domain.lower().strip(),)
        )
        conn.commit()
        return {"status": "success", "message": f"Domain '{domain}' added to whitelist."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ===================== TRUSTX AI Investigation Endpoints =====================
@app.post("/investigate", tags=["Investigation"])
async def run_investigation(input_data: URLInput, request: Request):
    """
    Run the complete TRUSTX AI 10-step investigation workflow.
    Correlates ML phishing detection, domain & DNS intelligence,
    SSL/TLS certificate validation, security headers, redirects,
    and threat intelligence into a unified 0-100 Trust Score.
    """
    client_ip = request.client.host if request.client else "unknown"
    url = input_data.url
    
    try:
        report = investigate_url(url, client_ip=client_ip)
        
        # Save to investigation_reports table
        conn = get_db()
        conn.execute(
            '''INSERT OR REPLACE INTO investigation_reports 
               (id, url, domain, trust_score, risk_level, report_json)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (report['investigation_id'], report['target_url'], report['domain'],
             report['trust_score'], report['risk_level'], json.dumps(report))
        )
        conn.commit()
        conn.close()
        
        return report
    except Exception as e:
        logger.error(f"Investigation error for {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@app.get("/investigation/{investigation_id}", tags=["Investigation"])
async def get_investigation_report(investigation_id: str):
    """
    Retrieve a previously generated investigation report by ID.
    """
    conn = get_db()
    row = conn.execute(
        'SELECT report_json FROM investigation_reports WHERE id = ?',
        (investigation_id,)
    ).fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Investigation report not found")
        
    return json.loads(row['report_json'])


@app.post("/qr/scan", tags=["QR Code"])
async def scan_qr_code(request: Request, file: UploadFile = File(...)):
    """
    Upload and decode a QR code image to inspect for phishing,
    trace destination redirects, and trigger an automated investigation.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        contents = await file.read()
        qr_data = decode_qr_image_bytes(contents)
        
        if not qr_data["success"]:
            return {
                "success": False,
                "error": qr_data["error"] or "Could not decode QR code.",
                "qr_data": qr_data
            }
            
        investigation = None
        target_url = qr_data.get("final_destination") or qr_data.get("extracted_url")
        if qr_data["is_url"] and target_url:
            investigation = investigate_url(target_url, client_ip=client_ip)
            
        return {
            "success": True,
            "qr_data": qr_data,
            "investigation": investigation
        }
    except Exception as e:
        logger.error(f"QR Scan error: {e}")
        raise HTTPException(status_code=500, detail=f"QR scan failed: {str(e)}")


@app.get("/threat-intel/graph/{domain}", tags=["Threat Intelligence"])
async def get_threat_graph_endpoint(domain: str):
    """
    Generate the interactive Threat Relationship Graph for a given domain,
    connecting shared infrastructure (IPs, NS, MX, Certificate Issuers, and historical scans).
    """
    try:
        graph = generate_threat_graph(domain)
        return graph
    except Exception as e:
        logger.error(f"Threat graph generation error for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-intel/summary", tags=["Threat Intelligence"])
async def get_threat_intel_summary():
    """
    Get aggregated threat intelligence metrics across community reports and URLhaus.
    """
    conn = get_db()
    total_reports = conn.execute('SELECT COUNT(*) FROM reported_urls').fetchone()[0]
    phishing_reports = conn.execute("SELECT COUNT(*) FROM reported_urls WHERE report_type = 'phishing'").fetchone()[0]
    fp_reports = conn.execute("SELECT COUNT(*) FROM reported_urls WHERE report_type = 'false_positive'").fetchone()[0]
    
    recent_reports = conn.execute(
        '''SELECT id, url, report_type, description, reported_at, status 
           FROM reported_urls ORDER BY reported_at DESC LIMIT 15'''
    ).fetchall()
    conn.close()
    
    return {
        "total_threat_reports": total_reports,
        "phishing_reports": phishing_reports,
        "false_positive_reports": fp_reports,
        "recent_reports": [
            {
                "id": r['id'],
                "url": r['url'],
                "type": r['report_type'],
                "description": r['description'],
                "reported_at": r['reported_at'],
                "status": r['status']
            }
            for r in recent_reports
        ]
    }


class VoteInput(BaseModel):
    url_hash: str
    vote_type: str


@app.post("/community/vote", tags=["Community"])
async def vote_threat_report(vote: VoteInput, request: Request):
    """
    Upvote or downvote a reported threat to build community consensus.
    """
    client_ip = request.client.host if request.client else "unknown"
    conn = get_db()
    try:
        conn.execute(
            '''INSERT OR REPLACE INTO community_votes (url_hash, vote_type, voter_ip)
               VALUES (?, ?, ?)''',
            (vote.url_hash, vote.vote_type, client_ip)
        )
        conn.commit()
        return {"status": "success", "message": f"Recorded {vote.vote_type} for report."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


# ===================== Helper Functions =====================
OFFICIAL_TRUSTED_DOMAINS = {
    'trustx.ai',
    'onrender.com',
    'render.com',
    'vercel.app',
    'trustx-frontend-uiij.onrender.com',
    'trustx-api.onrender.com',
    'localhost',
    '127.0.0.1',
    'github.com',
    'google.com',
    'microsoft.com',
    'apple.com',
}


def is_official_trusted_domain(domain: str) -> bool:
    """Check if domain is an immutable official platform or enterprise trusted domain."""
    if not domain:
        return False
    d = domain.lower().strip()
    if ':' in d:
        d = d.split(':')[0]
    for trusted in OFFICIAL_TRUSTED_DOMAINS:
        if d == trusted or d.endswith('.' + trusted):
            return True
    return False


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    import urllib.parse
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    if ':' in domain:
        domain = domain.split(':')[0]
    return domain.lower().strip()


# ===================== Run Server =====================
if __name__ == '__main__':
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
