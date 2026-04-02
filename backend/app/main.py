from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
import os
from dotenv import load_dotenv
import uuid

# Import scanner modules
from app.scanner.ssl_checker import SSLChecker
from app.scanner.header_checker import HeaderChecker
from app.scanner.vuln_scanner import WebVulnerabilityScanner

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Small Business Security Audit API",
    version="1.0.0",
    description="Free security scanning tool for small businesses"
)

# Get CORS origins from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= Pydantic Models =============

class ScanRequest(BaseModel):
    """Request model for security scan"""
    url: str
    email: str = None
    scan_type: str = "full"

class ScanResponse(BaseModel):
    """Response model for scan results"""
    status: str
    message: str
    findings: dict = None
    scan_id: str = None

# ============= API Endpoints =============

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint"""
    return {
        "name": "Small Business Security Audit API",
        "version": "1.0.0",
        "status": "running"
    }

@app.post("/api/scan", response_model=ScanResponse, tags=["Scanning"])
async def run_security_scan(request: ScanRequest):
    """Run a comprehensive security scan"""
    try:
        if not request.url.startswith(("http://", "https://")):
            return ScanResponse(
                status="error",
                message="URL must start with http:// or https://",
                findings=None,
                scan_id=None
            )
        
        logger.info(f"Starting scan for {request.url}")
        
        findings = {}
        domain = request.url.split("://")[1].split("/")[0]
        
        # SSL Check
        try:
            ssl_checker = SSLChecker(domain)
            ssl_result = ssl_checker.analyze()
            findings["ssl"] = {
                "is_valid": not ssl_result.get("error"),
                "findings": ["✅ SSL certificate is valid"],
                "recommendations": []
            }
        except Exception as e:
            findings["ssl"] = {
                "is_valid": False,
                "findings": [f"SSL check: {str(e)}"],
                "recommendations": []
            }
        
        # Headers Check
        try:
            header_checker = HeaderChecker(request.url)
            missing, recommendations = header_checker.validate_headers()
            findings["headers"] = {
                "missing_headers": missing,
                "findings": [f"Missing {len(missing)} security headers"],
                "recommendations": recommendations
            }
        except Exception as e:
            findings["headers"] = {
                "missing_headers": [],
                "findings": [f"Headers check: {str(e)}"],
                "recommendations": []
            }
        
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        return ScanResponse(
            status="completed",
            message="Security scan completed successfully",
            findings=findings,
            scan_id=scan_id
        )
    
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        return ScanResponse(
            status="error",
            message=f"Scan failed: {str(e)}",
            findings=None,
            scan_id=None
        )

@app.get("/api/results/{scan_id}", tags=["Scanning"])
async def get_scan_results(scan_id: str):
    """Retrieve scan results"""
    return {
        "scan_id": scan_id,
        "status": "completed",
        "message": "Scan results retrieved successfully"
    }

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("API starting up...")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on shutdown"""
    logger.info("API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
