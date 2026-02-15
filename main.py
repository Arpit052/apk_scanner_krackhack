from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_apk
import shutil
import os
import asyncio
from datetime import datetime

app = FastAPI(
    title="APK Security Analyzer",
    description="High-performance APK security scanner supporting files up to 300MB",
    version="2.0"
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# PERFORMANCE OPTIMIZATIONS
# ============================================================================

# 1. Increase max file size to 300MB (from 50MB)
MAX_FILE_SIZE = 300 * 1024 * 1024  # 300MB in bytes

# 2. Streaming upload for large files (prevents memory overflow)
CHUNK_SIZE = 1024 * 1024  # 1MB chunks

# 3. Temporary directory for uploads (faster than default /tmp on some systems)
UPLOAD_DIR = "/tmp/apk_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
async def read_index():
    """Serve the HTML frontend"""
    return FileResponse('index.html')


@app.get("/health")
async def health_check():
    """Health check endpoint with system info"""
    return {
        "status": "ok",
        "service": "APK Security Analyzer",
        "version": "2.0",
        "max_file_size_mb": MAX_FILE_SIZE / (1024 * 1024),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    """
    Main APK analysis endpoint - optimized for large files
    
    Features:
    - Supports APK files up to 300MB
    - Streaming upload for memory efficiency
    - Fast parallel analysis (12 concurrent checks)
    - Comprehensive security scanning
    """
    temp_filename = None
    
    try:
        # ========================================
        # STEP 1: VALIDATION (Fast pre-checks)
        # ========================================
        
        # Check file extension
        if not file.filename.endswith('.apk'):
            raise HTTPException(
                status_code=400, 
                detail="Invalid file type. Please upload an APK file (.apk extension required)"
            )
        
        print(f"\n{'='*70}")
        print(f"📥 NEW UPLOAD: {file.filename}")
        print(f"{'='*70}")
        
        # ========================================
        # STEP 2: STREAMING UPLOAD (Memory efficient)
        # ========================================
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = os.path.join(UPLOAD_DIR, f"apk_{timestamp}_{file.filename}")
        
        file_size = 0
        
        # Stream file to disk in chunks (prevents memory overflow for large files)
        with open(temp_filename, "wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                file_size += len(chunk)
                
                # Real-time size validation
                if file_size > MAX_FILE_SIZE:
                    # Clean up immediately
                    buffer.close()
                    os.remove(temp_filename)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024):.0f}MB. Your file: {file_size / (1024*1024):.1f}MB"
                    )
                
                buffer.write(chunk)
        
        # Check for empty files
        if file_size == 0:
            raise HTTPException(status_code=400, detail="File is empty")
        
        size_mb = file_size / (1024 * 1024)
        print(f"✅ Upload complete: {size_mb:.2f} MB")
        
        # ========================================
        # STEP 3: PERFORMANCE-OPTIMIZED ANALYSIS
        # ========================================
        
        print(f"🔍 Starting analysis...")
        start_time = datetime.now()
        
        # Run analysis in executor to prevent blocking
        # This allows FastAPI to handle other requests while analyzing
        report = await asyncio.get_event_loop().run_in_executor(
            None,  # Uses default thread pool
            analyze_apk,
            temp_filename
        )
        
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        # Check for analysis errors
        if "error" in report:
            print(f"❌ Analysis error: {report['error']}")
            raise HTTPException(status_code=500, detail=report["error"])
        
        # ========================================
        # STEP 4: RESULT ENRICHMENT
        # ========================================
        
        # Add performance metrics
        report["scan_metadata"] = {
            "scan_time_seconds": round(analysis_time, 2),
            "file_size_mb": round(size_mb, 2),
            "scan_speed_mb_per_sec": round(size_mb / analysis_time, 2) if analysis_time > 0 else 0,
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        # Performance summary
        print(f"✅ Analysis complete!")
        print(f"   ⏱️  Time: {analysis_time:.2f}s")
        print(f"   📊 Speed: {size_mb/analysis_time:.2f} MB/s")
        print(f"   🔍 Found: {report['summary']['total']} vulnerabilities")
        print(f"   🔴 Critical: {report['summary']['critical']}")
        print(f"   🟠 High: {report['summary']['high']}")
        print(f"   🟡 Medium: {report['summary']['medium']}")
        print(f"   🟢 Low: {report['summary']['low']}")
        
        if report.get('malware_detected'):
            print(f"   ⚠️  MALWARE: {report['malware_confidence']} confidence")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        print(f"❌ ERROR: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    
    finally:
        # ========================================
        # STEP 5: CLEANUP (Always executed)
        # ========================================
        if temp_filename and os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
                print(f"🗑️  Cleaned up: {os.path.basename(temp_filename)}")
            except Exception as e:
                print(f"⚠️  Cleanup warning: {str(e)}")


# ============================================================================
# BACKGROUND TASKS (Optional - for production)
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    print("\n" + "="*70)
    print("🚀 APK SECURITY ANALYZER - STARTING")
    print("="*70)
    print(f"📁 Max file size: {MAX_FILE_SIZE / (1024*1024):.0f} MB")
    print(f"⚡ Chunk size: {CHUNK_SIZE / (1024*1024):.0f} MB")
    print(f"💾 Upload directory: {UPLOAD_DIR}")
    print(f"🔧 12 parallel security checks enabled")
    print("="*70 + "\n")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("\n🛑 Shutting down APK Security Analyzer")
    
    # Clean up any remaining temp files
    try:
        for filename in os.listdir(UPLOAD_DIR):
            file_path = os.path.join(UPLOAD_DIR, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"🗑️  Cleaned up: {filename}")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global error handler"""
    error_msg = str(exc)
    print(f"❌ Global error: {error_msg}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": f"Server error: {error_msg}",
            "detail": "If this persists, please check the APK file integrity"
        }
    )


@app.exception_handler(413)
async def file_too_large_handler(request, exc):
    """Handle file too large errors"""
    return JSONResponse(
        status_code=413,
        content={
            "error": "File too large",
            "detail": f"Maximum allowed size is {MAX_FILE_SIZE / (1024*1024):.0f}MB",
            "tip": "Try analyzing a smaller APK or split large apps into modules"
        }
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*70)
    print("🚀 LAUNCHING APK SECURITY ANALYZER")
    print("="*70)
    print("📊 Configuration:")
    print(f"   • Max file size: {MAX_FILE_SIZE / (1024*1024):.0f} MB")
    print(f"   • Streaming chunks: {CHUNK_SIZE / (1024*1024):.0f} MB")
    print(f"   • Analysis: 12 parallel checks")
    print(f"   • Performance: Optimized for 5-15 second scans")
    print("="*70 + "\n")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        # Performance tuning
        workers=1,  # Single worker for consistent analysis
        limit_concurrency=10,  # Max 10 concurrent uploads
        timeout_keep_alive=300,  # 5 min timeout for large files
    )
