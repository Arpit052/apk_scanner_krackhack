from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_apk
import os
import asyncio
from datetime import datetime

app = FastAPI(
    title="APK Security Analyzer",
    description="High-performance APK security scanner - 300MB support",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 300 * 1024 * 1024  # 300MB
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
UPLOAD_DIR = "/tmp/apk_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.get("/")
async def read_index():
    return FileResponse('index.html')

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "max_file_size_mb": 300,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    temp_filename = None
    
    try:
        if not file.filename.endswith('.apk'):
            raise HTTPException(status_code=400, detail="Invalid file type")
        
        print(f"\n{'='*70}")
        print(f"📥 UPLOAD: {file.filename}")
        print(f"{'='*70}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        temp_filename = os.path.join(UPLOAD_DIR, f"apk_{timestamp}_{file.filename}")
        
        file_size = 0
        with open(temp_filename, "wb") as buffer:
            while chunk := await file.read(CHUNK_SIZE):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    buffer.close()
                    os.remove(temp_filename)
                    raise HTTPException(status_code=413, detail=f"File too large. Max 300MB")
                buffer.write(chunk)
        
        if file_size == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        
        size_mb = file_size / (1024 * 1024)
        print(f"✅ Upload: {size_mb:.2f} MB")
        print(f"🔍 Analyzing...")
        
        start_time = datetime.now()
        report = await asyncio.get_event_loop().run_in_executor(None, analyze_apk, temp_filename)
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        if "error" in report:
            raise HTTPException(status_code=500, detail=report["error"])
        
        report["scan_metadata"] = {
            "scan_time_seconds": round(analysis_time, 2),
            "file_size_mb": round(size_mb, 2),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
        
        print(f"✅ Complete: {analysis_time:.2f}s")
        print(f"📊 Found: {report['summary']['total']} vulnerabilities")
        print(f"🔴 Critical: {report['summary']['critical']}")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_filename and os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except:
                pass

@app.on_event("startup")
async def startup_event():
    print("\n" + "="*70)
    print("🚀 APK SECURITY ANALYZER")
    print("="*70)
    print(f"📁 Max: 300 MB")
    print(f"🔧 20 security checks enabled")
    print("="*70 + "\n")

@app.on_event("shutdown")
async def shutdown_event():
    print("\n🛑 Shutting down")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
