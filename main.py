from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_apk
import shutil
import os

app = FastAPI()

# Add CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Serve the HTML Frontend
@app.get("/")
async def read_index():
    return FileResponse('index.html')

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "APK Security Analyzer"}

# 2. The API Endpoint to Handle Uploads
@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    temp_filename = None
    
    try:
        # Validate file extension
        if not file.filename.endswith('.apk'):
            raise HTTPException(status_code=400, detail="Please upload a valid APK file")
        
        # Check file size (limit to 50MB for free tier)
        file.file.seek(0, 2)  # Seek to end
        file_size = file.file.tell()
        file.file.seek(0)  # Seek back to start
        
        if file_size > 50 * 1024 * 1024:  # 50MB
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 50MB")
        
        if file_size == 0:
            raise HTTPException(status_code=400, detail="File is empty")
        
        print(f"📥 Received APK: {file.filename} ({file_size / 1024 / 1024:.2f} MB)")
        
        # Save the uploaded file temporarily
        temp_filename = f"temp_{file.filename}"
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        print(f"💾 Saved to: {temp_filename}")
        print(f"🔍 Starting analysis...")
        
        # Run analyzer
        report = analyze_apk(temp_filename)
        
        # Check if analysis returned an error
        if "error" in report:
            print(f"❌ Analysis error: {report['error']}")
            raise HTTPException(status_code=500, detail=report["error"])
        
        print(f"✅ Analysis complete! Found {len(report.get('vulnerabilities', []))} vulnerabilities")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        print(f"❌ ERROR: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    
    finally:
        # Clean up: delete the file after analysis
        if temp_filename and os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
                print(f"🗑️ Cleaned up {temp_filename}")
            except Exception as e:
                print(f"⚠️ Failed to cleanup {temp_filename}: {str(e)}")

# Error handler for all exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": f"Server error: {str(exc)}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
