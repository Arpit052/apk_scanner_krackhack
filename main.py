from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from analyzer import analyze_apk, generate_report_text
import shutil
import os

app = FastAPI()

# Add CORS middleware (optional but recommended)
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

# 2. The API Endpoint to Handle Uploads
@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename.endswith('.apk'):
        return {"error": "Please upload a valid APK file"}
    
    # Save the uploaded file temporarily
    temp_filename = f"temp_{file.filename}"
    
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Run your analyzer script on the temp file
        print(f"Analyzing {file.filename}...")
        report = analyze_apk(temp_filename)
        
        # Check if there was an error during analysis
        if "error" in report:
            return {"error": report["error"]}
        
        return report
        
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
    
    finally:
        # Clean up: delete the file after analysis
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
            print(f"Cleaned up {temp_filename}")

# 3. Optional: Download report as text file
@app.post("/analyze/download")
async def analyze_and_download(file: UploadFile = File(...)):
    if not file.filename.endswith('.apk'):
        return {"error": "Please upload a valid APK file"}
    
    temp_filename = f"temp_{file.filename}"
    report_filename = f"{file.filename}_report.txt"
    
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Analyze
        report = analyze_apk(temp_filename)
        
        if "error" in report:
            return {"error": report["error"]}
        
        # Generate text report
        text_report = generate_report_text(report)
        
        # Save report to file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        return FileResponse(
            report_filename,
            media_type='text/plain',
            filename=report_filename
        )
        
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}
    
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
