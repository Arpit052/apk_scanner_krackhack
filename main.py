from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from analyzer import analyze_apk
import shutil
import os

app = FastAPI()

# 1. Serve the HTML Frontend
@app.get("/")
async def read_index():
    return FileResponse('index.html')

# 2. The API Endpoint to Handle Uploads
@app.post("/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    # Save the uploaded file temporarily
    temp_filename = f"temp_{file.filename}"
    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        # Run your analyzer script on the temp file
        report = analyze_apk(temp_filename)
    except Exception as e:
        return {"error": str(e)}
    finally:
        # Clean up: delete the file after analysis
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
            
    return report