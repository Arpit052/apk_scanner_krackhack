"""
KrackHack APK Scanner - web API.

Endpoints
  GET  /                      dashboard (index.html)
  GET  /health                liveness probe
  POST /api/scan              upload an APK -> {"job_id": ...}  (async, poll for progress)
  GET  /api/scan/{job_id}     progress, live log and - when finished - the report
  GET  /api/report/{job_id}.json | .sarif
  POST /analyze               legacy synchronous endpoint (returns the report directly)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from scanner.engine import ENGINE_VERSION, analyze
from scanner.sarif import to_sarif

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_MB = int(os.environ.get("MAX_UPLOAD_MB", "300"))
MAX_FILE_SIZE = MAX_MB * 1024 * 1024
CHUNK = 1024 * 1024
WORKERS = int(os.environ.get("SCANNER_WORKERS", "2"))
JOB_TTL = int(os.environ.get("JOB_TTL_SECONDS", "3600"))
MAX_PENDING = int(os.environ.get("MAX_PENDING_JOBS", "16"))
ALLOWED_EXT = (".apk", ".xapk", ".apks", ".apkm")

executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="scan")
jobs: dict = {}
jobs_lock = threading.Lock()


def _now() -> float:
    return time.time()


def _gc_jobs() -> None:
    cutoff = _now() - JOB_TTL
    with jobs_lock:
        for jid in [j for j, v in jobs.items() if v["updated"] < cutoff and v["status"] in ("done", "error")]:
            jobs.pop(jid, None)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    print("=" * 64)
    print(f"  KrackHack APK Scanner v{ENGINE_VERSION}  ·  max upload {MAX_MB} MB  ·  {WORKERS} worker(s)")
    print("=" * 64)
    yield
    executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="KrackHack APK Scanner", version=ENGINE_VERSION,
              description="Static security & malware analysis for Android apps (OWASP Mobile Top 10 2024 / MASVS)",
              lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
if os.path.isdir(os.path.join(BASE_DIR, "static")):
    app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.get("/")
async def index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/health")
async def health():
    with jobs_lock:
        running = sum(1 for j in jobs.values() if j["status"] == "running")
        queued = sum(1 for j in jobs.values() if j["status"] == "queued")
    return {"status": "ok", "version": ENGINE_VERSION, "max_file_size_mb": MAX_MB, "workers": WORKERS,
            "running": running, "queued": queued, "timestamp": datetime.now(timezone.utc).isoformat()}


async def _save_upload(file: UploadFile) -> tuple:
    name = os.path.basename(file.filename or "upload.apk")
    if not name.lower().endswith(ALLOWED_EXT):
        raise HTTPException(400, f"Unsupported file type. Upload one of: {', '.join(ALLOWED_EXT)}")
    tmpdir = tempfile.mkdtemp(prefix="apkscan_")
    path = os.path.join(tmpdir, "upload" + os.path.splitext(name)[1].lower())
    size = 0
    first = b""
    try:
        with open(path, "wb") as out:
            while chunk := await file.read(CHUNK):
                if not first:
                    first = chunk[:4]
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(413, f"File too large. Max {MAX_MB} MB")
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "Empty file")
        if first[:2] != b"PK":
            raise HTTPException(400, "This is not an APK (ZIP signature missing)")
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    return name, path, tmpdir, size


def _run_job(jid: str, path: str, tmpdir: str, name: str) -> None:
    job = jobs[jid]
    job["status"] = "running"
    job["started"] = _now()

    def progress(pct: int, stage: str, msg: str) -> None:
        job["progress"] = pct
        job["stage"] = stage
        job["message"] = msg
        job["log"].append({"t": round(_now() - job["started"], 2), "pct": pct, "msg": msg})
        job["updated"] = _now()

    try:
        report = analyze(path, progress=progress, original_name=name)
        job["result"] = report
        job["status"] = "done"
        job["progress"] = 100
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        job["log"].append({"t": round(_now() - job["started"], 2), "pct": job["progress"], "msg": f"ERROR: {e}"})
    finally:
        job["updated"] = _now()
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/api/scan")
async def create_scan(file: UploadFile = File(...)):
    _gc_jobs()
    with jobs_lock:
        pending = sum(1 for j in jobs.values() if j["status"] in ("queued", "running"))
    if pending >= MAX_PENDING:
        raise HTTPException(429, "Scanner is busy, try again in a minute")
    name, path, tmpdir, size = await _save_upload(file)
    jid = uuid.uuid4().hex[:16]
    with jobs_lock:
        jobs[jid] = {"id": jid, "file": name, "size": size, "status": "queued", "progress": 0, "stage": "queued",
                     "message": "Waiting for a free worker", "log": [], "created": _now(), "updated": _now(),
                     "result": None, "error": None}
    executor.submit(_run_job, jid, path, tmpdir, name)
    return {"job_id": jid, "file": name, "size": size}


@app.get("/api/scan/{jid}")
async def scan_status(jid: str, since: int = 0):
    job = jobs.get(jid)
    if not job:
        raise HTTPException(404, "Unknown or expired scan")
    body = {k: job[k] for k in ("id", "file", "size", "status", "progress", "stage", "message", "error")}
    body["log"] = job["log"][since:]
    body["log_total"] = len(job["log"])
    if job["status"] == "done":
        body["result"] = job["result"]
    return JSONResponse(body)


@app.get("/api/report/{jid}.json")
async def report_json(jid: str):
    job = jobs.get(jid)
    if not job or not job.get("result"):
        raise HTTPException(404, "Report not available")
    return JSONResponse(job["result"], headers={"Content-Disposition": f'attachment; filename="{jid}.json"'})


@app.get("/api/report/{jid}.sarif")
async def report_sarif(jid: str):
    job = jobs.get(jid)
    if not job or not job.get("result"):
        raise HTTPException(404, "Report not available")
    return JSONResponse(to_sarif(job["result"]), headers={"Content-Disposition": f'attachment; filename="{jid}.sarif"'})


@app.post("/analyze")
async def analyze_legacy(file: UploadFile = File(...)):
    """Synchronous endpoint kept for existing integrations."""
    name, path, tmpdir, _ = await _save_upload(file)
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, lambda: analyze(path, original_name=name))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
