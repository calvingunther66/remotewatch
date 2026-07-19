"""RemoteWatch FastAPI application: JSON API + static frontend.

Run with:  uvicorn backend.app:app --host 0.0.0.0 --port 8100
"""
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import apple_auth
from .gate import BasicAuthMiddleware
from .keygen import generate_keys
from .reports import AuthMissing, fetch_reports
from .store import (
    delete_key,
    key_path,
    keys_dir_default,
    list_keys,
    read_stored_reports,
)

KEYS_DIR = keys_dir_default()
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "frontend")

app = FastAPI(title="RemoteWatch", description="FindMy AirTag key generation & tracking")
app.add_middleware(BasicAuthMiddleware)


# ---------- request models ----------
class GenerateBody(BaseModel):
    count: int = Field(1, ge=1, le=50)
    prefix: str = ""


class LoginBody(BaseModel):
    username: str
    password: str
    method: str = "sms"  # "sms" or "trusted_device"


class VerifyBody(BaseModel):
    session_id: str
    code: str


class ReportsBody(BaseModel):
    hours: int = Field(24, ge=1, le=168)
    prefix: str = ""


# ---------- keys ----------
@app.get("/api/keys")
def get_keys():
    keys = list_keys(KEYS_DIR)
    reports = read_stored_reports(KEYS_DIR)
    # attach the latest cached fix to each key
    latest = {}
    for rep in reports:
        cur = latest.get(rep["key"])
        if cur is None or rep["timestamp"] > cur["timestamp"]:
            latest[rep["key"]] = rep
    counts = {}
    for rep in reports:
        counts[rep["key"]] = counts.get(rep["key"], 0) + 1
    for k in keys:
        k["last_report"] = latest.get(k["name"])
        k["report_count"] = counts.get(k["name"], 0)
    return {"keys": keys}


@app.post("/api/keys")
def post_keys(body: GenerateBody):
    keys = generate_keys(body.count, body.prefix, KEYS_DIR)
    # never return private material to the browser
    safe = [
        {
            "name": k["name"],
            "file": k["file"],
            "mac": k["mac"],
            "hashed_adv_key": k["hashed_adv_key"],
            "payload": k["payload"],
        }
        for k in keys
    ]
    return {"created": safe}


@app.get("/api/keys/{name}/download")
def download_key(name: str):
    path = key_path(KEYS_DIR, name)
    if not path or not os.path.exists(path):
        raise HTTPException(404, "Key not found")
    return FileResponse(path, media_type="text/plain", filename=name + ".keys")


@app.delete("/api/keys/{name}")
def remove_key(name: str):
    if not delete_key(KEYS_DIR, name):
        raise HTTPException(404, "Key not found")
    return {"deleted": name}


# ---------- reports / tracking ----------
@app.get("/api/reports")
def get_reports():
    """Return cached decrypted reports (no Apple round-trip)."""
    return {"reports": read_stored_reports(KEYS_DIR)}


@app.post("/api/reports/refresh")
def refresh_reports(body: ReportsBody):
    """Pull fresh location reports from Apple's FindMy network."""
    try:
        result = fetch_reports(KEYS_DIR, hours=body.hours, prefix=body.prefix)
    except AuthMissing:
        raise HTTPException(401, "Not signed in to Apple. Connect your Apple ID first.")
    except Exception as e:  # network / anisette / decrypt failures
        raise HTTPException(502, f"Could not fetch reports: {e}")
    return result


# ---------- apple auth ----------
@app.get("/api/auth/status")
def auth_status():
    return {"authenticated": apple_auth.is_authenticated(KEYS_DIR)}


@app.post("/api/auth/login")
def auth_login(body: LoginBody):
    try:
        return apple_auth.begin(KEYS_DIR, body.username, body.password, body.method)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/auth/verify")
def auth_verify(body: VerifyBody):
    try:
        return apple_auth.submit(KEYS_DIR, body.session_id, body.code)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/auth/logout")
def auth_logout():
    return {"signed_out": apple_auth.sign_out(KEYS_DIR)}


# ---------- frontend ----------
@app.get("/")
def index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"


# static assets (styles.css, app.js). Mounted last so /api/* wins.
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")
