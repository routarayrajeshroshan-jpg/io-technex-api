import os
import hmac
from threading import Lock
from functools import lru_cache

import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# --------------------------------------------------

# CONFIGURATION

# Set these variables in Render Environment.

# --------------------------------------------------

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
NODE_RED_API_KEY = os.environ["NODE_RED_API_KEY"]

# --------------------------------------------------

# FASTAPI APPLICATION

# --------------------------------------------------

app = FastAPI(title="IO Technex Smart EMS API")

app.add_middleware(
CORSMiddleware,
allow_origins=[
"https://io-technex.vercel.app",
"http://localhost:5173",
"http://localhost:5174",
],
allow_credentials=False,
allow_methods=["GET", "POST"],
allow_headers=[
"Content-Type",
"Authorization",
"X-API-Key",
],
)

# --------------------------------------------------

# TEMPORARY TELEMETRY STORAGE

# Data will be lost if the service restarts.

# --------------------------------------------------

storage_lock = Lock()
latest_meters = []

# --------------------------------------------------

# SUPABASE JWT AUTHENTICATION

# --------------------------------------------------

security = HTTPBearer(auto_error=False)

JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"

@lru_cache(maxsize=1)
def get_jwks_client():
return PyJWKClient(JWKS_URL, cache_keys=True)

def require_customer(
credentials: HTTPAuthorizationCredentials = Depends(security),
):
if credentials is None:
raise HTTPException(
status_code=401,
detail="Login required",
headers={"WWW-Authenticate": "Bearer"},
)

```
try:
    token = credentials.credentials

    signing_key = get_jwks_client().get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["ES256"],
        audience="authenticated",
        issuer=f"{SUPABASE_URL}/auth/v1",
        options={"require": ["exp", "sub", "iss", "aud"]},
    )

    return claims

except Exception:
    raise HTTPException(
        status_code=401,
        detail="Invalid or expired login token",
        headers={"WWW-Authenticate": "Bearer"},
    )
```

# --------------------------------------------------

# NODE-RED AUTHENTICATION

# --------------------------------------------------

def require_node_red(
x_api_key: str = Header(default="", alias="X-API-Key"),
):
if not x_api_key or not hmac.compare_digest(
x_api_key, NODE_RED_API_KEY
):
raise HTTPException(
status_code=401,
detail="Invalid telemetry credential",
)

# --------------------------------------------------

# TELEMETRY REQUEST MODEL

# --------------------------------------------------

class TelemetryPayload(BaseModel):
data_source: str = "SIMULATED"
meters: list[dict]

# --------------------------------------------------

# PUBLIC HEALTH ENDPOINTS

# --------------------------------------------------

@app.get("/")
def home():
return {
"message": "IO Technex Smart EMS API is running",
"authentication": "required for telemetry",
}

@app.get("/health")
def health():
return {"status": "healthy"}

# --------------------------------------------------

# RECEIVE TELEMETRY FROM NODE-RED

# Requires X-API-Key.

# --------------------------------------------------

@app.post("/api/v1/telemetry")
def receive_telemetry(
payload: TelemetryPayload,
_: None = Depends(require_node_red),
):
global latest_meters

```
if not payload.meters:
    raise HTTPException(
        status_code=400,
        detail="At least one meter reading is required",
    )

with storage_lock:
    latest_meters = payload.meters

return {
    "status": "success",
    "message": "Telemetry received",
    "count": len(payload.meters),
    "data_source": payload.data_source,
}
```

# --------------------------------------------------

# RETURN TELEMETRY TO AUTHENTICATED CUSTOMERS

# Requires a valid Supabase access token.

# --------------------------------------------------

@app.get("/api/v1/telemetry")
def get_telemetry(
claims: dict = Depends(require_customer),
):
with storage_lock:
meters = list(latest_meters)

```
return {
    "data_source": "NODE_RED" if meters else "SIMULATED",
    "count": len(meters),
    "meters": meters,
}
```
