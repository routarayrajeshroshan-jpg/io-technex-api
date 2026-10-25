import os
import hmac
from threading import Lock
from functools import lru_cache

import jwt
from jwt import PyJWKClient
from supabase import create_client, Client
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]
NODE_RED_API_KEY = os.environ["NODE_RED_API_KEY"]

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
)

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
# --------------------------------------------------

storage_lock = Lock()
latest_meters = []

# --------------------------------------------------
# AUTHENTICATION
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
        raise HTTPException(status_code=401, detail="Login required")

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
        )
def require_admin(
    claims: dict = Depends(require_customer),
):
    user_id = claims.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="User ID missing from login token",
        )

    try:
        result = (
            supabase.table("profiles")
            .select("role")
            .eq("id", user_id)
            .single()
            .execute()
        )

        profile = result.data

        if not profile or profile.get("role") != "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin access required",
            )

        return claims

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Unable to verify admin permissions",
        )


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
# DATABASE ACCESS
# --------------------------------------------------

def get_assigned_factories(user_id: str) -> list[str]:
    try:
        result = (
            supabase.table("factory_users")
            .select("factory_id")
            .eq("user_id", user_id)
            .execute()
        )

        return [
            str(row["factory_id"])
            for row in result.data
        ]

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Unable to verify factory access",
        )


def get_assigned_meter_ids(factory_ids: list[str]) -> set[int]:
    if not factory_ids:
        return set()

    try:
        result = (
            supabase.table("factory_meters")
            .select("slave_id")
            .in_("factory_id", factory_ids)
            .execute()
        )

        return {
            int(row["slave_id"])
            for row in result.data
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve assigned meters",
        )


# --------------------------------------------------
# REQUEST MODEL
# --------------------------------------------------
class CreateCustomerRequest(BaseModel):
    email: str
    password: str
    full_name: str

class CreateFactoryRequest(BaseModel):
    name: str
    location: str
    customer_user_id: str


class TelemetryPayload(BaseModel):
    data_source: str = "SIMULATED"
    meters: list[dict]


# --------------------------------------------------
# HEALTH ENDPOINTS
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "IO Technex Smart EMS API is running"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
@app.get("/api/v1/admin/check")
def admin_check(
    claims: dict = Depends(require_admin),
):
    return {
        "status": "success",
        "message": "Admin access verified",
        "user_id": claims.get("sub"),
    }
@app.post("/api/v1/admin/customers")
def create_customer(
    request: CreateCustomerRequest,
    claims: dict = Depends(require_admin),
):
    email = request.email.strip().lower()
    password = request.password
    full_name = request.full_name.strip()

    if not email or not full_name or len(password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Email and name are required; password must be at least 12 characters",
        )

    try:
        result = supabase.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": False,
            "user_metadata": {
                "full_name": full_name
            },
        })

        user = result.user

        if not user:
            raise HTTPException(
                status_code=500,
                detail="Customer account creation failed",
            )

        profile_result = (
            supabase.table("profiles")
            .upsert({
                "id": user.id,
                "full_name": full_name,
                "role": "customer",
            })
            .execute()
        )

        return {
            "status": "success",
            "message": "Customer account created",
            "customer": {
                "id": user.id,
                "email": user.email,
                "full_name": full_name,
                "role": "customer",
            },
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to create customer. Check whether the email already exists and verify Supabase configuration.",
        )
# --------------------------------------------------
# RECEIVE NODE-RED TELEMETRY
# --------------------------------------------------

@app.post("/api/v1/telemetry")
def receive_telemetry(
    payload: TelemetryPayload,
    _: None = Depends(require_node_red),
):
    global latest_meters

    if not payload.meters:
        raise HTTPException(
            status_code=400,
            detail="At least one meter reading is required",
        )

    for meter in payload.meters:
        if "slave_id" not in meter:
            raise HTTPException(
                status_code=400,
                detail="Each meter must include slave_id",
            )

    with storage_lock:
        latest_meters = payload.meters

    return {
        "status": "success",
        "message": "Telemetry received",
        "count": len(payload.meters),
        "data_source": payload.data_source,
    }


# --------------------------------------------------
# RETURN ONLY ASSIGNED METERS
# --------------------------------------------------

@app.get("/api/v1/telemetry")
def get_telemetry(
    claims: dict = Depends(require_customer),
):
    user_id = claims.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="User ID missing from login token",
        )

    factory_ids = get_assigned_factories(user_id)
    assigned_meter_ids = get_assigned_meter_ids(factory_ids)

    with storage_lock:
        meters = list(latest_meters)

    filtered_meters = [
        meter
        for meter in meters
        if meter.get("slave_id") is not None
        and int(meter["slave_id"]) in assigned_meter_ids
    ]

    return {
        "data_source": "NODE_RED" if filtered_meters else "SIMULATED",
        "count": len(filtered_meters),
        "meters": filtered_meters,
    }
