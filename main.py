import os
import hmac
from threading import Lock
from functools import lru_cache
from typing import Any
from uuid import UUID

import jwt
from jwt import PyJWKClient
from supabase import create_client, Client
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ConfigDict


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
# Set these environment variables in Render. Never hard-code secrets.
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_SECRET_KEY = os.environ["SUPABASE_SECRET_KEY"]
NODE_RED_API_KEY = os.environ["NODE_RED_API_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)


# --------------------------------------------------
# FASTAPI APPLICATION
# --------------------------------------------------
app = FastAPI(
    title="IO Technex Smart EMS API",
    version="1.0.0",
    description="API for IO Technex Smart EMS customer, factory, meter, and telemetry data.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://io-technex.vercel.app",
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# --------------------------------------------------
# TEMPORARY TELEMETRY STORAGE
# --------------------------------------------------
# NOTE: This is in-memory storage. Readings are lost when the API restarts
# and are not shared across multiple API instances. Move telemetry to a
# persistent database before production use.
storage_lock = Lock()
# Key is (factory_id, slave_id), so the same Modbus ID can exist in
# different factories without one factory's readings replacing another's.
latest_meters: dict[tuple[str, int], dict[str, Any]] = {}


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------
security = HTTPBearer(auto_error=False)
JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"


@lru_cache(maxsize=1)
def get_jwks_client() -> PyJWKClient:
    return PyJWKClient(JWKS_URL, cache_keys=True)


def require_customer(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
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
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    try:
        result = (
            supabase.table("profiles")
            .select("role")
            .eq("id", user_id)
            .maybe_single()
            .execute()
        )
        profile = result.data

        if not profile or profile.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")

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
) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, NODE_RED_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid telemetry credential")


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------
def get_assigned_factories(user_id: str) -> list[str]:
    try:
        result = (
            supabase.table("factory_users")
            .select("factory_id")
            .eq("user_id", user_id)
            .execute()
        )
        return [str(row["factory_id"]) for row in (result.data or [])]
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to verify factory access")


def get_factory_meter_map(factory_ids: list[str]) -> dict[str, set[int]]:
    """Return {factory_id: {assigned slave IDs}} for only the supplied factories."""
    if not factory_ids:
        return {}

    try:
        result = (
            supabase.table("factory_meters")
            .select("factory_id, slave_id")
            .in_("factory_id", factory_ids)
            .execute()
        )
        mapping: dict[str, set[int]] = {factory_id: set() for factory_id in factory_ids}
        for row in result.data or []:
            mapping.setdefault(str(row["factory_id"]), set()).add(int(row["slave_id"]))
        return mapping
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to retrieve assigned meters")


def validate_uuid(value: str, field_name: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail=f"Invalid {field_name}")


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------
class CreateCustomerRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class CreateFactoryRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    location: str = Field(min_length=1, max_length=200)
    customer_user_id: str = Field(min_length=1, max_length=100)


class RegisterMeterRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    factory_id: str = Field(min_length=1, max_length=100)
    slave_id: int = Field(ge=1, le=247)
    meter_name: str = Field(min_length=1, max_length=120)


class MeterReading(BaseModel):
    model_config = ConfigDict(extra="allow")
    slave_id: int = Field(ge=1, le=247)


class TelemetryPayload(BaseModel):
    # Required to prevent readings from different factories being mixed.
    factory_id: str = Field(min_length=1, max_length=100)
    data_source: str = Field(default="NODE_RED", min_length=1, max_length=40)
    meters: list[MeterReading] = Field(min_length=1, max_length=500)


# --------------------------------------------------
# HEALTH ENDPOINTS
# --------------------------------------------------
@app.get("/")
def home() -> dict[str, str]:
    return {"message": "IO Technex Smart EMS API is running"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


# --------------------------------------------------
# ADMIN: VERIFY ACCESS
# --------------------------------------------------
@app.get("/api/v1/admin/check")
def admin_check(claims: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
    return {
        "status": "success",
        "message": "Admin access verified",
        "user_id": str(claims.get("sub", "")),
    }


# --------------------------------------------------
# ADMIN: CREATE CUSTOMER
# --------------------------------------------------
@app.post("/api/v1/admin/customers", status_code=201)
def create_customer(
    request: CreateCustomerRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    email = request.email.strip().lower()
    full_name = request.full_name.strip()

    if not email or "@" not in email or not full_name:
        raise HTTPException(status_code=400, detail="A valid email and customer name are required")

    try:
        result = supabase.auth.admin.create_user(
            {
                "email": email,
                "password": request.password,
                "email_confirm": False,
                "user_metadata": {"full_name": full_name},
            }
        )
        user = result.user

        if not user:
            raise HTTPException(status_code=500, detail="Customer account creation failed")

        try:
            (
                supabase.table("profiles")
                .upsert(
                    {
                        "id": user.id,
                        "full_name": full_name,
                        "role": "customer",
                    }
                )
                .execute()
            )
        except Exception:
            # Compensate for partial creation so an auth account is not silently left
            # without the corresponding profile. If deletion fails, inspect Supabase.
            try:
                supabase.auth.admin.delete_user(user.id)
            except Exception:
                pass
            raise HTTPException(
                status_code=500,
                detail="Customer account was created but profile setup failed; check Supabase",
            )

        return {
            "status": "success",
            "message": "Customer account created. Email confirmation/invitation setup may still be required.",
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
# ADMIN: CREATE FACTORY AND ASSIGN CUSTOMER
# --------------------------------------------------
@app.post("/api/v1/admin/factories", status_code=201)
def create_factory(
    request: CreateFactoryRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    name = request.name.strip()
    location = request.location.strip()
    customer_user_id = request.customer_user_id.strip()

    if not name or not location or not customer_user_id:
        raise HTTPException(
            status_code=400,
            detail="Factory name, location, and customer user ID are required",
        )

    factory_id: str | None = None

    try:
        profile_result = (
            supabase.table("profiles")
            .select("id, role")
            .eq("id", customer_user_id)
            .maybe_single()
            .execute()
        )
        profile = profile_result.data

        if not profile or profile.get("role") != "customer":
            raise HTTPException(status_code=400, detail="A valid customer account is required")

        factory_result = (
            supabase.table("factories")
            .insert({"name": name, "location": location})
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=500, detail="Factory creation failed")

        factory = factory_result.data[0]
        factory_id = str(factory["id"])

        try:
            (
                supabase.table("factory_users")
                .insert({"factory_id": factory_id, "user_id": customer_user_id})
                .execute()
            )
        except Exception:
            # Best-effort cleanup. For strict atomicity, use a Supabase SQL RPC
            # transaction for both inserts.
            try:
                supabase.table("factories").delete().eq("id", factory_id).execute()
            except Exception:
                pass
            raise HTTPException(
                status_code=500,
                detail="Factory assignment failed. Check the customer and factory_users table.",
            )

        return {
            "status": "success",
            "message": "Factory created and customer assigned",
            "factory": {
                "id": factory_id,
                "name": factory.get("name", name),
                "location": factory.get("location", location),
            },
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to create factory or assign customer",
        )


# --------------------------------------------------
# ADMIN: REGISTER METER TO FACTORY
# --------------------------------------------------
@app.post("/api/v1/admin/meters", status_code=201)
def register_meter(
    request: RegisterMeterRequest,
    claims: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    factory_id = validate_uuid(request.factory_id.strip(), "factory ID")
    meter_name = request.meter_name.strip()
    slave_id = request.slave_id

    if not meter_name:
        raise HTTPException(status_code=400, detail="Meter name is required")

    try:
        factory_result = (
            supabase.table("factories")
            .select("id")
            .eq("id", factory_id)
            .maybe_single()
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")

        result = (
            supabase.table("factory_meters")
            .insert(
                {
                    "factory_id": factory_id,
                    "slave_id": slave_id,
                    "meter_name": meter_name,
                }
            )
            .execute()
        )
        if not result.data:
            raise HTTPException(status_code=500, detail="Meter registration returned no record")

        return {
            "status": "success",
            "message": "Meter registered",
            "meter": result.data[0],
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to register meter. Check for a duplicate slave ID in this factory.",
        )


# --------------------------------------------------
# RECEIVE NODE-RED TELEMETRY
# --------------------------------------------------
@app.post("/api/v1/telemetry", status_code=202)
def receive_telemetry(
    payload: TelemetryPayload,
    _: None = Depends(require_node_red),
) -> dict[str, Any]:
    factory_id = validate_uuid(payload.factory_id.strip(), "factory ID")

    # Only accept telemetry for a factory and meters already registered in Supabase.
    try:
        factory_result = (
            supabase.table("factories")
            .select("id")
            .eq("id", factory_id)
            .maybe_single()
            .execute()
        )
        if not factory_result.data:
            raise HTTPException(status_code=404, detail="Factory not found")

        registered_result = (
            supabase.table("factory_meters")
            .select("slave_id")
            .eq("factory_id", factory_id)
            .execute()
        )
        registered_ids = {
            int(row["slave_id"]) for row in (registered_result.data or [])
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Unable to validate factory meter assignments")

    if not registered_ids:
        raise HTTPException(status_code=400, detail="No meters are registered to this factory")

    seen_ids: set[int] = set()
    normalized_readings: list[dict[str, Any]] = []

    for reading_model in payload.meters:
        reading = reading_model.model_dump()
        slave_id = int(reading["slave_id"])

        if slave_id not in registered_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Slave ID {slave_id} is not registered to this factory",
            )
        if slave_id in seen_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate slave ID {slave_id} in this telemetry payload",
            )

        seen_ids.add(slave_id)
        reading["factory_id"] = factory_id
        reading["data_source"] = payload.data_source
        normalized_readings.append(reading)

    with storage_lock:
        for reading in normalized_readings:
            key = (factory_id, int(reading["slave_id"]))
            latest_meters[key] = reading

    return {
        "status": "success",
        "message": "Telemetry received",
        "factory_id": factory_id,
        "count": len(normalized_readings),
        "data_source": payload.data_source,
    }


# --------------------------------------------------
# CUSTOMER: RETURN ONLY ASSIGNED FACTORY METERS
# --------------------------------------------------
@app.get("/api/v1/telemetry")
def get_telemetry(
    claims: dict[str, Any] = Depends(require_customer),
) -> dict[str, Any]:
    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="User ID missing from login token")

    factory_ids = get_assigned_factories(user_id)
    if not factory_ids:
        return {
            "data_source": "SIMULATED",
            "count": 0,
            "factories": [],
            "meters": [],
        }

    factory_meter_map = get_factory_meter_map(factory_ids)

    with storage_lock:
        stored_readings = list(latest_meters.values())

    # Match on BOTH factory_id and slave_id. Never filter by slave ID alone.
    filtered_meters = [
        reading
        for reading in stored_readings
        if reading.get("factory_id") in factory_ids
        and int(reading.get("slave_id", 0)) in factory_meter_map.get(
            str(reading.get("factory_id")), set()
        )
    ]

    data_source = (
        filtered_meters[0].get("data_source", "NODE_RED")
        if filtered_meters
        else "SIMULATED"
    )

    return {
        "data_source": data_source,
        "count": len(filtered_meters),
        "factories": factory_ids,
        "meters": filtered_meters,
    }
