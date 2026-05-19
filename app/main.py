from __future__ import annotations

import io
import os
import re
import shutil
import uuid
import csv
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect, or_, text, func
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import date, datetime, timedelta
import pandas as pd
from fpdf import FPDF

from .database import Base, engine, SessionLocal
from .models import Store, Entry, Route, EntryAuditLog, business_today, IST as _IST
from .auth import hash_password, verify_password, admin_secret_ok

Base.metadata.create_all(bind=engine)

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_store_columns() -> None:
    insp = inspect(engine)
    if "stores" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("stores")}
    is_sqlite = str(engine.url).startswith("sqlite")
    with engine.begin() as conn:
        if "location_url" not in cols:
            conn.execute(text("ALTER TABLE stores ADD COLUMN location_url VARCHAR"))
        if "opening_balance" not in cols:
            ob_type = "REAL DEFAULT 0" if is_sqlite else "DOUBLE PRECISION DEFAULT 0"
            conn.execute(text(f"ALTER TABLE stores ADD COLUMN opening_balance {ob_type}"))
        if "sort_order" not in cols:
            conn.execute(text("ALTER TABLE stores ADD COLUMN sort_order INTEGER DEFAULT 0"))


def _ensure_entry_columns() -> None:
    insp = inspect(engine)
    if "entries" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("entries")}
    is_sqlite = str(engine.url).startswith("sqlite")
    ts_type = "DATETIME" if is_sqlite else "TIMESTAMP"
    with engine.begin() as conn:
        if "collected_cash" not in cols:
            conn.execute(text("ALTER TABLE entries ADD COLUMN collected_cash FLOAT DEFAULT 0"))
        if "collected_upi" not in cols:
            conn.execute(text("ALTER TABLE entries ADD COLUMN collected_upi FLOAT DEFAULT 0"))
        if "updated_at" not in cols:
            conn.execute(text(f"ALTER TABLE entries ADD COLUMN updated_at {ts_type}"))
    db = SessionLocal()
    try:
        for e in db.query(Entry).all():
            cc = float(e.collected_cash or 0)
            cu = float(e.collected_upi or 0)
            amt = float(e.amount_collected or 0)
            if cc == 0 and cu == 0 and amt > 0:
                pm = (e.payment_mode or "cash").lower()
                if pm == "upi":
                    e.collected_upi = amt
                else:
                    e.collected_cash = amt
                e.amount_collected = amt
        db.commit()
    finally:
        db.close()


_ensure_store_columns()
_ensure_entry_columns()


def _ensure_route_code_column() -> None:
    insp = inspect(engine)
    if "routes" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("routes")}
    if "route_code" not in cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE routes ADD COLUMN route_code INTEGER"))
    db = SessionLocal()
    try:
        for r in db.query(Route).all():
            if getattr(r, "route_code", None) is None:
                r.route_code = r.id
        db.commit()
    finally:
        db.close()
    with engine.begin() as conn:
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_routes_route_code ON routes (route_code)"))


_ensure_route_code_column()


def _migrate_utc_to_ist() -> None:
    """One-time: shift existing created_at from UTC to IST (+5:30).

    Uses a marker column 'tz_migrated' on entries to avoid running twice.
    """
    insp = inspect(engine)
    if "entries" not in insp.get_table_names():
        return
    cols = {c["name"] for c in insp.get_columns("entries")}
    if "tz_migrated" in cols:
        return
    is_sqlite = str(engine.url).startswith("sqlite")
    with engine.begin() as conn:
        bool_type = "BOOLEAN DEFAULT 1" if is_sqlite else "BOOLEAN DEFAULT TRUE"
        conn.execute(text(f"ALTER TABLE entries ADD COLUMN tz_migrated {bool_type}"))
    db = SessionLocal()
    try:
        from datetime import timedelta as _td
        offset = _td(hours=5, minutes=30)
        for e in db.query(Entry).all():
            if e.created_at is not None:
                e.created_at = e.created_at + offset
        db.commit()
    finally:
        db.close()


_migrate_utc_to_ist()


def _ensure_store_name_unique_index() -> None:
    """Add a unique index on stores.name if it doesn't already exist."""
    insp = inspect(engine)
    if "stores" not in insp.get_table_names():
        return
    existing = {idx["name"] for idx in insp.get_indexes("stores")}
    if "uq_store_name" in existing:
        return
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE UNIQUE INDEX uq_store_name ON stores (name)"
            ))
    except Exception:
        pass


_ensure_store_name_unique_index()

app = FastAPI()

_cors = os.environ.get("CORS_ORIGINS", "*").strip()
_cors_list = [o.strip() for o in _cors.split(",") if o.strip()] if _cors != "*" else ["*"]
_cors_credentials = False if _cors_list == ["*"] else True

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_list,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------- ADMIN ----------------
def _admin_secret_from_request(request: Request) -> str:
    return (request.headers.get("X-Admin-Secret") or request.headers.get("x-admin-secret") or "").strip()


def _require_admin(request: Request, body_secret: str | None = None) -> None:
    hdr = _admin_secret_from_request(request)
    if admin_secret_ok(hdr) or admin_secret_ok((body_secret or "").strip() if body_secret else None):
        return
    detail = (
        "Invalid or missing admin secret"
        if os.environ.get("ADMIN_SECRET", "").strip()
        else "Server ADMIN_SECRET is not configured"
    )
    raise HTTPException(403, detail)


class AdminVerifyBody(BaseModel):
    admin_secret: str


@app.post("/admin/verify")
def admin_verify(body: AdminVerifyBody):
    if not admin_secret_ok(body.admin_secret):
        raise HTTPException(403, "Invalid admin secret")
    return {"ok": True}


def _next_business_date(base: date | None = None) -> date:
    base_date = base or business_today()
    return base_date + timedelta(days=1)


def _entry_net_units(e: Entry) -> int:
    return int(e.delivered or 0) - int(e.returned or 0)


def _safe_round_prediction(value: float) -> int:
    return max(0, int(round(float(value or 0))))


def _daily_net_totals(
    db: Session,
    from_date: date,
    to_date: date,
    route_id: int | None = None,
) -> dict[date, int]:
    q = db.query(Entry).filter(
        Entry.date >= from_date,
        Entry.date <= to_date,
        Entry.is_closed == False,
    )

    if route_id is not None:
        q = q.filter(Entry.route_id == route_id)

    totals: dict[date, int] = defaultdict(int)
    for e in q.all():
        if e.date is not None:
            totals[e.date] += _entry_net_units(e)

    return dict(totals)


def _average(values: list[int | float]) -> float:
    if not values:
        return 0.0
    return float(sum(values)) / float(len(values))


def _prediction_confidence(
    same_weekday_count: int,
    last_7_count: int,
    last_day_total: int,
) -> str:
    if same_weekday_count >= 4 and last_7_count >= 5:
        return "high"
    if same_weekday_count >= 2 and last_7_count >= 3:
        return "medium"
    if same_weekday_count >= 1 or last_7_count >= 1 or last_day_total > 0:
        return "low"
    return "no_data"


class AdminSalesPredictionResponse(BaseModel):
    prediction_date: date
    prediction_weekday: str
    route_id: int | None = None
    predicted_units: int
    avg_same_weekday: float
    same_weekday_count: int
    last_7_days_avg: float
    last_7_days_count: int
    last_day_total: int
    confidence: str
    formula: str


@app.get("/admin/prediction/sales", response_model=AdminSalesPredictionResponse)
def admin_sales_prediction(
    request: Request,
    route_id: int | None = Query(None),
    history_days: int = Query(90, ge=14, le=365),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)

    today = business_today()
    prediction_date = _next_business_date(today)
    prediction_weekday_index = prediction_date.weekday()

    history_start = today - timedelta(days=history_days)
    history_end = today

    daily_totals = _daily_net_totals(
        db=db,
        from_date=history_start,
        to_date=history_end,
        route_id=route_id,
    )

    same_weekday_values: list[int] = []
    for d, total in daily_totals.items():
        if d < prediction_date and d.weekday() == prediction_weekday_index:
            same_weekday_values.append(int(total))

    avg_same_weekday = _average(same_weekday_values)

    last_7_start = today - timedelta(days=6)
    last_7_values: list[int] = []
    cursor = last_7_start
    while cursor <= today:
        if cursor in daily_totals:
            last_7_values.append(int(daily_totals[cursor]))
        cursor += timedelta(days=1)

    last_7_days_avg = _average(last_7_values)
    last_day_total = int(daily_totals.get(today, 0) or 0)

    if last_day_total == 0 and daily_totals:
        available_dates = sorted(daily_totals.keys())
        if available_dates:
            last_available_date = available_dates[-1]
            last_day_total = int(daily_totals.get(last_available_date, 0) or 0)

    weighted_prediction = (
        0.5 * avg_same_weekday
        + 0.3 * last_7_days_avg
        + 0.2 * last_day_total
    )

    predicted_units = _safe_round_prediction(weighted_prediction)

    confidence = _prediction_confidence(
        same_weekday_count=len(same_weekday_values),
        last_7_count=len(last_7_values),
        last_day_total=last_day_total,
    )

    return {
        "prediction_date": prediction_date,
        "prediction_weekday": prediction_date.strftime("%A"),
        "route_id": route_id,
        "predicted_units": predicted_units,
        "avg_same_weekday": round(avg_same_weekday, 2),
        "same_weekday_count": len(same_weekday_values),
        "last_7_days_avg": round(last_7_days_avg, 2),
        "last_7_days_count": len(last_7_values),
        "last_day_total": last_day_total,
        "confidence": confidence,
        "formula": "0.5*avg_same_weekday + 0.3*last_7_days_avg + 0.2*last_day_total",
    }


# ---------------- EDIT WINDOW & AUDIT ----------------

_EDIT_WINDOW_MINUTES = 15


def _is_within_edit_window(entry: Entry) -> bool:
    if entry.created_at is None:
        return False
    now = datetime.now(_IST).replace(tzinfo=None)
    return (now - entry.created_at).total_seconds() <= _EDIT_WINDOW_MINUTES * 60


def _write_audit_rows(
    db: Session,
    entry: Entry,
    changes: dict[str, tuple[str, str]],
    edited_by: str,
) -> None:
    """Write one audit row per changed field. `changes` maps field -> (old, new)."""
    now = datetime.now(_IST).replace(tzinfo=None)
    for field, (old_val, new_val) in changes.items():
        db.add(EntryAuditLog(
            entry_id=entry.id,
            field_name=field,
            old_value=old_val,
            new_value=new_val,
            edited_by=edited_by,
            edited_at=now,
        ))


def _snapshot_entry_fields(e: Entry) -> dict[str, str]:
    cc, cu = _entry_cash_upi(e)
    return {
        "delivered": str(int(e.delivered or 0)),
        "returned": str(int(e.returned or 0)),
        "collected_cash": str(round(cc, 2)),
        "collected_upi": str(round(cu, 2)),
        "upi_received": str(bool(e.upi_received)),
        "is_closed": str(bool(e.is_closed)),
    }


def _diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict[str, tuple[str, str]]:
    changes: dict[str, tuple[str, str]] = {}
    for k in before:
        if before[k] != after.get(k, before[k]):
            changes[k] = (before[k], after[k])
    return changes


# ---------------- ROUTES (admin creates) ----------------
_ROUTE_PASSWORD_PATTERN = re.compile(r"^\d{4}$")


def _validate_route_password(plain: str) -> None:
    if not plain or not _ROUTE_PASSWORD_PATTERN.fullmatch(plain.strip()):
        raise HTTPException(
            400,
            "Route password must be exactly 4 digits (0-9 only), e.g. 4829.",
        )


class AdminRouteCreate(BaseModel):
    route_code: int = Field(..., ge=1, description="Business route ID shown in lists and Excel (e.g. 1).")
    name: str
    password: str
    admin_secret: str | None = None


def _route_name_conflict(db: Session, name: str, exclude_id: int | None = None) -> Route | None:
    """Return an existing route if another row already uses this name (case-insensitive)."""
    key = (name or "").strip().lower()
    if not key:
        return None
    q = db.query(Route).filter(func.lower(func.trim(Route.name)) == key)
    if exclude_id is not None:
        q = q.filter(Route.id != exclude_id)
    return q.first()


def _route_code_conflict(db: Session, code: int, exclude_id: int | None = None) -> Route | None:
    q = db.query(Route).filter(Route.route_code == int(code))
    if exclude_id is not None:
        q = q.filter(Route.id != exclude_id)
    return q.first()


def _resolve_internal_route_id_from_code(db: Session, route_code: int) -> int:
    r = db.query(Route).filter(Route.route_code == int(route_code)).first()
    if not r:
        raise HTTPException(
            400,
            f"No route with route ID {int(route_code)}. Create the route in admin first.",
        )
    return r.id


def _store_name_conflict(
    db: Session,
    name: str,
    exclude_store_id: int | None = None,
) -> Store | None:
    """Return any existing store whose name matches (case-insensitive, globally unique)."""
    key = (name or "").strip().lower()
    if not key:
        return None
    q = db.query(Store).filter(
        func.lower(func.trim(Store.name)) == key,
    )
    if exclude_store_id is not None:
        q = q.filter(Store.id != exclude_store_id)
    return q.first()


_ROUTE_FILENAME_RE = re.compile(
    r"^Route\s+(\d+)\s*[\u2013\u2014\-]\s*(.+)$",
    re.IGNORECASE | re.DOTALL,
)


def _parse_route_from_upload_filename(filename: str | None) -> tuple[int, str] | None:
    """Match e.g. 'Route 1 – Eachanari–Kovaipudur Belt.xlsx' → (1, 'Eachanari–Kovaipudur Belt')."""
    if not filename:
        return None
    stem = Path(filename).stem.strip()
    m = _ROUTE_FILENAME_RE.match(stem)
    if not m:
        return None
    return int(m.group(1)), m.group(2).strip()


@app.post("/admin/routes")
def admin_create_route(body: AdminRouteCreate, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, body.admin_secret)

    name_stripped = body.name.strip()
    if not name_stripped:
        raise HTTPException(400, "Route name cannot be empty")

    dup_code = _route_code_conflict(db, body.route_code, None)
    if dup_code:
        raise HTTPException(
            409,
            f"Route ID {body.route_code} is already used by \"{dup_code.name}\". Choose a different route ID.",
        )

    dup = _route_name_conflict(db, name_stripped, None)
    if dup:
        raise HTTPException(
            409,
            f'A route with this name already exists (route ID {dup.route_code}, "{dup.name}"). Use a different name.',
        )

    _validate_route_password(body.password)
    r = Route(
        route_code=int(body.route_code),
        name=name_stripped,
        password=hash_password(body.password.strip()),
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return {"id": r.id, "route_code": r.route_code, "name": r.name}


class AdminRoutePatch(BaseModel):
    route_code: int | None = None
    name: str | None = None
    password: str | None = None


@app.get("/admin/routes")
def admin_list_routes(request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    rows = db.query(Route).order_by(Route.route_code.asc(), Route.id.asc()).all()
    return [{"id": r.id, "route_code": r.route_code, "name": r.name} for r in rows]


@app.patch("/admin/routes/{route_id}")
def admin_patch_route(
    route_id: int,
    body: AdminRoutePatch,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    r = db.query(Route).filter(Route.id == route_id).first()
    if not r:
        raise HTTPException(404, "Route not found")
    if body.route_code is not None:
        if body.route_code < 1:
            raise HTTPException(400, "Route ID must be a positive integer.")
        dup_c = _route_code_conflict(db, body.route_code, route_id)
        if dup_c:
            raise HTTPException(
                409,
                f"Route ID {body.route_code} is already used by \"{dup_c.name}\".",
            )
        r.route_code = int(body.route_code)
    if body.name is not None:
        name_stripped = body.name.strip()
        if not name_stripped:
            raise HTTPException(400, "Route name cannot be empty")
        dup = _route_name_conflict(db, name_stripped, route_id)
        if dup:
            raise HTTPException(
                409,
                f'Another route already uses this name (route ID {dup.route_code}, "{dup.name}"). Choose a different name.',
            )
        r.name = name_stripped
    if body.password is not None and body.password != "":
        _validate_route_password(body.password)
        r.password = hash_password(body.password.strip())
    db.commit()
    db.refresh(r)
    return {"id": r.id, "route_code": r.route_code, "name": r.name}


@app.delete("/admin/routes/{route_id}")
def admin_delete_route(route_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    r = db.query(Route).filter(Route.id == route_id).first()
    if not r:
        raise HTTPException(404, "Route not found")

    store_ids = [s.id for s in db.query(Store).filter(Store.route_id == route_id).all()]
    if store_ids:
        db.query(Entry).filter(Entry.store_id.in_(store_ids)).delete(synchronize_session=False)
    db.query(Entry).filter(Entry.route_id == route_id).delete(synchronize_session=False)
    db.query(Store).filter(Store.route_id == route_id).delete(synchronize_session=False)
    db.query(Route).filter(Route.id == route_id).delete()
    db.commit()
    return {"ok": True, "deleted_id": route_id}


class RouteLogin(BaseModel):
    route_id: int
    password: str


@app.get("/routes")
def get_routes(db: Session = Depends(get_db)):
    rows = db.query(Route).order_by(Route.route_code.asc(), Route.id.asc()).all()
    return [{"id": r.id, "route_code": r.route_code, "name": r.name} for r in rows]


@app.post("/routes/login")
def route_login(body: RouteLogin, db: Session = Depends(get_db)):
    route = db.query(Route).filter(Route.id == body.route_id).first()
    if not route or not verify_password(body.password, route.password):
        raise HTTPException(401, "Invalid password")
    return {
        "message": "Access granted",
        "route_id": route.id,
        "route_code": route.route_code,
        "name": route.name,
    }


# ---------------- STORE ----------------
class StoreCreate(BaseModel):
    name: str
    area: str | None = None
    price: float
    route_id: int

    offer_type: str = "none"
    offer_buy: int = 0
    offer_get: int = 0
    offer_min_qty: int = 0
    bundle_price: float = 0

    photo_url: str | None = None
    location_url: str | None = None
    notes: str | None = None
    opening_balance: float = 0


class StoreUpdate(BaseModel):
    name: str | None = None
    is_active: bool | None = None
    photo_url: str | None = None
    location_url: str | None = None
    notes: str | None = None
    area: str | None = None
    price: float | None = None
    offer_type: str | None = None
    offer_buy: int | None = None
    offer_get: int | None = None
    offer_min_qty: int | None = None
    bundle_price: float | None = None
    opening_balance: float | None = None

class StoreReorderItem(BaseModel):
    id: int
    sort_order: int


class StoreReorderBody(BaseModel):
    stores: list[StoreReorderItem]



def _validate_store_offers(
    offer_type: str,
    offer_buy: int,
    offer_min_qty: int,
) -> None:
    ot = (offer_type or "none").lower()
    if ot in ("flat", "flat_carry", "bundle") and offer_buy <= 0:
        raise HTTPException(400, "offer_buy must be greater than 0 for flat/flat_carry/bundle offers")
    if ot == "threshold" and offer_min_qty <= 0:
        raise HTTPException(400, "offer_min_qty must be greater than 0 for threshold offers")


def _store_net_units_before(
    db: Session,
    store_id: int,
    exclude_entry_id: int | None = None,
) -> int:
    q = db.query(Entry).filter(Entry.store_id == store_id, Entry.is_closed == False)  # noqa: E712
    if exclude_entry_id is not None:
        q = q.filter(Entry.id != exclude_entry_id)
    net = 0
    for e in q.all():
        net += int(e.delivered or 0) - int(e.returned or 0)
    return max(0, net)


@app.post("/stores")
def create_store(store: StoreCreate, db: Session = Depends(get_db)):
    _validate_store_offers(store.offer_type, store.offer_buy, store.offer_min_qty)

    name_stripped = (store.name or "").strip()
    if not name_stripped:
        raise HTTPException(400, "Store name cannot be empty")

    dup = _store_name_conflict(db, name_stripped, None)
    if dup:
        raise HTTPException(
            409,
            f'A store named "{dup.name}" already exists (on route ID {dup.route_id}). '
            "Store names must be unique across all routes.",
        )

    ob = float(store.opening_balance or 0)
    if ob < 0:
        raise HTTPException(400, "opening_balance cannot be negative")

    try:
        s = Store(
            name=name_stripped,
            area=store.area,
            price=store.price,
            route_id=store.route_id,
            offer_type=store.offer_type,
            offer_buy=store.offer_buy,
            offer_get=store.offer_get,
            offer_min_qty=store.offer_min_qty,
            bundle_price=store.bundle_price,
            photo_url=store.photo_url,
            location_url=store.location_url,
            notes=store.notes,
            opening_balance=ob,
        )

        db.add(s)
        db.commit()
        db.refresh(s)

        return {
            "id": s.id,
            "name": s.name,
            "recent": True
        }

    except Exception as e:
        raise HTTPException(500, str(e))


def _entry_balance_due(e: Entry) -> float:
    if e.is_closed:
        return 0.0
    return float(e.balance or 0)


@app.get("/stores/{route_id}")
def get_stores(
    route_id: int,
    include_inactive: bool = Query(False),
    db: Session = Depends(get_db),
):
    today = business_today()

    q = db.query(Store).filter(Store.route_id == route_id)
    if not include_inactive:
        q = q.filter(or_(Store.is_active == True, Store.is_active.is_(None)))
    stores = q.order_by(Store.sort_order.asc(), Store.id.asc()).all()

    store_ids = [s.id for s in stores]
    entries_by_store: dict[int, list[Entry]] = defaultdict(list)
    if store_ids:
        for e in db.query(Entry).filter(Entry.store_id.in_(store_ids)).all():
            entries_by_store[e.store_id].append(e)

    entered_today_ids: set[int] = set()
    if store_ids:
        for (sid,) in (
            db.query(Entry.store_id)
            .filter(Entry.date == today, Entry.store_id.in_(store_ids))
            .distinct()
        ):
            entered_today_ids.add(sid)

    result = []
    for s in stores:
        store_ob = float(getattr(s, "opening_balance", None) or 0)
        outstanding = store_ob + sum(_entry_balance_due(e) for e in entries_by_store[s.id])

        result.append({
            "id": s.id,
            "name": s.name,
            "price": s.price,
            "entered_today": s.id in entered_today_ids,
            "is_active": True if s.is_active is None else bool(s.is_active),
            "outstanding": round(outstanding, 2),
            "sort_order": int(getattr(s, "sort_order", 0) or 0),
        })

    return result


@app.patch("/store/{store_id}")
def patch_store(store_id: int, body: StoreUpdate, db: Session = Depends(get_db)):
    s = db.query(Store).filter(Store.id == store_id).first()
    if not s:
        raise HTTPException(404, "Store not found")

    data = body.model_dump(exclude_unset=True)
    if "name" in data and data["name"] is not None:
        nm = str(data["name"]).strip()
        if not nm:
            raise HTTPException(400, "Store name cannot be empty")
        dup_n = _store_name_conflict(db, nm, store_id)
        if dup_n:
            raise HTTPException(
                409,
                f'Another store is already named "{dup_n.name}" (route ID {dup_n.route_id}). '
                "Store names must be unique across all routes.",
            )
        data["name"] = nm
    if "opening_balance" in data and data["opening_balance"] is not None:
        if float(data["opening_balance"]) < 0:
            raise HTTPException(400, "opening_balance cannot be negative")
        data["opening_balance"] = float(data["opening_balance"])
    for k, v in data.items():
        setattr(s, k, v)
    _validate_store_offers(s.offer_type, int(s.offer_buy or 0), int(s.offer_min_qty or 0))
    db.commit()
    db.refresh(s)

    return {
        "id": s.id,
        "name": s.name,
        "area": s.area,
        "price": s.price,
        "offer_type": s.offer_type,
        "offer_buy": s.offer_buy,
        "offer_get": s.offer_get,
        "offer_min_qty": s.offer_min_qty,
        "bundle_price": s.bundle_price,
        "is_active": True if s.is_active is None else bool(s.is_active),
        "photo_url": s.photo_url,
        "location_url": s.location_url,
        "notes": s.notes,
        "route_id": s.route_id,
        "opening_balance": round(float(getattr(s, "opening_balance", None) or 0), 2),
    }


@app.patch("/admin/stores/reorder")
def admin_reorder_stores(
    body: StoreReorderBody,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_admin(request, None)

    if not body.stores:
        return {"ok": True, "updated": 0}

    ids = [int(item.id) for item in body.stores]
    rows = db.query(Store).filter(Store.id.in_(ids)).all()
    store_map = {int(s.id): s for s in rows}

    updated = 0
    for item in body.stores:
        s = store_map.get(int(item.id))
        if not s:
            continue
        s.sort_order = int(item.sort_order)
        updated += 1

    db.commit()

    return {"ok": True, "updated": updated}


@app.delete("/admin/stores/{store_id}")
def admin_delete_store(store_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    s = db.query(Store).filter(Store.id == store_id).first()
    if not s:
        raise HTTPException(404, "Store not found")
    db.query(Entry).filter(Entry.store_id == store_id).delete(synchronize_session=False)
    db.query(Store).filter(Store.id == store_id).delete()
    db.commit()
    return {"ok": True, "deleted_id": store_id}


@app.post("/upload/store-photo")
def upload_store_photo(file: UploadFile = File(...)):
    allowed = {".jpg", ".jpeg", ".png", ".webp"}
    ext = Path(file.filename or "").suffix.lower()
    if ext not in allowed:
        ext = ".jpg"
    name = f"{uuid.uuid4().hex}{ext}"
    dest = UPLOAD_DIR / name
    with open(dest, "wb") as out:
        shutil.copyfileobj(file.file, out)
    return {"photo_url": f"/static/{name}"}


# ---------------- STORE INFO ----------------
@app.get("/store/{store_id}")
def get_store(store_id: int, db: Session = Depends(get_db)):
    s = db.query(Store).filter(Store.id == store_id).first()
    if not s:
        raise HTTPException(404, "Store not found")

    return {
        "id": s.id,
        "name": s.name,
        "area": s.area,
        "price": s.price,
        "offer_type": s.offer_type,
        "offer_buy": s.offer_buy,
        "offer_get": s.offer_get,
        "offer_min_qty": s.offer_min_qty,
        "bundle_price": s.bundle_price,
        "photo_url": s.photo_url,
        "location_url": s.location_url or None,
        "notes": s.notes,
        "is_active": True if s.is_active is None else bool(s.is_active),
        "route_id": s.route_id,
        "opening_balance": round(float(getattr(s, "opening_balance", None) or 0), 2),
    }


# ---------------- IMPORT ----------------
def _normalize_store_import_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Match Excel headers to API keys: trim, lowercase, hyphens → underscores."""
    out = df.copy()
    out.columns = [str(c).strip().lower().replace("-", "_") for c in out.columns]
    return out


@app.post("/import/stores")
def import_stores(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    _require_admin(request, None)

    try:
        raw = file.file.read()
        if not raw:
            raise HTTPException(400, "Empty file upload.")
        # Reading from SpooledTemporaryFile directly often breaks openpyxl; buffer is reliable (mobile + curl).
        df = pd.read_excel(io.BytesIO(raw), engine="openpyxl")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Could not read Excel file: {e}") from e

    df = _normalize_store_import_columns(df)

    parsed_fn = _parse_route_from_upload_filename(file.filename)
    file_default_route_code: int | None = None
    if parsed_fn:
        fn_code, fn_name = parsed_fn
        route_for_file = db.query(Route).filter(Route.route_code == fn_code).first()
        if not route_for_file:
            raise HTTPException(
                400,
                f'No route with ID {fn_code}. Create it in admin with name matching the file '
                f'(expected from file name: "{fn_name}").',
            )
        if (route_for_file.name or "").strip().lower() != fn_name.strip().lower():
            raise HTTPException(
                400,
                f'File name says route "{fn_name}" (ID {fn_code}), but that ID is named '
                f'"{route_for_file.name}" in the database. Fix the file name or the route in admin.',
            )
        file_default_route_code = fn_code

    required = {"name", "price"}
    missing = required - set(df.columns)
    if missing:
        raise HTTPException(
            400,
            f"Missing required column(s): {', '.join(sorted(missing))}. "
            f"Found columns: {', '.join(map(str, df.columns))}. "
            "Use: name, area, price, route_id, offer_type, offer_buy, offer_get, offer_min_qty (or offer_min-qty), bundle_price, opening_balance (optional). "
            "Column route_id is the business route ID (same as in admin). If the Excel file is named like "
            "\"Route 1 – My Route Name.xlsx\", route_id may be omitted and rows use that route.",
        )
    if "route_id" not in df.columns and file_default_route_code is None:
        raise HTTPException(
            400,
            "Missing column route_id. Add a route_id column (business route ID), or name the file "
            'like "Route 1 – My route name.xlsx" so it matches an existing route.',
        )

    count = 0
    import_seen: set[str] = set()

    for idx, row in df.iterrows():
        row_num = int(idx) + 2  # 1-based sheet row (header is row 1)
        try:
            ot = str(row.get("offer_type", "none") or "none")
            ob = int(row.get("offer_buy", 0) or 0)
            om = int(row.get("offer_min_qty", 0) or 0)
            _validate_store_offers(ot, ob, om)

            ob_imp = float(row.get("opening_balance", 0) or 0)
            if ob_imp < 0:
                ob_imp = 0.0
            nm = row["name"]
            if pd.isna(nm) or str(nm).strip() == "":
                continue
            raw_rid = row["route_id"] if "route_id" in df.columns else None
            if raw_rid is None or (isinstance(raw_rid, float) and pd.isna(raw_rid)) or str(raw_rid).strip() == "":
                if file_default_route_code is None:
                    raise HTTPException(400, f"Excel row {row_num}: route_id is required.")
                route_code_val = file_default_route_code
            else:
                try:
                    route_code_val = int(float(raw_rid))
                except (TypeError, ValueError) as e:
                    raise HTTPException(400, f"Excel row {row_num}: invalid route_id — {e}") from e
            if file_default_route_code is not None and route_code_val != file_default_route_code:
                raise HTTPException(
                    400,
                    f"Excel row {row_num}: route_id must be {file_default_route_code} "
                    f"(from the file name \"Route {file_default_route_code} – …\").",
                )

            internal_route_id = _resolve_internal_route_id_from_code(db, route_code_val)

            name_clean = str(nm).strip()
            seen_key = name_clean.lower()
            if seen_key in import_seen:
                raise HTTPException(
                    400,
                    f'Excel row {row_num}: duplicate store name "{name_clean}" in this file.',
                )
            import_seen.add(seen_key)

            dup_imp = _store_name_conflict(db, name_clean, None)
            if dup_imp:
                raise HTTPException(
                    400,
                    f'Excel row {row_num}: store "{name_clean}" already exists '
                    f'(id {dup_imp.id}, route {dup_imp.route_id}). Store names must be unique across all routes.',
                )

            ar = row.get("area")
            area_out = None if ar is None or pd.isna(ar) else str(ar).strip() or None
            store = Store(
                name=name_clean,
                area=area_out,
                price=float(row["price"]),
                route_id=internal_route_id,
                offer_type=ot,
                offer_buy=ob,
                offer_get=int(row.get("offer_get", 0) or 0),
                offer_min_qty=om,
                bundle_price=float(row.get("bundle_price", 0) or 0),
                opening_balance=ob_imp,
            )

            db.add(store)
            count += 1
        except HTTPException as e:
            d = e.detail
            msg = d if isinstance(d, str) else str(d)
            raise HTTPException(e.status_code, f"Excel row {row_num}: {msg}") from e
        except KeyError as e:
            raise HTTPException(400, f"Excel row {row_num}: missing column value {e}") from e
        except (TypeError, ValueError) as e:
            raise HTTPException(400, f"Excel row {row_num}: invalid number — {e}") from e

    db.commit()

    return {"message": f"{count} stores imported"}


# ---------------- ENTRY ----------------
class EntryCreate(BaseModel):
    store_id: int
    route_id: int
    delivered: int = 0
    returned: int = 0
    amount_collected: float = 0
    collected_cash: float = 0
    collected_upi: float = 0
    payment_mode: str = "cash"
    upi_received: bool = False
    is_closed: bool = False
    entry_id: int | None = None


def _payment_mode_label(cc: float, cu: float) -> str:
    if cc > 0 and cu > 0:
        return "mixed"
    if cu > 0:
        return "upi"
    if cc > 0:
        return "cash"
    return "cash"


def _payment_label(cc: float, cu: float) -> str:
    parts = []
    if cc > 0:
        parts.append(f"Cash ₹{cc:.0f}")
    if cu > 0:
        parts.append(f"UPI ₹{cu:.0f}")
    return " · ".join(parts) if parts else "—"


def _compute_totals(
    db: Session,
    store: Store,
    delivered: int,
    returned: int,
    entry: EntryCreate,
    exclude_entry_id: int | None = None,
):
    ot = (store.offer_type or "none").lower()
    if ot in ("flat", "flat_carry", "bundle") and store.offer_buy <= 0:
        raise HTTPException(400, "Store offer_buy must be > 0 for this offer type")

    if ot == "flat":
        free = (delivered // store.offer_buy) * store.offer_get
        billable = delivered - free
        total = billable * store.price

    elif ot == "flat_carry":
        cycle = int(store.offer_buy or 0) + int(store.offer_get or 0)
        if cycle <= 0:
            raise HTTPException(400, "For flat_carry, offer_buy + offer_get must be > 0")
        net_before = _store_net_units_before(db, int(store.id), exclude_entry_id)
        net_now = max(0, int(delivered or 0) - int(returned or 0))
        net_after = net_before + net_now

        free_before = (net_before // cycle) * int(store.offer_get or 0)
        free_after = (net_after // cycle) * int(store.offer_get or 0)
        bill_before = net_before - free_before
        bill_after = net_after - free_after

        free = max(0, free_after - free_before)
        billable = max(0, bill_after - bill_before)
        total = billable * store.price

    elif ot == "threshold":
        free = store.offer_get if delivered >= store.offer_min_qty else 0
        billable = delivered - free
        total = billable * store.price

    elif ot == "bundle":
        bundle = delivered // store.offer_buy
        rem = delivered % store.offer_buy
        total = bundle * store.bundle_price + rem * store.price
        free = 0
        billable = delivered

    else:
        free = 0
        billable = delivered
        total = billable * store.price

    cc = float(entry.collected_cash or 0)
    cu = float(entry.collected_upi or 0)
    legacy_amt = float(entry.amount_collected or 0)

    if cc == 0 and cu == 0 and legacy_amt > 0:
        pm = (entry.payment_mode or "cash").lower()
        if pm == "upi":
            if not entry.upi_received:
                cu = 0.0
            else:
                cu = legacy_amt
        else:
            cc = legacy_amt
    elif cu > 0 and not entry.upi_received:
        raise HTTPException(
            400,
            "Turn on UPI received before saving a UPI amount, or set UPI to 0.",
        )

    if cc < 0 or cu < 0:
        raise HTTPException(400, "Collected amounts cannot be negative.")

    collected = cc + cu
    mode = _payment_mode_label(cc, cu)
    balance = total - collected
    return free, billable, total, mode, collected, balance, cc, cu


def _entry_cash_upi(e: Entry) -> tuple[float, float]:
    cc = float(e.collected_cash or 0)
    cu = float(e.collected_upi or 0)
    if cc == 0 and cu == 0:
        amt = float(e.amount_collected or 0)
        if amt > 0:
            pm = (e.payment_mode or "cash").lower()
            if pm == "upi":
                cu = amt
            else:
                cc = amt
    return cc, cu


def _today_entry_json(e: Entry) -> dict:
    cc, cu = _entry_cash_upi(e)
    editable = _is_within_edit_window(e)
    remaining_sec = 0
    if editable and e.created_at is not None:
        now = datetime.now(_IST).replace(tzinfo=None)
        remaining_sec = max(0, int(_EDIT_WINDOW_MINUTES * 60 - (now - e.created_at).total_seconds()))
    return {
        "id": e.id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "delivered": e.delivered,
        "returned": e.returned,
        "collected_cash": cc,
        "collected_upi": cu,
        "amount_collected": float(e.amount_collected or 0),
        "total_amount": float(e.total_amount or 0),
        "balance": float(e.balance or 0),
        "payment_mode": e.payment_mode,
        "upi_received": bool(e.upi_received),
        "is_closed": bool(e.is_closed),
        "editable": editable,
        "edit_remaining_sec": remaining_sec,
    }


@app.get("/entries/today/{store_id}")
def get_today_entries(store_id: int, db: Session = Depends(get_db)):
    today = business_today()
    rows = (
        db.query(Entry)
        .filter(Entry.store_id == store_id, Entry.date == today)
        .order_by(Entry.id.asc())
        .all()
    )
    return {"entries": [_today_entry_json(e) for e in rows]}


@app.post("/entries")
def create_entry(entry: EntryCreate, db: Session = Depends(get_db)):

    store = db.query(Store).filter(Store.id == entry.store_id).first()
    if not store:
        raise HTTPException(404, "Store not found")

    if store.route_id != entry.route_id:
        raise HTTPException(400, "Store does not belong to this route")

    if store.is_active is False:
        raise HTTPException(400, "This store is inactive. Activate it before adding entries.")

    today = business_today()

    if entry.entry_id is not None and entry.is_closed:
        raise HTTPException(400, "Do not send entry_id when marking closed.")

    if entry.is_closed:
        closed_today = db.query(Entry).filter(
            Entry.store_id == entry.store_id,
            Entry.date == today,
            Entry.is_closed == True,
        ).first()
        if closed_today:
            closed_today.route_id = entry.route_id
            closed_today.delivered = 0
            closed_today.returned = 0
            closed_today.free = 0
            closed_today.billable = 0
            closed_today.total_amount = 0.0
            closed_today.amount_collected = 0.0
            closed_today.collected_cash = 0.0
            closed_today.collected_upi = 0.0
            closed_today.payment_mode = entry.payment_mode.lower()
            closed_today.upi_received = False
            closed_today.balance = 0.0
        else:
            db.add(
                Entry(
                    store_id=entry.store_id,
                    route_id=entry.route_id,
                    is_closed=True,
                    delivered=0,
                    returned=0,
                    free=0,
                    billable=0,
                    total_amount=0.0,
                    amount_collected=0.0,
                    collected_cash=0.0,
                    collected_upi=0.0,
                    payment_mode=entry.payment_mode.lower(),
                    upi_received=False,
                    balance=0.0,
                )
            )
        db.commit()
        row = (
            closed_today
            if closed_today
            else db.query(Entry)
            .filter(Entry.store_id == entry.store_id, Entry.date == today, Entry.is_closed == True)
            .order_by(Entry.id.desc())
            .first()
        )
        return {
            "message": "Store closed",
            "total": 0.0,
            "collected": 0.0,
            "balance": 0.0,
            "warning": None,
            "entry_id": row.id if row else None,
        }

    delivered = entry.delivered
    free, billable, total, mode, collected, balance, cc, cu = _compute_totals(
        db, store, delivered, entry.returned, entry, entry.entry_id
    )

    if entry.entry_id is not None:
        existing = db.query(Entry).filter(Entry.id == entry.entry_id).first()
        if not existing:
            raise HTTPException(404, "Entry not found")
        if existing.store_id != entry.store_id:
            raise HTTPException(400, "Entry does not belong to this store")
        if existing.route_id != entry.route_id:
            raise HTTPException(400, "Store does not belong to this route")
        if existing.is_closed:
            raise HTTPException(400, "Cannot edit a closed entry as a sale")
        if existing.date != today:
            raise HTTPException(400, "Only today's entries can be edited")
        if not _is_within_edit_window(existing):
            raise HTTPException(
                403,
                f"Edit window expired. Entries can only be edited within "
                f"{_EDIT_WINDOW_MINUTES} minutes of creation. Contact admin.",
            )

        before = _snapshot_entry_fields(existing)

        existing.is_closed = False
        existing.route_id = entry.route_id
        existing.delivered = entry.delivered
        existing.returned = entry.returned
        existing.free = free
        existing.billable = billable
        existing.total_amount = total
        existing.amount_collected = collected
        existing.collected_cash = cc
        existing.collected_upi = cu
        existing.payment_mode = mode
        existing.upi_received = entry.upi_received
        existing.balance = balance
        existing.updated_at = datetime.now(_IST).replace(tzinfo=None)

        after = _snapshot_entry_fields(existing)
        changes = _diff_snapshots(before, after)
        if changes:
            _write_audit_rows(db, existing, changes, "staff")

        db.commit()
        return {
            "total": total,
            "collected": collected,
            "balance": balance,
            "warning": None,
            "entry_id": existing.id,
        }

    row = Entry(
        store_id=entry.store_id,
        route_id=entry.route_id,
        delivered=entry.delivered,
        returned=entry.returned,
        free=free,
        billable=billable,
        total_amount=total,
        amount_collected=collected,
        collected_cash=cc,
        collected_upi=cu,
        payment_mode=mode,
        upi_received=entry.upi_received,
        balance=balance,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {
        "total": total,
        "collected": collected,
        "balance": balance,
        "warning": None,
        "entry_id": row.id,
    }


# ---------------- ADMIN ENTRY EDIT ----------------
class AdminEntryUpdate(BaseModel):
    delivered: int | None = None
    returned: int | None = None
    collected_cash: float | None = None
    collected_upi: float | None = None
    upi_received: bool | None = None
    is_closed: bool | None = None


@app.get("/admin/entries")
def admin_list_entries(
    request: Request,
    route_id: int | None = Query(None),
    store_id: int | None = Query(None),
    entry_date: str | None = Query(None, description="YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    q = db.query(Entry)
    if route_id is not None:
        q = q.filter(Entry.route_id == route_id)
    if store_id is not None:
        q = q.filter(Entry.store_id == store_id)
    if entry_date is not None:
        d = _parse_ymd(entry_date, "entry_date")
        q = q.filter(Entry.date == d)
    entries = q.order_by(Entry.date.desc(), Entry.id.desc()).limit(100).all()

    store_ids = sorted({int(e.store_id) for e in entries if e.store_id})
    stores_map = {s.id: s for s in db.query(Store).filter(Store.id.in_(store_ids)).all()} if store_ids else {}
    route_ids = sorted({int(e.route_id) for e in entries if e.route_id})
    routes_map = {r.id: r for r in db.query(Route).filter(Route.id.in_(route_ids)).all()} if route_ids else {}

    result = []
    for e in entries:
        cc, cu = _entry_cash_upi(e)
        s = stores_map.get(int(e.store_id)) if e.store_id else None
        r = routes_map.get(int(e.route_id)) if e.route_id else None
        result.append({
            "id": e.id,
            "date": e.date.strftime("%Y-%m-%d") if e.date else None,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "store_id": e.store_id,
            "store_name": s.name if s else "?",
            "route_id": e.route_id,
            "route_code": r.route_code if r else None,
            "route_name": r.name if r else "?",
            "delivered": e.delivered,
            "returned": e.returned,
            "free": e.free,
            "billable": e.billable,
            "total_amount": float(e.total_amount or 0),
            "collected_cash": cc,
            "collected_upi": cu,
            "amount_collected": float(e.amount_collected or 0),
            "balance": float(e.balance or 0),
            "payment_mode": e.payment_mode,
            "upi_received": bool(e.upi_received),
            "is_closed": bool(e.is_closed),
        })
    return {"entries": result}


@app.get("/admin/entries/{entry_id}")
def admin_get_entry(entry_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    e = db.query(Entry).filter(Entry.id == entry_id).first()
    if not e:
        raise HTTPException(404, "Entry not found")
    s = db.query(Store).filter(Store.id == e.store_id).first()
    r = db.query(Route).filter(Route.id == e.route_id).first()
    cc, cu = _entry_cash_upi(e)
    return {
        "id": e.id,
        "date": e.date.strftime("%Y-%m-%d") if e.date else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "store_id": e.store_id,
        "store_name": s.name if s else "?",
        "route_id": e.route_id,
        "route_code": r.route_code if r else None,
        "route_name": r.name if r else "?",
        "delivered": e.delivered,
        "returned": e.returned,
        "free": e.free,
        "billable": e.billable,
        "total_amount": float(e.total_amount or 0),
        "collected_cash": cc,
        "collected_upi": cu,
        "amount_collected": float(e.amount_collected or 0),
        "balance": float(e.balance or 0),
        "payment_mode": e.payment_mode,
        "upi_received": bool(e.upi_received),
        "is_closed": bool(e.is_closed),
    }


@app.patch("/admin/entries/{entry_id}")
def admin_patch_entry(
    entry_id: int,
    body: AdminEntryUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    existing = db.query(Entry).filter(Entry.id == entry_id).first()
    if not existing:
        raise HTTPException(404, "Entry not found")

    store = db.query(Store).filter(Store.id == existing.store_id).first()
    if not store:
        raise HTTPException(404, "Store linked to this entry no longer exists")

    before = _snapshot_entry_fields(existing)
    want_closed = body.is_closed if body.is_closed is not None else bool(existing.is_closed)

    if want_closed:
        existing.is_closed = True
        existing.delivered = 0
        existing.returned = 0
        existing.free = 0
        existing.billable = 0
        existing.total_amount = 0.0
        existing.amount_collected = 0.0
        existing.collected_cash = 0.0
        existing.collected_upi = 0.0
        existing.balance = 0.0
        existing.upi_received = False
        existing.updated_at = datetime.now(_IST).replace(tzinfo=None)

        after = _snapshot_entry_fields(existing)
        changes = _diff_snapshots(before, after)
        if changes:
            _write_audit_rows(db, existing, changes, "admin")

        db.commit()
        db.refresh(existing)
        cc, cu = _entry_cash_upi(existing)
        return {
            "id": existing.id,
            "date": existing.date.strftime("%Y-%m-%d") if existing.date else None,
            "delivered": existing.delivered,
            "returned": existing.returned,
            "total_amount": 0.0,
            "collected_cash": cc,
            "collected_upi": cu,
            "balance": 0.0,
            "is_closed": True,
        }

    delivered = body.delivered if body.delivered is not None else int(existing.delivered or 0)
    returned = body.returned if body.returned is not None else int(existing.returned or 0)
    cc_in = body.collected_cash if body.collected_cash is not None else float(existing.collected_cash or 0)
    cu_in = body.collected_upi if body.collected_upi is not None else float(existing.collected_upi or 0)
    upi_recv = body.upi_received if body.upi_received is not None else bool(existing.upi_received)

    if cc_in < 0 or cu_in < 0:
        raise HTTPException(400, "Collected amounts cannot be negative")

    proxy = EntryCreate(
        store_id=int(existing.store_id),
        route_id=int(existing.route_id),
        delivered=delivered,
        returned=returned,
        collected_cash=cc_in,
        collected_upi=cu_in,
        upi_received=upi_recv,
    )
    free, billable, total, mode, collected, balance, cc, cu = _compute_totals(
        db, store, delivered, returned, proxy, entry_id
    )

    existing.is_closed = False
    existing.delivered = delivered
    existing.returned = returned
    existing.free = free
    existing.billable = billable
    existing.total_amount = total
    existing.amount_collected = collected
    existing.collected_cash = cc
    existing.collected_upi = cu
    existing.payment_mode = mode
    existing.upi_received = upi_recv
    existing.balance = balance
    existing.updated_at = datetime.now(_IST).replace(tzinfo=None)

    after = _snapshot_entry_fields(existing)
    changes = _diff_snapshots(before, after)
    if changes:
        _write_audit_rows(db, existing, changes, "admin")

    db.commit()
    db.refresh(existing)

    return {
        "id": existing.id,
        "date": existing.date.strftime("%Y-%m-%d") if existing.date else None,
        "delivered": existing.delivered,
        "returned": existing.returned,
        "total_amount": float(existing.total_amount or 0),
        "collected_cash": float(existing.collected_cash or 0),
        "collected_upi": float(existing.collected_upi or 0),
        "balance": float(existing.balance or 0),
        "is_closed": bool(existing.is_closed),
    }


@app.delete("/admin/entries/{entry_id}")
def admin_delete_entry(entry_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    existing = db.query(Entry).filter(Entry.id == entry_id).first()
    if not existing:
        raise HTTPException(404, "Entry not found")
    db.query(Entry).filter(Entry.id == entry_id).delete()
    db.commit()
    return {"ok": True, "deleted_id": entry_id}


@app.get("/admin/entries/{entry_id}/audit")
def admin_entry_audit(entry_id: int, request: Request, db: Session = Depends(get_db)):
    _require_admin(request, None)
    existing = db.query(Entry).filter(Entry.id == entry_id).first()
    if not existing:
        raise HTTPException(404, "Entry not found")
    rows = (
        db.query(EntryAuditLog)
        .filter(EntryAuditLog.entry_id == entry_id)
        .order_by(EntryAuditLog.edited_at.desc(), EntryAuditLog.id.desc())
        .all()
    )
    return {
        "entry_id": entry_id,
        "audit": [
            {
                "id": r.id,
                "field": r.field_name,
                "old_value": r.old_value,
                "new_value": r.new_value,
                "edited_by": r.edited_by,
                "edited_at": r.edited_at.isoformat() if r.edited_at else None,
            }
            for r in rows
        ],
    }


# ---------------- REPORT (today) ----------------
def _pdf_cell_text(value: object, max_len: int = 60) -> str:
    """FPDF core fonts only support Latin-1; strip/replace other chars to avoid HTTP 500."""
    s = "" if value is None else str(value)
    s = s[:max_len]
    return s.encode("latin-1", errors="replace").decode("latin-1")


def _report_pdf_date(d: date) -> str:
    """dd-mon-yyyy with lowercase English month abbrev (e.g. 07-apr-2026)."""
    mon = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
    return f"{d.day:02d}-{mon[d.month - 1]}-{d.year}"


@app.get("/report/today")
def report_today(
    route_id: int = Query(..., description="Logged-in route only"),
    db: Session = Depends(get_db),
):
    today = business_today()
    q = db.query(Entry).filter(Entry.date == today, Entry.route_id == route_id)
    entries = q.all()

    total_sold = sum(int(e.delivered or 0) for e in entries)

    cash = sum(_entry_cash_upi(e)[0] for e in entries)
    upi = sum(_entry_cash_upi(e)[1] for e in entries)
    balance = sum(float(e.balance or 0) for e in entries)
    returns = sum(int(e.returned or 0) for e in entries)

    stores_out = []
    for e in entries:
        s = db.query(Store).filter(Store.id == e.store_id).first()
        stores_out.append({
            "name": s.name if s else "?",
            "delivered": int(e.delivered or 0),
            "returned": int(e.returned or 0),
            "collected": float(e.amount_collected or 0),
            "balance": float(e.balance or 0),
            "is_closed": e.is_closed,
        })

    return {
        "summary": {
            "total_sold": total_sold,
            "cash": cash,
            "upi": upi,
            "balance": balance,
            "returns": returns,
        },
        "stores": stores_out,
    }


@app.get("/report/today/pdf")
def report_today_pdf(
    route_id: int = Query(...),
    db: Session = Depends(get_db),
):
    payload = report_today(route_id=route_id, db=db)
    summary = payload["summary"]
    stores_rows = payload["stores"]

    route = db.query(Route).filter(Route.id == route_id).first()
    if route and route.route_code is not None:
        report_title = f"Route {route.route_code} - {route.name} daily report - {_report_pdf_date(business_today())}"
    elif route:
        report_title = f"{route.name} daily report - {_report_pdf_date(business_today())}"
    else:
        report_title = f"Route (id {route_id}) daily report - {_report_pdf_date(business_today())}"

    ts = int(summary["total_sold"])
    cash = float(summary["cash"])
    upi = float(summary["upi"])
    bal_sum = float(summary["balance"])
    ret = int(summary["returns"])

    total_del = sum(int(r["delivered"]) for r in stores_rows)
    total_ret = sum(int(r["returned"]) for r in stores_rows)
    total_col = sum(float(r["collected"]) for r in stores_rows)
    total_bal = sum(float(r["balance"]) for r in stores_rows)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, _pdf_cell_text(report_title, 120), ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(
        0,
        8,
        _pdf_cell_text(f"Total sold: {ts}  |  Cash: {cash:.2f}  |  UPI: {upi:.2f}"),
        ln=True,
    )
    pdf.cell(
        0,
        8,
        _pdf_cell_text(f"Balance: {bal_sum:.2f}  |  Returns: {ret}  |  Route: {route.route_code if route and route.route_code is not None else route_id}"),
        ln=True,
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(60, 8, "Store", border=1)
    pdf.cell(25, 8, "Del", border=1)
    pdf.cell(25, 8, "Ret", border=1)
    pdf.cell(35, 8, "Collected", border=1)
    pdf.cell(35, 8, "Balance", border=1, ln=True)
    pdf.set_font("Helvetica", "", 10)
    for row in stores_rows:
        pdf.cell(60, 8, _pdf_cell_text(row["name"], 28), border=1)
        pdf.cell(25, 8, _pdf_cell_text(row["delivered"]), border=1)
        pdf.cell(25, 8, _pdf_cell_text(row["returned"]), border=1)
        pdf.cell(35, 8, _pdf_cell_text(f"{float(row['collected']):.2f}"), border=1)
        pdf.cell(35, 8, _pdf_cell_text(f"{float(row['balance']):.2f}"), border=1, ln=True)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(60, 8, _pdf_cell_text("TOTAL"), border=1)
    pdf.cell(25, 8, _pdf_cell_text(total_del), border=1)
    pdf.cell(25, 8, _pdf_cell_text(total_ret), border=1)
    pdf.cell(35, 8, _pdf_cell_text(f"{total_col:.2f}"), border=1)
    pdf.cell(35, 8, _pdf_cell_text(f"{total_bal:.2f}"), border=1, ln=True)

    raw = pdf.output()
    if isinstance(raw, str):
        body: bytes = raw.encode("latin-1")
    else:
        body = bytes(raw)
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="route_sync-daily.pdf"'},
    )


def _parse_ymd(value: str, field: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as e:
        raise HTTPException(400, f"{field} must be YYYY-MM-DD") from e


def _admin_report_range_payload(
    db: Session,
    from_date: date,
    to_date: date,
    route_id: int | None,
) -> dict:
    if to_date < from_date:
        raise HTTPException(400, "to_date must be on or after from_date")

    selected_route: Route | None = None
    if route_id is not None:
        selected_route = db.query(Route).filter(Route.id == route_id).first()
        if not selected_route:
            raise HTTPException(404, "Route not found")

    q = db.query(Entry).filter(Entry.date >= from_date, Entry.date <= to_date)
    if route_id is not None:
        q = q.filter(Entry.route_id == route_id)
    entries = q.order_by(Entry.date.asc(), Entry.id.asc()).all()

    route_ids = sorted({int(e.route_id or 0) for e in entries if e.route_id is not None and int(e.route_id or 0) > 0})
    routes_map = {
        r.id: r
        for r in db.query(Route).filter(Route.id.in_(route_ids)).all()
    } if route_ids else {}

    store_ids = sorted({int(e.store_id or 0) for e in entries if e.store_id is not None and int(e.store_id or 0) > 0})
    stores_map = {
        s.id: s
        for s in db.query(Store).filter(Store.id.in_(store_ids)).all()
    } if store_ids else {}

    total_delivered = 0
    total_returns = 0
    total_cash = 0.0
    total_upi = 0.0
    total_collected = 0.0
    total_balance = 0.0

    agg: dict[int, dict] = {}
    for e in entries:
        rid = int(e.route_id or 0)
        sid = int(e.store_id or 0)
        d = int(e.delivered or 0)
        r = int(e.returned or 0)
        cc, cu = _entry_cash_upi(e)
        collected = float(cc + cu)
        bal = float(e.balance or 0)

        total_delivered += d
        total_returns += r
        total_cash += float(cc)
        total_upi += float(cu)
        total_collected += collected
        total_balance += bal

        if sid not in agg:
            route_row = routes_map.get(rid)
            store_row = stores_map.get(sid)
            agg[sid] = {
                "store_id": sid,
                "store_name": store_row.name if store_row else "?",
                "route_id": rid,
                "route_code": route_row.route_code if route_row else None,
                "route_name": route_row.name if route_row else f"Route {rid}",
                "delivered": 0,
                "returned": 0,
                "collected": 0.0,
                "balance": 0.0,
            }
        row = agg[sid]
        row["delivered"] += d
        row["returned"] += r
        row["collected"] += collected
        row["balance"] += bal

    stores_rows = list(agg.values())
    stores_rows.sort(key=lambda x: ((x.get("route_code") or 10**9), str(x.get("route_name") or ""), str(x.get("store_name") or "")))

    route_info = None
    if selected_route:
        route_info = {
            "id": selected_route.id,
            "route_code": selected_route.route_code,
            "name": selected_route.name,
        }

    return {
        "from_date": from_date.isoformat(),
        "to_date": to_date.isoformat(),
        "route": route_info,
        "summary": {
            "total_delivered": total_delivered,
            "total_returns": total_returns,
            "cash": round(total_cash, 2),
            "upi": round(total_upi, 2),
            "total_collected": round(total_collected, 2),
            "total_balance": round(total_balance, 2),
        },
        "stores": [
            {
                **row,
                "collected": round(float(row["collected"]), 2),
                "balance": round(float(row["balance"]), 2),
            }
            for row in stores_rows
        ],
    }


@app.get("/admin/report/range")
def admin_report_range(
    request: Request,
    from_date: str = Query(..., description="YYYY-MM-DD"),
    to_date: str = Query(..., description="YYYY-MM-DD"),
    route_id: int | None = Query(None, description="Optional internal route id filter"),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    fd = _parse_ymd(from_date, "from_date")
    td = _parse_ymd(to_date, "to_date")
    return _admin_report_range_payload(db, fd, td, route_id)


@app.get("/admin/report/range/pdf")
def admin_report_range_pdf(
    request: Request,
    from_date: str = Query(..., description="YYYY-MM-DD"),
    to_date: str = Query(..., description="YYYY-MM-DD"),
    route_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    fd = _parse_ymd(from_date, "from_date")
    td = _parse_ymd(to_date, "to_date")
    payload = _admin_report_range_payload(db, fd, td, route_id)
    summary = payload["summary"]
    rows = payload["stores"]
    route_info = payload["route"]

    route_label = (
        f'Route {route_info["route_code"]} - {route_info["name"]}'
        if route_info and route_info.get("route_code") is not None
        else (route_info["name"] if route_info else "All routes")
    )
    title = f"{route_label} report - {_report_pdf_date(fd)} to {_report_pdf_date(td)}"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, _pdf_cell_text(title, 120), ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(
        0,
        7,
        _pdf_cell_text(
            f"Delivered: {summary['total_delivered']}  |  Returns: {summary['total_returns']}  |  "
            f"Collected: {summary['total_collected']:.2f}  |  Balance: {summary['total_balance']:.2f}"
        ),
        ln=True,
    )
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(42, 8, "Route", border=1)
    pdf.cell(52, 8, "Store", border=1)
    pdf.cell(18, 8, "Del", border=1)
    pdf.cell(18, 8, "Ret", border=1)
    pdf.cell(30, 8, "Collected", border=1)
    pdf.cell(30, 8, "Balance", border=1, ln=True)
    pdf.set_font("Helvetica", "", 9)
    for row in rows:
        rlabel = (
            f'R{row["route_code"]} {row["route_name"]}'
            if row.get("route_code") is not None
            else str(row.get("route_name") or "")
        )
        pdf.cell(42, 8, _pdf_cell_text(rlabel, 22), border=1)
        pdf.cell(52, 8, _pdf_cell_text(row["store_name"], 28), border=1)
        pdf.cell(18, 8, _pdf_cell_text(row["delivered"]), border=1)
        pdf.cell(18, 8, _pdf_cell_text(row["returned"]), border=1)
        pdf.cell(30, 8, _pdf_cell_text(f'{float(row["collected"]):.2f}'), border=1)
        pdf.cell(30, 8, _pdf_cell_text(f'{float(row["balance"]):.2f}'), border=1, ln=True)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(94, 8, "TOTAL", border=1)
    pdf.cell(18, 8, _pdf_cell_text(summary["total_delivered"]), border=1)
    pdf.cell(18, 8, _pdf_cell_text(summary["total_returns"]), border=1)
    pdf.cell(30, 8, _pdf_cell_text(f'{float(summary["total_collected"]):.2f}'), border=1)
    pdf.cell(30, 8, _pdf_cell_text(f'{float(summary["total_balance"]):.2f}'), border=1, ln=True)

    raw = pdf.output()
    body = raw.encode("latin-1") if isinstance(raw, str) else bytes(raw)
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="admin-range-report.pdf"'},
    )


@app.get("/admin/report/range/csv")
def admin_report_range_csv(
    request: Request,
    from_date: str = Query(..., description="YYYY-MM-DD"),
    to_date: str = Query(..., description="YYYY-MM-DD"),
    route_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    fd = _parse_ymd(from_date, "from_date")
    td = _parse_ymd(to_date, "to_date")
    payload = _admin_report_range_payload(db, fd, td, route_id)
    rows = payload["stores"]
    summary = payload["summary"]

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["from_date", payload["from_date"], "to_date", payload["to_date"]])
    w.writerow([])
    w.writerow(["route_code", "route_name", "store_name", "delivered", "returned", "collected", "balance"])
    for r in rows:
        w.writerow([
            r.get("route_code") if r.get("route_code") is not None else "",
            r.get("route_name") or "",
            r.get("store_name") or "",
            r.get("delivered") or 0,
            r.get("returned") or 0,
            f'{float(r.get("collected") or 0):.2f}',
            f'{float(r.get("balance") or 0):.2f}',
        ])
    w.writerow([])
    w.writerow([
        "TOTAL",
        "",
        "",
        summary["total_delivered"],
        summary["total_returns"],
        f'{float(summary["total_collected"]):.2f}',
        f'{float(summary["total_balance"]):.2f}',
    ])

    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="admin-range-report.csv"'},
    )


# ---------------- SNAPSHOT ----------------
@app.get("/store/{store_id}/snapshot")
def snapshot(store_id: int, db: Session = Depends(get_db)):
    s = db.query(Store).filter(Store.id == store_id).first()
    if not s:
        raise HTTPException(404, "Store not found")

    entries = db.query(Entry).filter(Entry.store_id == store_id).all()

    store_ob = float(getattr(s, "opening_balance", None) or 0)
    outstanding = store_ob + sum(_entry_balance_due(e) for e in entries)

    yesterday = business_today() - timedelta(days=1)

    y_entries = db.query(Entry).filter(
        Entry.store_id == store_id,
        Entry.date == yesterday
    ).all()

    yesterday_packets = sum(e.delivered for e in y_entries)

    last_payment_entry = db.query(Entry).filter(
        Entry.store_id == store_id,
        Entry.amount_collected > 0
    ).order_by(Entry.id.desc()).first()

    last_payment = last_payment_entry.amount_collected if last_payment_entry else 0

    return {
        "outstanding": round(outstanding, 2),
        "opening_balance": round(store_ob, 2),
        "yesterday_packets": yesterday_packets,
        "last_payment": last_payment,
    }


# ---------------- LEDGER ----------------
@app.get("/ledger/{store_id}")
def ledger(
    store_id: int,
    from_date: str | None = Query(None),
    to_date: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Each row combines sales history (packets sold / returned) with money (bill, paid, running due).

    **balance_before** = total owed before this visit line; **running_balance** = after (cumulative).
    **line_due** = unpaid portion from this visit only. Returns are packet counts only (already in billing logic).
    """
    store = db.query(Store).filter(Store.id == store_id).first()
    if not store:
        raise HTTPException(404, "Store not found")
    store_ob = float(getattr(store, "opening_balance", None) or 0)

    all_rows = (
        db.query(Entry)
        .filter(Entry.store_id == store_id)
        .order_by(Entry.date.asc(), Entry.id.asc())
        .all()
    )

    total_outstanding = store_ob + sum(_entry_balance_due(e) for e in all_rows)

    fd: date | None = None
    td: date | None = None
    if from_date and to_date:
        try:
            fd = datetime.strptime(from_date, "%Y-%m-%d").date()
            td = datetime.strptime(to_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(400, "from_date and to_date must be YYYY-MM-DD")

    prior_entries_due = 0.0
    if fd is not None:
        prior_entries_due = sum(_entry_balance_due(e) for e in all_rows if e.date < fd)
    opening_balance = store_ob + prior_entries_due

    if fd is not None and td is not None:
        entries = [e for e in all_rows if fd <= e.date <= td]
    else:
        entries = list(all_rows)

    result = []
    running_balance = opening_balance

    for e in entries:
        if e.is_closed:
            debit = 0.0
            credit = 0.0
            line_due = 0.0
            cc = 0.0
            cu = 0.0
        else:
            debit = float(e.total_amount or 0)
            cc = float(e.collected_cash or 0)
            cu = float(e.collected_upi or 0)
            if cc == 0 and cu == 0:
                amt = float(e.amount_collected or 0)
                if amt > 0:
                    pm = (e.payment_mode or "cash").lower()
                    if pm == "upi":
                        cu = amt
                    else:
                        cc = amt
            credit = cc + cu
            line_due = _entry_balance_due(e)

        balance_before = round(running_balance, 2)
        running_balance += line_due
        balance_after = round(running_balance, 2)

        result.append({
            "id": e.id,
            "date": e.date.strftime("%Y-%m-%d"),
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "delivered": e.delivered,
            "returned": e.returned,
            "packets_sold": e.delivered,
            "packets_returned": e.returned,
            "debit": debit,
            "credit": credit,
            "bill_amount": round(debit, 2),
            "amount_paid": round(credit, 2),
            "collected": e.amount_collected,
            "collected_cash": cc,
            "collected_upi": cu,
            "payment_mode": (e.payment_mode or "") or "—",
            "payment_label": _payment_label(cc, cu),
            "line_due": round(line_due, 2),
            "balance": round(line_due, 2),
            "balance_before": balance_before,
            "balance_after": balance_after,
            "running_balance": balance_after,
            "is_closed": e.is_closed,
        })

    return {
        "summary": {
            "total_outstanding": round(total_outstanding, 2),
            "opening_balance": round(opening_balance, 2),
            "store_opening_balance": round(store_ob, 2),
        },
        "entries": result,
    }
    @app.get("/ledger/{store_id}/bill.pdf")
    def ledger_bill_pdf(
        store_id: int,
        from_date: str | None = Query(None),
        to_date: str | None = Query(None),
        db: Session = Depends(get_db),
    ):
        store = db.query(Store).filter(Store.id == store_id).first()
        if not store:
            raise HTTPException(404, "Store not found")
    
        payload = ledger(
            store_id=store_id,
            from_date=from_date,
            to_date=to_date,
            db=db,
        )
    
        summary = payload.get("summary", {})
        rows = payload.get("entries", [])
    
        route = db.query(Route).filter(Route.id == store.route_id).first()
    
        if from_date and to_date:
            period_label = f"{from_date} to {to_date}"
            file_period = f"{from_date}_to_{to_date}"
        else:
            period_label = "All history"
            file_period = "all_history"
    
        store_name = store.name or f"Store {store_id}"
        route_label = "Route"
        if route:
            if route.route_code is not None:
                route_label = f"Route {route.route_code} - {route.name}"
            else:
                route_label = route.name
    
        total_sold = 0
        total_returned = 0
        total_bill = 0.0
        total_paid = 0.0
        total_due = 0.0
    
        for row in rows:
            if row.get("is_closed"):
                continue
            total_sold += int(row.get("packets_sold") or row.get("delivered") or 0)
            total_returned += int(row.get("packets_returned") or row.get("returned") or 0)
            total_bill += float(row.get("bill_amount") or row.get("debit") or 0)
            total_paid += float(row.get("amount_paid") or row.get("credit") or 0)
            total_due += float(row.get("line_due") or row.get("balance") or 0)
    
        total_outstanding = float(summary.get("total_outstanding") or 0)
        opening_balance = float(summary.get("opening_balance") or 0)
    
        pdf = FPDF()
        pdf.add_page()
    
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 9, _pdf_cell_text("SRI MAHALAKSHMI HOME FOODS", 120), ln=True, align="C")
    
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, _pdf_cell_text("Idli Dosa Batter Supplier", 120), ln=True, align="C")
        pdf.cell(0, 6, _pdf_cell_text("Ledger Bill / Statement", 120), ln=True, align="C")
    
        pdf.ln(4)
    
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 7, _pdf_cell_text(f"Store: {store_name}", 120), ln=True)
    
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, _pdf_cell_text(f"Route: {route_label}", 120), ln=True)
        pdf.cell(0, 6, _pdf_cell_text(f"Period: {period_label}", 120), ln=True)
        pdf.cell(0, 6, _pdf_cell_text(f"Generated on: {_report_pdf_date(business_today())}", 120), ln=True)
    
        pdf.ln(3)
    
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(47, 8, _pdf_cell_text("Opening Balance", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text("Bill Amount", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text("Paid", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text("Outstanding", 30), border=1, ln=True)
    
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(47, 8, _pdf_cell_text(f"{opening_balance:.2f}", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text(f"{total_bill:.2f}", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text(f"{total_paid:.2f}", 30), border=1)
        pdf.cell(47, 8, _pdf_cell_text(f"{total_outstanding:.2f}", 30), border=1, ln=True)
    
        pdf.ln(5)
    
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, _pdf_cell_text("Sales Summary", 120), ln=True)
    
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, _pdf_cell_text(f"Total sold packets: {total_sold}", 120), ln=True)
        pdf.cell(0, 6, _pdf_cell_text(f"Total returned packets: {total_returned}", 120), ln=True)
        pdf.cell(0, 6, _pdf_cell_text(f"Total due from selected period: {total_due:.2f}", 120), ln=True)
    
        pdf.ln(4)
    
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(24, 8, "Date", border=1)
        pdf.cell(18, 8, "Sold", border=1)
        pdf.cell(18, 8, "Ret", border=1)
        pdf.cell(28, 8, "Bill", border=1)
        pdf.cell(28, 8, "Paid", border=1)
        pdf.cell(28, 8, "Due", border=1)
        pdf.cell(34, 8, "Balance", border=1, ln=True)
    
        pdf.set_font("Helvetica", "", 8)
    
        if not rows:
            pdf.cell(178, 8, _pdf_cell_text("No entries found for this period.", 120), border=1, ln=True)
        else:
            for row in rows:
                if pdf.get_y() > 270:
                    pdf.add_page()
                    pdf.set_font("Helvetica", "B", 9)
                    pdf.cell(24, 8, "Date", border=1)
                    pdf.cell(18, 8, "Sold", border=1)
                    pdf.cell(18, 8, "Ret", border=1)
                    pdf.cell(28, 8, "Bill", border=1)
                    pdf.cell(28, 8, "Paid", border=1)
                    pdf.cell(28, 8, "Due", border=1)
                    pdf.cell(34, 8, "Balance", border=1, ln=True)
                    pdf.set_font("Helvetica", "", 8)
    
                if row.get("is_closed"):
                    pdf.cell(24, 8, _pdf_cell_text(row.get("date", ""), 20), border=1)
                    pdf.cell(18, 8, "0", border=1)
                    pdf.cell(18, 8, "0", border=1)
                    pdf.cell(28, 8, "0.00", border=1)
                    pdf.cell(28, 8, "0.00", border=1)
                    pdf.cell(28, 8, "0.00", border=1)
                    pdf.cell(34, 8, _pdf_cell_text(f"{float(row.get('balance_after') or 0):.2f}", 20), border=1, ln=True)
                    continue
    
                sold = int(row.get("packets_sold") or row.get("delivered") or 0)
                returned = int(row.get("packets_returned") or row.get("returned") or 0)
                bill = float(row.get("bill_amount") or row.get("debit") or 0)
                paid = float(row.get("amount_paid") or row.get("credit") or 0)
                due = float(row.get("line_due") or row.get("balance") or 0)
                bal_after = float(row.get("balance_after") or row.get("running_balance") or 0)
    
                pdf.cell(24, 8, _pdf_cell_text(row.get("date", ""), 20), border=1)
                pdf.cell(18, 8, _pdf_cell_text(sold, 10), border=1)
                pdf.cell(18, 8, _pdf_cell_text(returned, 10), border=1)
                pdf.cell(28, 8, _pdf_cell_text(f"{bill:.2f}", 20), border=1)
                pdf.cell(28, 8, _pdf_cell_text(f"{paid:.2f}", 20), border=1)
                pdf.cell(28, 8, _pdf_cell_text(f"{due:.2f}", 20), border=1)
                pdf.cell(34, 8, _pdf_cell_text(f"{bal_after:.2f}", 20), border=1, ln=True)
    
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, _pdf_cell_text(f"Final Outstanding: {total_outstanding:.2f}", 120), ln=True)
    
        pdf.set_font("Helvetica", "", 8)
        pdf.ln(4)
        pdf.multi_cell(
            0,
            5,
            _pdf_cell_text(
                "This is a computer-generated ledger statement from RouteSync for Sri Mahalakshmi Home Foods.",
                180,
            ),
        )
    
        raw = pdf.output()
        if isinstance(raw, str):
            body: bytes = raw.encode("latin-1")
        else:
            body = bytes(raw)
    
        safe_store_name = re.sub(r"[^A-Za-z0-9_-]+", "_", store_name).strip("_")[:60] or f"store_{store_id}"
        filename = f"SMHF_{safe_store_name}_{file_period}.pdf"
    
        return Response(
            content=body,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


# ---------------- DASHBOARD ----------------
@app.get("/admin/dashboard")
def admin_dashboard(
    request: Request,
    from_date: str = Query(..., description="YYYY-MM-DD"),
    to_date: str = Query(..., description="YYYY-MM-DD"),
    route_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    _require_admin(request, None)
    fd = _parse_ymd(from_date, "from_date")
    td = _parse_ymd(to_date, "to_date")
    if td < fd:
        raise HTTPException(400, "to_date must be on or after from_date")

    selected_route: Route | None = None
    if route_id is not None:
        selected_route = db.query(Route).filter(Route.id == route_id).first()
        if not selected_route:
            raise HTTPException(404, "Route not found")

    q = db.query(Entry).filter(Entry.date >= fd, Entry.date <= td)
    if route_id is not None:
        q = q.filter(Entry.route_id == route_id)
    entries = q.order_by(Entry.date.asc(), Entry.id.asc()).all()

    route_ids = sorted({int(e.route_id or 0) for e in entries if e.route_id is not None and int(e.route_id or 0) > 0})
    routes_map = {r.id: r for r in db.query(Route).filter(Route.id.in_(route_ids)).all()} if route_ids else {}

    store_ids = sorted({int(e.store_id or 0) for e in entries if e.store_id is not None and int(e.store_id or 0) > 0})
    stores_map = {s.id: s for s in db.query(Store).filter(Store.id.in_(store_ids)).all()} if store_ids else {}

    total_delivered = 0
    total_returned = 0
    total_cash = 0.0
    total_upi = 0.0
    total_collected = 0.0
    total_balance = 0.0
    stores_visited: set[int] = set()

    daily_agg: dict[str, dict] = {}
    store_agg: dict[int, dict] = {}
    store_daily_agg: dict[tuple[int, str], dict] = {}

    for e in entries:
        sid = int(e.store_id or 0)
        d = int(e.delivered or 0)
        r = int(e.returned or 0)
        cc, cu = _entry_cash_upi(e)
        collected = float(cc + cu)
        bal = float(e.balance or 0)
        edate = e.date.isoformat() if e.date else ""

        total_delivered += d
        total_returned += r
        total_cash += float(cc)
        total_upi += float(cu)
        total_collected += collected
        total_balance += bal
        if sid > 0:
            stores_visited.add(sid)

        if edate not in daily_agg:
            daily_agg[edate] = {"date": edate, "delivered": 0, "returned": 0, "collected": 0.0, "balance": 0.0}
        day = daily_agg[edate]
        day["delivered"] += d
        day["returned"] += r
        day["collected"] += collected
        day["balance"] += bal

        if sid not in store_agg:
            store_row = stores_map.get(sid)
            route_row = routes_map.get(int(e.route_id or 0))
            store_agg[sid] = {
                "store_id": sid,
                "store_name": store_row.name if store_row else "?",
                "route_id": int(e.route_id or 0),
                "route_code": route_row.route_code if route_row else None,
                "delivered": 0,
                "returned": 0,
                "collected": 0.0,
                "balance": 0.0,
            }
        sa = store_agg[sid]
        sa["delivered"] += d
        sa["returned"] += r
        sa["collected"] += collected
        sa["balance"] += bal

        sdkey = (sid, edate)
        if sdkey not in store_daily_agg:
            store_row2 = stores_map.get(sid)
            store_daily_agg[sdkey] = {
                "store_id": sid,
                "store_name": store_row2.name if store_row2 else "?",
                "date": edate,
                "delivered": 0,
                "returned": 0,
                "collected": 0.0,
            }
        sda = store_daily_agg[sdkey]
        sda["delivered"] += d
        sda["returned"] += r
        sda["collected"] += collected

    outstanding_map: dict[int, float] = {}
    for sid in store_ids:
        store_obj = stores_map.get(sid)
        ob = float(getattr(store_obj, "opening_balance", None) or 0) if store_obj else 0.0
        all_entries = db.query(Entry).filter(Entry.store_id == sid).all()
        outstanding_map[sid] = round(ob + sum(_entry_balance_due(e) for e in all_entries), 2)

    store_list = list(store_agg.values())
    for s in store_list:
        s["collected"] = round(s["collected"], 2)
        s["balance"] = round(s["balance"], 2)
        s["outstanding"] = outstanding_map.get(s["store_id"], 0.0)
    store_list.sort(key=lambda x: x["delivered"], reverse=True)

    daily_list = sorted(daily_agg.values(), key=lambda x: x["date"])
    for d in daily_list:
        d["collected"] = round(d["collected"], 2)
        d["balance"] = round(d["balance"], 2)

    store_daily_list = sorted(store_daily_agg.values(), key=lambda x: (x["store_name"], x["date"]))
    for sd in store_daily_list:
        sd["collected"] = round(sd["collected"], 2)

    n_stores = len(stores_visited) or 1

    return {
        "summary": {
            "total_delivered": total_delivered,
            "total_returned": total_returned,
            "total_cash": round(total_cash, 2),
            "total_upi": round(total_upi, 2),
            "total_collected": round(total_collected, 2),
            "total_balance": round(total_balance, 2),
            "total_stores_visited": len(stores_visited),
            "avg_sale_per_store": round(total_collected / n_stores, 2),
        },
        "daily": daily_list,
        "stores": store_list,
        "store_daily": store_daily_list,
    }


app.mount("/static", StaticFiles(directory=str(UPLOAD_DIR)), name="static")
