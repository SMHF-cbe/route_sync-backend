from __future__ import annotations

from datetime import date, datetime, timezone, timedelta

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    Integer,
    String,
    UniqueConstraint,
)

from .database import Base


# -------------------------------------------------------------------
# Timezone
# -------------------------------------------------------------------

IST = timezone(timedelta(hours=5, minutes=30))


def business_today() -> date:
    """
    Calendar date in IST.

    Important:
    - Daily business turnover happens at midnight India time.
    - This avoids server UTC creating wrong dates for Indian users.
    """
    return datetime.now(IST).date()


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------

class Route(Base):
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True, index=True)

    # Business route number:
    # Example: 1 in "Route 1 – Area Name"
    # Excel route_id refers to this value.
    route_code = Column(Integer, unique=True, nullable=True, index=True)

    name = Column(String, nullable=False)
    password = Column(String, nullable=False)


# -------------------------------------------------------------------
# Stores
# -------------------------------------------------------------------

class Store(Base):
    __tablename__ = "stores"
    __table_args__ = (
        UniqueConstraint("name", name="uq_store_name"),
    )

    id = Column(Integer, primary_key=True, index=True)

    # Basic store info
    name = Column(String, nullable=False, unique=True)
    area = Column(String)
    price = Column(Float, nullable=False)
    route_id = Column(Integer)

    # Store status
    is_active = Column(Boolean, default=True)

    # Manual route-wise ordering for drag-and-drop sorting
    sort_order = Column(Integer, default=0)

    # Offers
    offer_type = Column(String, default="none")
    offer_buy = Column(Integer, default=0)
    offer_get = Column(Integer, default=0)
    offer_min_qty = Column(Integer, default=0)
    bundle_price = Column(Float, default=0)

    # Extra info
    photo_url = Column(String)
    location_url = Column(String)
    notes = Column(String)

    # Amount already owed before first tracked visit
    # Example: old pending amount before using RouteSync
    opening_balance = Column(Float, default=0)


# -------------------------------------------------------------------
# Entries
# -------------------------------------------------------------------

class Entry(Base):
    __tablename__ = "entries"

    id = Column(Integer, primary_key=True, index=True)

    # Business date
    date = Column(Date, default=business_today)

    # Created/updated timestamps in IST without tzinfo
    created_at = Column(DateTime, default=lambda: datetime.now(IST).replace(tzinfo=None))
    updated_at = Column(DateTime, nullable=True)

    # Relations
    store_id = Column(Integer)
    route_id = Column(Integer)

    # Quantity tracking
    delivered = Column(Integer, default=0)
    returned = Column(Integer, default=0)

    # Offer calculation result
    free = Column(Integer, default=0)
    billable = Column(Integer, default=0)

    # Billing
    total_amount = Column(Float, default=0)

    # Collection tracking
    amount_collected = Column(Float, default=0)
    collected_cash = Column(Float, default=0)
    collected_upi = Column(Float, default=0)
    payment_mode = Column(String)
    upi_received = Column(Boolean, default=False)

    # Balance
    balance = Column(Float, default=0)

    # Closed/no-sale entry
    is_closed = Column(Boolean, default=False)


# -------------------------------------------------------------------
# Entry Audit Log
# -------------------------------------------------------------------

class EntryAuditLog(Base):
    __tablename__ = "entry_audit_log"

    id = Column(Integer, primary_key=True, index=True)

    entry_id = Column(Integer, nullable=False, index=True)
    field_name = Column(String, nullable=False)

    old_value = Column(String)
    new_value = Column(String)

    edited_by = Column(String, nullable=False)
    edited_at = Column(DateTime, default=lambda: datetime.now(IST).replace(tzinfo=None))
