from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
from sqlalchemy.orm import declarative_base, sessionmaker


def _merge_url_query(url: str, extra: dict[str, str]) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in extra.items():
        if key not in q:
            q[key] = value
    new_query = urlencode(q)
    return urlunparse(parsed._replace(query=new_query))


def _postgres_engine_url(url: str) -> str:
    """Normalize Postgres URL for hosted DBs (Supabase, Render, etc.).

    - Ensures TLS via sslmode (Supabase requires encrypted connections).
    - Set DATABASE_SSLMODE=disable for a local Postgres without SSL.
    - Set DATABASE_SSLMODE=prefer|verify-full|... to override the default.
    """
    ssl_raw = (os.environ.get("DATABASE_SSLMODE") or "").strip().lower()
    if ssl_raw == "disable":
        return url

    sslmode = ssl_raw if ssl_raw else "require"
    return _merge_url_query(url, {"sslmode": sslmode})


# Treat unset or blank DATABASE_URL as missing (empty env var would otherwise crash create_engine).
_raw_db = (os.environ.get("DATABASE_URL") or "").strip()
DATABASE_URL = _raw_db or "sqlite:///./routesync.db"

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    _url = _postgres_engine_url(DATABASE_URL)
    engine = create_engine(
        _url,
        pool_pre_ping=True,
        # Managed Postgres (incl. Supabase) may drop idle connections.
        pool_recycle=int(os.environ.get("DATABASE_POOL_RECYCLE", "300")),
    )
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()
