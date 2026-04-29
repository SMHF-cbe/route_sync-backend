from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./routesync.db",
)

if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(DATABASE_URL,pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()
