from __future__ import annotations

import os

import bcrypt


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, stored: str | None) -> bool:
    if not stored:
        return False
    if stored.startswith("$2"):
        return bcrypt.checkpw(plain.encode("utf-8"), stored.encode("utf-8"))
    return plain == stored


def admin_secret_ok(provided: str | None) -> bool:
    expected = os.environ.get("ADMIN_SECRET", "").strip()
    if not expected:
        return False
    return (provided or "").strip() == expected
