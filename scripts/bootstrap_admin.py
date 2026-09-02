#!/usr/bin/env python3
"""Create the first local RF-NIDS administrator after migrations are applied."""

from __future__ import annotations

import argparse
from getpass import getpass

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.api.auth import hash_password, normalize_email
from src.api.database import build_engine
from src.api.models import User
from src.common.config import Settings


def create_admin(db: Session, *, name: str, email: str, password: str) -> User:
    normalized_email = normalize_email(email)
    if db.scalar(select(User).where(User.email == normalized_email)) is not None:
        raise ValueError(f"A user with email {normalized_email} already exists")
    user = User(
        name=name.strip(),
        email=normalized_email,
        password_hash=hash_password(password),
        role="ADMIN",
        is_active=True,
    )
    if not user.name:
        raise ValueError("Administrator name must not be empty")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    password = getpass("Administrator password (minimum 12 characters): ")
    confirmation = getpass("Confirm administrator password: ")
    if password != confirmation:
        parser.error("password confirmation does not match")

    engine = build_engine(Settings.from_env().database_url)
    try:
        with Session(engine) as db:
            user = create_admin(db, name=args.name, email=args.email, password=password)
        print(f"Created active ADMIN user {user.email}")
    except ValueError as exc:
        parser.error(str(exc))
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
