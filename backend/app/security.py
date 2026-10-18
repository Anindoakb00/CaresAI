import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import SessionToken, User

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User) -> str:
    raw_token = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=get_settings().session_ttl_hours)
    db.add(SessionToken(user_id=user.id, token_hash=_hash_token(raw_token), expires_at=expires_at))
    db.commit()
    return raw_token


def delete_session(db: Session, raw_token: str | None) -> None:
    if raw_token:
        db.execute(delete(SessionToken).where(SessionToken.token_hash == _hash_token(raw_token)))
        db.commit()


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    raw_token = request.cookies.get("careshield_session")
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    session = db.scalar(select(SessionToken).where(SessionToken.token_hash == _hash_token(raw_token)))
    now = datetime.now(timezone.utc)
    if not session or session.expires_at.replace(tzinfo=timezone.utc) < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account unavailable")
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permission")
        return user

    return dependency


def require_csrf(request: Request, user: User = Depends(current_user)) -> User:
    cookie_token = request.cookies.get("careshield_csrf")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return user


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(24)

