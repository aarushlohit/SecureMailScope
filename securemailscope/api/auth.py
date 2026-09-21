"""
SecureMailScope - Authentication API Endpoints & FastApi Dependencies
Provides Signup, Login, Session Verification, and User Ownership.
"""
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from fastapi import APIRouter, HTTPException, Depends, Header, Request, Response, status
from sqlalchemy.orm import Session

from securemailscope.db.session import get_db, engine
from securemailscope.db.models import AuthSessionModel, UserModel
from securemailscope.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    TOKEN_TTL_SECONDS,
    revoke_token
)

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: str


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: str
    token: str
    access_token: Optional[str] = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _ensure_auth_session_table() -> None:
    AuthSessionModel.__table__.create(bind=engine, checkfirst=True)


def _extract_bearer_or_cookie(
    authorization: Optional[str],
    request: Optional[Request],
    *,
    strict: bool = False
) -> Optional[str]:
    if authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:].strip()
            return token or None
        if strict:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed authorization header.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        return None
    if request and "securemailscope_token" in request.cookies:
        return request.cookies.get("securemailscope_token")
    return None


def _create_persisted_session(user: UserModel, db: Session, request: Optional[Request] = None) -> str:
    _ensure_auth_session_table()
    session_id = f"SES-{uuid.uuid4().hex[:24].upper()}"
    token = create_access_token(
        {"sub": user.user_id, "email": user.email, "role": user.role, "sid": session_id},
        expires_in=TOKEN_TTL_SECONDS
    )
    payload = verify_access_token(token)
    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    user_agent = None
    if request:
        user_agent = (request.headers.get("user-agent") or "")[:255] or None
    db.add(AuthSessionModel(
        session_id=session_id,
        token_hash=_token_hash(token),
        user_id=user.user_id,
        expires_at=expires_at,
        user_agent=user_agent,
    ))
    db.commit()
    return token


def _revoke_persisted_session(token: str, db: Session) -> None:
    _ensure_auth_session_table()
    payload = verify_access_token(token)
    if not payload:
        return
    row = db.query(AuthSessionModel).filter_by(
        session_id=payload.get("sid"),
        token_hash=_token_hash(token),
    ).first()
    if row and row.revoked_at is None:
        row.revoked_at = _utc_now()
        db.commit()


def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    request: Request = None,
    db: Session = Depends(get_db)
) -> Optional[UserModel]:
    token = _extract_bearer_or_cookie(authorization, request)
    if not token:
        return None

    payload = verify_access_token(token)
    if not payload or "sub" not in payload or "sid" not in payload:
        return None

    try:
        _ensure_auth_session_table()
        row = db.query(AuthSessionModel).filter_by(
            session_id=payload["sid"],
            token_hash=_token_hash(token),
            user_id=payload["sub"],
        ).first()
    except Exception:
        return None

    now = _utc_now()
    if not row or row.revoked_at is not None or _as_aware_utc(row.expires_at) <= now:
        return None

    user = db.query(UserModel).filter_by(user_id=payload["sub"], is_active=True).first()
    if not user:
        return None
    row.last_used_at = now
    db.commit()
    return user


def get_or_create_default_user(db: Session) -> UserModel:
    user = db.query(UserModel).filter_by(email="analyst@agency.gov").first()
    if not user:
        user = UserModel(
            user_id="USR-DEFAULTANALYST",
            email="analyst@agency.gov",
            password_hash=hash_password("analyst123!"),
            full_name="Alex Morgan",
            role="analyst",
            is_active=True
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
        except Exception:
            db.rollback()
            user = db.query(UserModel).filter_by(user_id="USR-DEFAULTANALYST").first()
    return user


def get_current_user(
    authorization: Optional[str] = Header(None),
    request: Request = None,
    db: Session = Depends(get_db)
) -> UserModel:
    user = get_current_user_optional(authorization, request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


@auth_router.post("/signup", response_model=UserResponse)
def signup(req: SignupRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    email_clean = req.email.strip().lower()
    if not EMAIL_REGEX.match(email_clean):
        raise HTTPException(status_code=400, detail="Invalid email address format.")

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    existing = db.query(UserModel).filter_by(email=email_clean).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists.")

    uid = f"USR-{uuid.uuid4().hex[:8].upper()}"
    user = UserModel(
        user_id=uid,
        email=email_clean,
        password_hash=hash_password(req.password),
        full_name=req.full_name.strip() or "Security Analyst",
        role="analyst",
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = _create_persisted_session(user, db, request)
    response.set_cookie(
        key="securemailscope_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=30 * 24 * 3600
    )

    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        token=token,
        access_token=token
    )


@auth_router.post("/login", response_model=UserResponse)
def login(req: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    email_clean = req.email.strip().lower()
    user = db.query(UserModel).filter_by(email=email_clean).first()

    if not user or not verify_password(req.password, user.password_hash) or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = _create_persisted_session(user, db, request)
    response.set_cookie(
        key="securemailscope_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=30 * 24 * 3600
    )

    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        token=token,
        access_token=token
    )


@auth_router.get("/me")
def me(current_user: UserModel = Depends(get_current_user)):
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None
    }


@auth_router.post("/logout")
def logout(response: Response, request: Request, authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    token = _extract_bearer_or_cookie(authorization, request, strict=True)

    if token:
        _revoke_persisted_session(token, db)
        revoke_token(token)

    response.delete_cookie(key="securemailscope_token")
    return {"status": "ok", "message": "Logged out successfully. Session invalidated."}
