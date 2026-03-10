from datetime import datetime, timedelta

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.database import get_db
from app.models.user import User

router = APIRouter()
settings = get_settings()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    is_admin: bool
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.jwt_expiration_minutes)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)


async def get_current_user(
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Auth disabled for development — always returns admin user.

    To re-enable auth, restore the original get_current_user that
    validates JWT/API tokens (see git history).
    """
    # Always return the first admin user (no auth check)
    result = await db.execute(
        select(User).where(User.is_admin == True).limit(1)
    )
    user = result.scalar_one_or_none()
    if user:
        return user

    # Fallback: return any user
    result = await db.execute(select(User).limit(1))
    user = result.scalar_one_or_none()
    if user:
        return user

    # No users at all — create a default admin
    default_admin = User(
        username="admin",
        email="admin@phantom.local",
        password_hash=hash_password("changeme"),
        is_admin=True,
        is_active=True,
        role="ADMIN",
    )
    db.add(default_admin)
    await db.flush()
    return default_admin


@router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where((User.username == user_data.username) | (User.email == user_data.email))
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
    )
    db.add(user)
    await db.flush()
    return user


def require_role(*roles):
    """Dependency that checks user role."""
    from app.models.user import UserRole

    async def checker(user: User = Depends(get_current_user)):
        if user.role.value not in [r.value if hasattr(r, "value") else r for r in roles]:
            if not user.is_admin:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    return user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user.id})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return [
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role.value, "is_active": u.is_active}
        for u in result.scalars().all()
    ]


class UserRoleUpdate(BaseModel):
    role: str


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    data: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    from app.models.user import UserRole
    try:
        new_role = UserRole(data.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role. Use: {[r.value for r in UserRole]}")
    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    target_user.role = new_role
    return {"id": target_user.id, "username": target_user.username, "role": new_role.value}


@router.post("/api-token")
async def generate_api_token(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Generate a long-lived API token for CI/CD integration."""
    import hashlib
    import secrets
    raw_token = f"phnt_{secrets.token_hex(32)}"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    user.api_token_hash = token_hash
    await db.flush()
    return {"api_token": raw_token, "note": "Store this token securely. It cannot be retrieved again."}


@router.delete("/api-token")
async def revoke_api_token(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Revoke the current user's API token."""
    user.api_token_hash = None
    await db.flush()
    return {"detail": "API token revoked"}
