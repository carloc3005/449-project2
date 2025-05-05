from datetime import datetime, timedelta, timezone
from typing import Optional, Annotated

from fastapi import Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from ..config.settings import settings
# Adjusted import path assuming crud.py will be in the db directory
from ..db import database, crud
from ..models import user as user_models
from ..models import token as token_models

# Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Scheme Configuration (using cookies instead of Authorization header)
# We won't use OAuth2PasswordBearer directly for dependency injection
# because we'll read the token from the cookie manually.
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Keep for reference or potential future use

# --- Password Utilities ---

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)

# --- JWT Token Utilities ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # Use "sub" (subject) for username, a standard JWT claim
    to_encode.update({"exp": expire, "sub": to_encode.get("username")})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[token_models.TokenData]:
    """Decodes a JWT access token and returns the payload."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: Optional[str] = payload.get("sub")
        role: Optional[str] = payload.get("role")
        if username is None:
            return None
        return token_models.TokenData(username=username, role=role)
    except JWTError:
        return None

# --- Authentication Dependencies ---

async def get_current_user(
    request: Request,
    db: Session = Depends(database.get_db)
) -> Optional[user_models.User]:
    """
    Dependency to get the current user from the JWT token stored in cookies.
    Raises HTTPException if the token is invalid or the user doesn't exist.
    """
    token = request.cookies.get("access_token")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}, # Although using cookies, standard header might be expected by some clients
    )
    if token is None:
        # If no token in cookie, maybe it's in header (for API testing)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ")[1]
        else:
            raise credentials_exception

    token_data = decode_access_token(token)
    if token_data is None or token_data.username is None:
        raise credentials_exception

    # Use the crud function to get user from DB
    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: user_models.User = Depends(get_current_user)
) -> user_models.User:
    """
    Dependency to ensure the user fetched from the token is active (if we add an is_active flag later).
    Currently, just returns the user if found by get_current_user.
    """
    # If we add an is_active field to the User model:
    # if not current_user.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Dependency for Admin-only routes
async def require_admin(
    current_user: user_models.User = Depends(get_current_active_user)
):
    """
    Dependency to ensure the current user has the 'admin' role.
    """
    if current_user.role != user_models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user

# --- Helper Functions for Login/Logout ---

def set_auth_cookie(response: Response, token: str):
    """Sets the access token in an HTTPOnly cookie."""
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True, # Important for security! Prevents JS access.
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, # Max age in seconds
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, # Also set expires for older browsers
        samesite="Lax", # Can be "Strict" or "Lax" or "None" (None requires Secure=True)
        secure=False, # Set to True if using HTTPS
        path="/"
    )

def unset_auth_cookie(response: Response):
    """Unsets (deletes) the access token cookie."""
    response.delete_cookie(key="access_token", path="/")
