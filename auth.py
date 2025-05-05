from passlib.context import CryptContext
from fastapi import Request, Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "default_session_secret")
SESSION_COOKIE_NAME = "session"

# Password hashing
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Session management (cookie-based)
def get_serializer():
    return URLSafeTimedSerializer(SESSION_SECRET_KEY)

def create_session_cookie(data: dict, max_age=3600):
    s = get_serializer()
    return s.dumps(data)

def get_session_data(cookie: str, max_age=3600):
    s = get_serializer()
    try:
        data = s.loads(cookie, max_age=max_age)
        return data
    except (BadSignature, SignatureExpired):
        return None

def set_session(response: Response, data: dict):
    cookie_val = create_session_cookie(data)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_val,
        httponly=True,
        max_age=3600,
        samesite="lax",
        secure=False  # Set to True in production with HTTPS
    )

def clear_session(response: Response):
    response.delete_cookie(SESSION_COOKIE_NAME)