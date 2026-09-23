import os
import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import psycopg
from dotenv import load_dotenv
from fastapi import Request

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
# Localde (http) False, canlı sunucuda (https) True olmalı
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_NAME = "session_token"

if not DATABASE_URL or not SECRET_KEY:
    raise RuntimeError("DATABASE_URL ve SECRET_KEY .env dosyasında tanımlı olmalı.")


class AuthError(Exception):
    """Kullanıcıya gösterilebilecek hata mesajı taşır."""


# ---------- Token ----------

def create_jwt_token(email: str, days: int) -> str:
    payload = {
        "sub": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=days),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user_email(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


# ---------- Doğrulama ----------

USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username: str, email: str, password: str, password_confirm: str) -> dict:
    """Alan bazlı hata sözlüğü döndürür; boşsa her şey geçerli."""
    errors = {}
    if not USERNAME_RE.match(username):
        errors["username"] = "3-30 karakter; sadece küçük harf, rakam, _ ve . kullanılabilir."
    if not EMAIL_RE.match(email):
        errors["email"] = "Geçerli bir e-posta adresi gir."
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Z]", password):
        errors["password"] = "En az 8 karakter, bir rakam ve bir büyük harf içermeli."
    if password != password_confirm:
        errors["password_confirm"] = "Şifreler eşleşmiyor."
    return errors


# ---------- Veritabanı işlemleri ----------

def create_user(username: str, email: str, password: str) -> None:
    """Kullanıcıyı oluşturur. Kullanıcı adı / e-posta alınmışsa AuthError fırlatır."""
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed),
                )
    except psycopg.errors.UniqueViolation as e:
        if "email" in str(e):
            raise AuthError("Bu e-posta ile zaten bir hesap var.")
        raise AuthError("Bu kullanıcı adı alınmış.")


def authenticate(identifier: str, password: str):
    """Doğruysa kullanıcının e-postasını, değilse None döndürür."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, password FROM users WHERE username = %s OR email = %s",
                (identifier, identifier),
            )
            row = cur.fetchone()

    if not row:
        return None
    db_email, db_hash = row
    if not bcrypt.checkpw(password.encode("utf-8"), db_hash.encode("utf-8")):
        return None
    return db_email


def get_username(email: str):
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
    return row[0] if row else None
