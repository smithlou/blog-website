from dotenv import load_dotenv
import os
import psycopg
import bcrypt
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi import Response, Request, HTTPException, Depends
import jwt
from datetime import datetime, timedelta, timezone


load_dotenv()
DATABASE_URL= os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

def create_jwt_token(email: str) -> str:
    payload = {
        "sub": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def register_func(response, email, password, password_confirm, username):
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                if cur.fetchone():
                    return {"message": "Böyle bir eposta zaten var"}

                if password != password_confirm:
                    return {"message": "Şifreler uyuşmuyor!"}

                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cr_password = hashed.decode('utf-8')

                cur.execute(
                    "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, cr_password),
                )
                conn.commit()

                token = create_jwt_token(email)

                redirect = RedirectResponse(url="/dashboard/", status_code=303)
                redirect.set_cookie(
                    key="session_token",
                    value=token,
                    httponly=True,
                    secure=True,   # local'de http ile test ediyorsan False yap
                    samesite="lax",
                    max_age=30 * 24 * 3600,
                )
                return redirect   # artik hem yonlendirme hem cookie ayni nesnede
    except Exception as e:
        print(f"Bir sorunla karşılaşıldı: {e}")
        return {"message": "Sunucu hatası"}


def login_func(response, identifier, password):
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT email, password FROM users WHERE username = %s OR email = %s",
                    (identifier, identifier),
                )
                arama = cur.fetchone()

                if not arama:
                    return {"message": "Böyle bir hesap bulunamadı"}

                db_email, db_sifre = arama

                if not bcrypt.checkpw(password.encode('utf-8'), db_sifre.encode('utf-8')):
                    return {"message": "Şifre hatalı"}

                token = create_jwt_token(db_email)
                redirect = RedirectResponse(url="/dashboard/", status_code=303)

                redirect.set_cookie(
                    key="session_token",
                    value=token,
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    max_age=30 * 24 * 3600,
                )
                
                return redirect
    except Exception as e:
        print(f"Bir sorunla karşılaşıldı: {e}")
        return {"message": "Sunucu hatası"}

def get_current_user_email(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None