from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db

router = APIRouter(prefix="/users", tags=["users"])
templates = Jinja2Templates(directory="templates")


def login_redirect(email: str, remember_me: bool) -> RedirectResponse:
    """Token üretir, cookie'yi ayarlar ve dashboard'a yönlendirir."""
    days = 30 if remember_me else 1
    token = db.create_jwt_token(email, days=days)
    response = RedirectResponse(url="/dashboard/", status_code=303)
    response.set_cookie(
        key=db.COOKIE_NAME,
        value=token,
        httponly=True,
        secure=db.COOKIE_SECURE,
        samesite="lax",
        # remember_me yoksa max_age verilmez -> tarayıcı kapanınca silinir
        max_age=days * 24 * 3600 if remember_me else None,
    )
    return response


# ---------- Kayıt ----------

@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {})


@router.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    accept_terms: bool = Form(False),
):
    username = username.strip().lower()
    email = email.strip().lower()
    # Şifreye DOKUNMUYORUZ: büyük/küçük harf şifrenin parçası.

    form_data = {"username": username, "email": email}
    errors = db.validate_registration(username, email, password, password_confirm)
    if not accept_terms:
        errors["accept_terms"] = "Devam etmek için koşulları kabul etmelisin."

    if errors:
        return templates.TemplateResponse(
            request, "register.html",
            {"errors": errors, "form_data": form_data}, status_code=400,
        )

    try:
        db.create_user(username, email, password)
    except db.AuthError as e:
        return templates.TemplateResponse(
            request, "register.html",
            {"error": str(e), "form_data": form_data}, status_code=400,
        )
    except Exception as e:
        print(f"Kayıt hatası: {e}")
        return templates.TemplateResponse(
            request, "register.html",
            {"error": "Sunucu hatası, lütfen tekrar dene.", "form_data": form_data}, status_code=500,
        )

    return login_redirect(email, remember_me=True)


# ---------- Giriş ----------

@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
def login(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False),
):
    identifier = identifier.strip().lower()
    form_data = {"identifier": identifier}

    try:
        email = db.authenticate(identifier, password)
    except Exception as e:
        print(f"Giriş hatası: {e}")
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Sunucu hatası, lütfen tekrar dene.", "form_data": form_data}, status_code=500,
        )

    if not email:
        # Hangisinin yanlış olduğunu söylemiyoruz: hesap var mı yok mu bilgisini sızdırmamak için
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Kullanıcı adı/e-posta veya şifre hatalı.", "form_data": form_data},
            status_code=400,
        )

    return login_redirect(email, remember_me)


@router.post("/logout")
def logout():
    response = RedirectResponse(url="/users/login", status_code=303)
    response.delete_cookie(db.COOKIE_NAME)
    return response
    
