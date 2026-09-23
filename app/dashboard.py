from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

import db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory="templates")


@router.get("/")
def main(request: Request):
    email = db.get_current_user_email(request)
    if not email:
        return RedirectResponse(url="/users/login", status_code=303)

    context = {"email": email, "username": db.get_username(email)}
    return templates.TemplateResponse(request, "dashboard.html", context)


# Eski formlar /dashboard/logout'a gönderdiği için korunuyor
@router.post("/logout")
def logout():
    response = RedirectResponse(url="/users/login", status_code=303)
    response.delete_cookie(db.COOKIE_NAME)
    return response
