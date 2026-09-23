from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
import db

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"]
)

templates = Jinja2Templates(directory="templates")

@router.get("/")
def main(request: Request):
    email = db.get_current_user_email(request)
    if not email:
        return RedirectResponse(url="/users/login", status_code=303)
    context = context = {"message": "200 OK"}
    return templates.TemplateResponse(request, "dashboard.html", context)

@router.post("/logout")
def logout():
    response = RedirectResponse(url="/users/login", status_code=303)
    response.delete_cookie("session_token")
    return response