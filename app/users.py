from fastapi import APIRouter, Response
from fastapi.templating import Jinja2Templates
from fastapi import Request, Form
import db


router = APIRouter(
    prefix="/users",
    tags=["users"]
)
templates = Jinja2Templates(directory="templates")


@router.get("/register")
def register_page(request: Request):
    context = {"message": "200 OK"}
    return templates.TemplateResponse(request, "register.html", context)

@router.post("/register")
def register(response: Response, username: str = Form(...), email: str = Form(...), password: str = Form(...), password_confirm: str = Form(...)):
    new_e = email.lower()
    new_p = password.lower()
    new_pc = password_confirm.lower()
    return db.register_func(new_e, new_p, new_pc, username, response)

@router.get("/login")
def login_page(request: Request):
    context = {"message": "200 OK"}
    return templates.TemplateResponse(request, "login.html", context)

@router.post("/login")
def login(response: Response, identifier: str = Form(...), password: str = Form(...), remember_me: bool = Form(False),):
    new_i = identifier.lower()
    new_p = password.lower()
    return db.login_func(response, new_i, new_p)