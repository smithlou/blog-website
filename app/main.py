from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import users, dashboard
import db


app = FastAPI(title="FronBlog")
templates = Jinja2Templates(directory="templates")

app.include_router(users.router)
app.include_router(dashboard.router)

@app.get("/")
def main(request: Request):
    email = db.get_current_user_email(request)
    if not email:
        return RedirectResponse(url="/users/login", status_code=303)
    return {"message": "made by fron"}

