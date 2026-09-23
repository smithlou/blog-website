from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

import dashboard
import db
import users

app = FastAPI(title="FronBlog")

app.include_router(users.router)
app.include_router(dashboard.router)


@app.get("/")
def home(request: Request):
    if db.get_current_user_email(request):
        return RedirectResponse(url="/dashboard/", status_code=303)
    return RedirectResponse(url="/users/login", status_code=303)
