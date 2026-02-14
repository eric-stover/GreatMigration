"""Local authentication routes."""
import os
import secrets
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from logging_utils import get_user_logger

SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").strip().lower() in {"1", "true", "yes", "on"}
# LOCAL_USERS format: "user1:pass1,user2:pass2"
README_URL = "https://github.com/jacob-hopkins/GreatMigration#readme"
HELP_URL = os.getenv("HELP_URL", README_URL)


def _load_users() -> Dict[str, str]:
    raw = os.getenv("LOCAL_USERS", "")
    users: Dict[str, str] = {}
    for pair in raw.split(","):
        if ":" in pair:
            u, p = pair.split(":", 1)
            users[u.strip()] = p.strip()
    return users


def _load_push_users() -> set[str]:
    return {x.strip() for x in os.getenv("LOCAL_PUSH_USERS", "").split(",") if x.strip()}


USERS = _load_users()
_PUSH_USERS = _load_push_users()
router = APIRouter()

action_logger = get_user_logger()


def _html_login(error: Optional[str] = None) -> str:
    msg = f'<p class="text-sm text-rose-600 dark:text-rose-400 mt-2">{error}</p>' if error else ''
    return f"""
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Sign in</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>tailwind.config = {{ darkMode: 'media' }};</script>
  </head>
  <body class="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-900 dark:text-slate-100" style="background-image: url('/static/logo.png'); background-position: center; background-repeat: no-repeat; background-size: 1500px;">
    <a href="{HELP_URL}" target="_blank" rel="noopener" class="fixed top-4 right-4 text-white/80 hover:text-white" aria-label="Help">
      <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10A8 8 0 11 2 10a8 8 0 0116 0zM10 5a3 3 0 00-3 3 .75.75 0 101.5 0A1.5 1.5 0 0110 6.5a1.5 1.5 0 011.5 1.5c0 .401-.08.558-.494.969-.458.451-1.168 1.15-1.168 2.531h1.5c0-.822.447-1.2.903-1.642.571-.56 1.009-1.078 1.009-1.858A3 3 0 0010 5zm0 8a1 1 0 100 2 1 1 0 000-2z" clip-rule="evenodd"/></svg>
    </a>
    <div class="min-h-screen flex items-center justify-center p-6">
      <div class="w-full max-w-md bg-white dark:bg-slate-800 rounded-2xl shadow p-6">
        <h1 class="text-xl font-semibold">Sign in</h1>
        <p class="text-sm text-slate-600 dark:text-slate-300">Use your local account</p>
        {msg}
        <form method="post" action="/login" class="mt-4 space-y-3">
          <div>
            <label class="block text-sm font-medium mb-1">Username</label>
            <input name="username" autocomplete="username" class="w-full border rounded p-2 dark:bg-slate-900 dark:border-slate-700" required />
          </div>
          <div>
            <label class="block text-sm font-medium mb-1">Password</label>
            <input name="password" type="password" autocomplete="current-password" class="w-full border rounded p-2 dark:bg-slate-900 dark:border-slate-700" required />
          </div>
          <button class="w-full mt-2 px-3 py-2 rounded text-white bg-emerald-600 hover:bg-emerald-700">Sign in</button>
        </form>
      </div>
    </div>
  </body>
</html>
"""


@router.get("/login", response_class=HTMLResponse)
def get_login():
    return HTMLResponse(_html_login())


@router.post("/login")
def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    if USERS.get(username) != password:
        client_host = request.client.host if request.client else "-"
        action_logger.warning("local_login_failed user=%s client=%s", username, client_host)
        return HTMLResponse(_html_login("Invalid username or password."), status_code=401)

    request.session["user"] = {
        "name": username,
        "email": "",
        "can_push": username in _PUSH_USERS,
        "read_only": username not in _PUSH_USERS,
    }
    client_host = request.client.host if request.client else "-"
    action_logger.info("local_login_success user=%s client=%s", username, client_host)
    return RedirectResponse("/", status_code=302)


@router.get("/logout")
def logout(request: Request):
    user = request.session.get("user", {})
    client_host = request.client.host if request.client else "-"
    username = user.get("name") or "anonymous"
    action_logger.info("local_logout user=%s client=%s", username, client_host)
    request.session.clear()
    return RedirectResponse("/", status_code=302)


# ----- Dependencies -----

def current_user(request: Request) -> Dict[str, Any]:
    u = request.session.get("user")
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required")
    return u


def require_push_rights(user=Depends(current_user)):
    if not user.get("can_push"):
        raise HTTPException(status_code=403, detail="Push permission required")
    return user


@router.get("/me")
def me(user=Depends(current_user)):
    return {
        "ok": True,
        "user": {
            "name": user.get("name"),
            "email": user.get("email"),
            "can_push": user.get("can_push", False),
            "read_only": user.get("read_only", False),
        },
    }


def install_auth(app):
    """Enable session auth routes."""
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=SESSION_HTTPS_ONLY)
    app.include_router(router)
