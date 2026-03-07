# auth_ldap.py
import os
import secrets
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from ldap3 import Server, Connection, ALL, Tls, NTLM, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from logging_utils import get_user_logger

SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_urlsafe(32)
LDAP_SERVER_URL = os.getenv("LDAP_SERVER_URL", "ldaps://dc01.testdomain.local:636")
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE", "DC=testdomain,DC=local")


def _parse_search_bases(raw: Optional[str]) -> List[str]:
    """Return a list of search bases, supporting semicolon/newline separated input."""
    if not raw:
        return []

    # Accept semicolons or newlines as separators while preserving DN commas
    cleaned = raw.replace("\n", ";")
    bases = [part.strip() for part in cleaned.split(";") if part.strip()]
    return bases or []


LDAP_SEARCH_BASES = _parse_search_bases(os.getenv("LDAP_SEARCH_BASES") or LDAP_SEARCH_BASE)
LDAP_BIND_TEMPLATE = os.getenv("LDAP_BIND_TEMPLATE", "{username}@testdomain.local")
PUSH_GROUP_DN = os.getenv("PUSH_GROUP_DN")  # CN=NetAuto-Push,OU=Groups,...
READONLY_GROUP_DNS = _parse_search_bases(os.getenv("READONLY_GROUP_DN"))
LDAP_MATCHING_RULE_IN_CHAIN = os.getenv("LDAP_MATCHING_RULE_IN_CHAIN", "true").strip().lower() not in {"0", "false", "no", "off"}

# Optional service account for searches
LDAP_SERVICE_DN = os.getenv("LDAP_SERVICE_DN", "CN=GreatMigration,CN=Users,DC=testdomain,DC=local")
LDAP_SERVICE_PASSWORD = os.getenv("LDAP_SERVICE_PASSWORD")

README_URL = "https://github.com/jacob-hopkins/GreatMigration#readme"
HELP_URL = os.getenv("HELP_URL", README_URL)

router = APIRouter()

action_logger = get_user_logger()

def _server() -> Server:
    use_ssl = LDAP_SERVER_URL.lower().startswith("ldaps://")
    return Server(LDAP_SERVER_URL, use_ssl=use_ssl, get_info=ALL, connect_timeout=8)

def _bind_as(username: str, password: str) -> Connection:
    """Bind as the user. username is raw (e.g., 'alice'), we render per template."""
    user_bind = LDAP_BIND_TEMPLATE.format(username=username)
    conn = Connection(_server(), user=user_bind, password=password, auto_bind=True)
    return conn

def _bind_service() -> Optional[Connection]:
    """Bind as service account for searches, if configured."""
    if not LDAP_SERVICE_DN or not LDAP_SERVICE_PASSWORD:
        return None
    return Connection(_server(), user=LDAP_SERVICE_DN, password=LDAP_SERVICE_PASSWORD, auto_bind=True)

def _iter_search_bases() -> List[str]:
    bases = LDAP_SEARCH_BASES or []
    if not bases and LDAP_SEARCH_BASE:
        bases = [LDAP_SEARCH_BASE]
    return bases


def _search_user(conn: Connection, username: str) -> Optional[Dict[str, Any]]:
    """Find user entry by UPN or sAMAccountName."""
    # Two filters to be robust
    upn = LDAP_BIND_TEMPLATE.format(username=username)
    search_filter = f"(|(userPrincipalName={upn})(sAMAccountName={username}))"
    attrs = [
        "distinguishedName",
        "displayName",
        "mail",
        "userPrincipalName",
        "memberOf",
    ]
    for base in _iter_search_bases():
        ok = conn.search(
            search_base=base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            size_limit=1,
        )
        if ok and conn.entries:
            break
    else:
        return None

    e = conn.entries[0]
    def _list(attr):
        try:
            return [str(x) for x in getattr(e, attr).values]
        except Exception:
            return []
    return {
        "dn": str(e.entry_dn),
        "displayName": str(getattr(e, "displayName", "")),
        "mail": str(getattr(e, "mail", "")),
        "upn": str(getattr(e, "userPrincipalName", "")),
        "memberOf": _list("memberOf"),
    }

def _is_member_of_group(user_dn: str, group_dn: str, search_conn: Connection) -> bool:
    """
    Recursive group check with AD matching-rule support and generic LDAP fallback.
    """
    escaped_user_dn = escape_filter_chars(user_dn)
    escaped_group_dn = escape_filter_chars(group_dn)

    if LDAP_MATCHING_RULE_IN_CHAIN:
        # (memberOf:1.2.840.113556.1.4.1941:=<groupDN>) true if user is directly or indirectly a member
        filt = (
            "(&(distinguishedName="
            f"{escaped_user_dn}"
            ")(memberOf:1.2.840.113556.1.4.1941:="
            f"{escaped_group_dn}"
            "))"
        )
        try:
            for base in _iter_search_bases():
                ok = search_conn.search(
                    search_base=base,
                    search_filter=filt,
                    search_scope=SUBTREE,
                    attributes=["distinguishedName"],
                    size_limit=1,
                )
                if ok and search_conn.entries:
                    return True
        except Exception:
            # Fallback to generic traversal below for non-AD directories.
            pass

    # Generic LDAP fallback: recursively follow memberOf references.
    queue: List[str] = [user_dn]
    visited: set[str] = set()
    target = group_dn.strip().lower()

    while queue:
        current_dn = queue.pop(0).strip()
        if not current_dn:
            continue
        key = current_dn.lower()
        if key in visited:
            continue
        visited.add(key)
        if key == target:
            return True

        current_escaped = escape_filter_chars(current_dn)
        group_filter = f"(distinguishedName={current_escaped})"
        for base in _iter_search_bases():
            try:
                ok = search_conn.search(
                    search_base=base,
                    search_filter=group_filter,
                    search_scope=SUBTREE,
                    attributes=["memberOf", "distinguishedName"],
                    size_limit=1,
                )
            except Exception:
                continue
            if not (ok and search_conn.entries):
                continue
            entry = search_conn.entries[0]
            try:
                parent_groups = [str(v) for v in getattr(entry, "memberOf").values]
            except Exception:
                parent_groups = []
            for parent in parent_groups:
                if parent.strip().lower() == target:
                    return True
                if parent.strip().lower() not in visited:
                    queue.append(parent)
            break

    return False

def _html_login(error: Optional[str] = None) -> str:
    msg = f'<p class="text-sm text-rose-600 dark:text-rose-400 mt-2">{error}</p>' if error else ''
    hint = 'user@testdomain.local' if '{username}@' in LDAP_BIND_TEMPLATE else 'TESTDOMAIN\\user'
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
        <p class="text-sm text-slate-600 dark:text-slate-300">Use your corporate AD credentials</p>
        {msg}
        <form method="post" action="/login" class="mt-4 space-y-3">
          <div>
            <label class="block text-sm font-medium mb-1">Username</label>
            <input name="username" autocomplete="username" class="w-full border rounded p-2 dark:bg-slate-900 dark:border-slate-700" required />
            <p class="text-xs text-slate-500 dark:text-slate-400 mt-1">Format: {hint}</p>
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
    # 1) Bind as user to verify credentials
    try:
        user_conn = _bind_as(username, password)
    except Exception:
        client_host = request.client.host if request.client else "-"
        action_logger.warning("ldap_login_failed user=%s client=%s reason=bind_failed", username, client_host)
        return HTMLResponse(_html_login("Invalid username or password."), status_code=401)

    # 2) Find user entry (with groups)
    entry = _search_user(user_conn, username)
    if not entry:
        client_host = request.client.host if request.client else "-"
        action_logger.warning("ldap_login_failed user=%s client=%s reason=user_not_found", username, client_host)
        return HTMLResponse(_html_login("User not found in directory."), status_code=401)

    # 3) If we need recursive group check, bind service (or reuse user bind if permitted)
    svc_conn = None
    if PUSH_GROUP_DN or READONLY_GROUP_DNS:
        try:
            svc_conn = _bind_service()
        except Exception:
            svc_conn = None

    membership_conn = svc_conn or user_conn

    can_push = False
    if PUSH_GROUP_DN:
        try:
            can_push = _is_member_of_group(entry["dn"], PUSH_GROUP_DN, membership_conn)
        except Exception:
            can_push = False

    is_read_only = False
    if READONLY_GROUP_DNS:
        try:
            for group_dn in READONLY_GROUP_DNS:
                if _is_member_of_group(entry["dn"], group_dn, membership_conn):
                    is_read_only = True
                    break
        except Exception:
            is_read_only = False

    has_group_requirement = bool(PUSH_GROUP_DN or READONLY_GROUP_DNS)
    if has_group_requirement and not (can_push or is_read_only):
        client_host = request.client.host if request.client else "-"
        action_logger.warning(
            "ldap_login_failed user=%s client=%s reason=not_in_allowed_group",
            username,
            client_host,
        )
        return HTMLResponse(
            _html_login("Your account is not authorized for Mist pushes."),
            status_code=403,
        )

    # 4) Store session
    read_only_flag = bool(is_read_only and not can_push)
    request.session["user"] = {
        "name": entry.get("displayName") or username,
        "email": entry.get("mail") or entry.get("upn") or "",
        "dn": entry["dn"],
        "upn": entry.get("upn") or "",
        "can_push": bool(can_push),
        "read_only": read_only_flag,
    }
    client_host = request.client.host if request.client else "-"
    action_logger.info(
        "ldap_login_success user=%s client=%s can_push=%s read_only=%s",
        entry.get("displayName") or username,
        client_host,
        bool(can_push),
        read_only_flag,
    )
    return RedirectResponse("/", status_code=302)

@router.get("/logout")
def logout(request: Request):
    user = request.session.get("user", {})
    client_host = request.client.host if request.client else "-"
    username = user.get("name") or user.get("upn") or "anonymous"
    action_logger.info("ldap_logout user=%s client=%s", username, client_host)
    request.session.clear()
    resp = RedirectResponse("/", status_code=302)
    return resp

# ----- Dependencies you can use to protect routes -----
def current_user(request: Request) -> Dict[str, Any]:
    u = request.session.get("user")
    if not u:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth required")
    return u

def require_push_rights(user = Depends(current_user)):
    if not user.get("can_push"):
        raise HTTPException(status_code=403, detail="Push permission required")
    return user

@router.get("/me")
def me(user = Depends(current_user)):
    # Minimal info for the frontend
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
    """Call this from app.py to enable sessions + routes."""
    # Add SessionMiddleware if not already present
    app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax", https_only=False)
    app.include_router(router)

__all__ = ["install_auth", "current_user", "require_push_rights"]
