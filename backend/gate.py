"""HTTP Basic Auth gate for the whole app (GUI + API).

Separate from apple_auth.py, which handles signing in to Apple's FindMy
network — this gates entry to RemoteWatch itself.
"""
import base64
import os
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

UNAUTHORIZED = Response(
    status_code=401,
    content="Unauthorized",
    headers={"WWW-Authenticate": 'Basic realm="RemoteWatch"'},
)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        username = os.environ.get("REMOTEWATCH_USERNAME")
        password = os.environ.get("REMOTEWATCH_PASSWORD")
        if not username or not password or request.url.path == "/health":
            return await call_next(request)

        given_user, given_pass = "", ""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            try:
                given_user, given_pass = base64.b64decode(auth[6:]).decode("utf-8").split(":", 1)
            except Exception:
                pass

        if secrets.compare_digest(given_user, username) and secrets.compare_digest(given_pass, password):
            return await call_next(request)
        return UNAUTHORIZED
