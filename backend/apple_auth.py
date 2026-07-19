"""Web-driven Apple ID login, including the resumable 2FA handshake.

Wraps the low-level GSA helpers so the frontend can sign in without any
interactive prompts:

  1. ``begin(username, password)`` runs SRP. If Apple accepts immediately it
     writes ``auth.json`` and returns ``authenticated``. If a second factor is
     required it fires off the SMS / trusted-device request and returns a
     short-lived ``session_id`` with status ``needs_2fa``.
  2. ``submit(session_id, code)`` validates the code, re-runs SRP against the
     now-trusted session, exchanges it for the MobileMe search-party token, and
     writes ``auth.json``.

Sessions (which hold the password in memory only, never on disk) live in a
process-local dict — appropriate for the single-user self-hosted deployment
this app targets.
"""
import json
import os
import secrets
import time

from .cores import pypush_gsa_icloud as gsa
from .store import auth_path

# session_id -> {username, password, adsid, idms_token, method, created}
_SESSIONS = {}
_SESSION_TTL = 600  # seconds


def _reap():
    now = time.time()
    for sid in [s for s, v in _SESSIONS.items() if now - v["created"] > _SESSION_TTL]:
        _SESSIONS.pop(sid, None)


def _write_auth(keys_dir, mobileme):
    j = {
        "dsid": mobileme["dsid"],
        "searchPartyToken": mobileme["delegates"]["com.apple.mobileme"]["service-data"]["tokens"]["searchPartyToken"],
    }
    os.makedirs(keys_dir, exist_ok=True)
    path = auth_path(keys_dir)
    with open(path, "w") as f:
        json.dump(j, f)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return j


def _finish(keys_dir, username, spd):
    """Exchange a completed GSA session for MobileMe tokens and persist them."""
    mobileme = gsa.mobileme_from_spd(username, spd)
    delegate = mobileme.get("delegates", {}).get("com.apple.mobileme", {})
    if delegate.get("status") != 0:
        reason = delegate.get("status-message", "iCloud login was rejected.")
        raise RuntimeError(reason)
    _write_auth(keys_dir, mobileme)


def begin(keys_dir, username, password, method="sms"):
    """Start a login. Returns a status dict.

    ``authenticated`` — signed in, ``auth.json`` written.
    ``needs_2fa`` — a code was sent; call :func:`submit` with ``session_id``.
    """
    _reap()
    try:
        spd = gsa.gsa_authenticate(username, password, second_factor=method)
    except gsa.TwoFactorRequired as tf:
        if tf.method == "trusted_device":
            gsa.trusted_second_factor_request(tf.adsid, tf.idms_token)
        else:
            gsa.sms_second_factor_request(tf.adsid, tf.idms_token)
        sid = secrets.token_urlsafe(18)
        _SESSIONS[sid] = {
            "username": username,
            "password": password,
            "adsid": tf.adsid,
            "idms_token": tf.idms_token,
            "method": tf.method,
            "created": time.time(),
        }
        return {"status": "needs_2fa", "session_id": sid, "method": tf.method}

    if not spd:
        raise RuntimeError("Authentication failed. Check your Apple ID and password.")
    _finish(keys_dir, username, spd)
    return {"status": "authenticated"}


def submit(keys_dir, session_id, code):
    """Complete a 2FA login begun with :func:`begin`."""
    _reap()
    sess = _SESSIONS.get(session_id)
    if not sess:
        raise RuntimeError("Login session expired. Please sign in again.")

    code = (code or "").strip()
    if sess["method"] == "trusted_device":
        gsa.trusted_second_factor_submit(sess["adsid"], sess["idms_token"], code)
    else:
        gsa.sms_second_factor_submit(sess["adsid"], sess["idms_token"], code)

    # The session is now trusted; a fresh SRP handshake should complete cleanly.
    spd = gsa.gsa_authenticate(sess["username"], sess["password"], second_factor=sess["method"])
    if not spd:
        raise RuntimeError("Two-factor verification failed. Check the code and try again.")
    _finish(keys_dir, sess["username"], spd)
    _SESSIONS.pop(session_id, None)
    return {"status": "authenticated"}


def is_authenticated(keys_dir):
    return os.path.exists(auth_path(keys_dir))


def sign_out(keys_dir):
    path = auth_path(keys_dir)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False
