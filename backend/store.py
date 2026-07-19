"""Filesystem + SQLite helpers for stored keys and cached location reports."""
import glob
import os
import sqlite3


def keys_dir_default():
    return os.environ.get(
        "REMOTEWATCH_KEYS_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "keys"),
    )


def reports_db_path(keys_dir):
    return os.path.join(keys_dir, "reports.db")


def auth_path(keys_dir):
    return os.path.join(keys_dir, "auth.json")


def _parse_keyfile(path):
    """Parse a ``.keys`` file into a dict keyed by its human labels."""
    fields = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if ": " not in line:
                continue
            label, value = line.split(": ", 1)
            fields[label] = value
    return fields


def list_keys(keys_dir):
    """Return metadata for every ``.keys`` file in ``keys_dir`` (no secrets)."""
    out = []
    for path in sorted(glob.glob(os.path.join(keys_dir, "*.keys"))):
        fields = _parse_keyfile(path)
        name = os.path.basename(path)[:-5]
        out.append({
            "name": name,
            "file": os.path.basename(path),
            "mac": fields.get("MAC", ""),
            "hashed_adv_key": fields.get("Hashed adv key", ""),
            "advertisement_key": fields.get("Advertisement key", ""),
            "payload": fields.get("Payload", ""),
            "created": os.path.getmtime(path),
        })
    return out


def key_path(keys_dir, name):
    """Resolve a key ``name`` to its file path, guarding against traversal."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    path = os.path.join(keys_dir, name + ".keys")
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(keys_dir):
        return None
    return path


def delete_key(keys_dir, name):
    path = key_path(keys_dir, name)
    if not path or not os.path.exists(path):
        return False
    os.remove(path)
    return True


def read_stored_reports(keys_dir, names=None):
    """Read cached decrypted reports from the SQLite database.

    Lets the UI render the last-known map without re-hitting Apple. Returns a
    list of report dicts sorted oldest-first.
    """
    db = reports_db_path(keys_dir)
    if not os.path.exists(db):
        return []
    con = sqlite3.connect(db)
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='reports'"
        )
        if cur.fetchone() is None:
            return []
        rows = cur.execute(
            "SELECT id_short, timestamp, lat, lon, conf FROM reports ORDER BY timestamp ASC"
        ).fetchall()
    finally:
        con.close()

    out = []
    for name, timestamp, lat, lon, conf in rows:
        if names is not None and name not in names:
            continue
        try:
            latf, lonf = float(lat), float(lon)
        except (TypeError, ValueError):
            continue
        out.append({
            "key": name,
            "timestamp": timestamp,
            "lat": latf,
            "lon": lonf,
            "conf": conf,
        })
    return out
