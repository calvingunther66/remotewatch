"""Fetch and decrypt FindMy location reports for stored keys.

Refactored from MatthewKuKanich/FindMyFlipper (AirTagGeneration/request_reports.py)
into an importable function. The request/decrypt/store pipeline is unchanged:
keyfiles are matched by their hashed advertisement key, reports are pulled from
Apple's acsnservice, decrypted with the private key, and cached in SQLite.
"""
import base64
import datetime
import glob
import json
import os
import sqlite3
import struct

import requests

from .Decryptor import Decryptor
from .cores.pypush_gsa_icloud import generate_anisette_headers
from .store import auth_path, reports_db_path


class AuthMissing(Exception):
    """Raised when no Apple auth token is present — the user must sign in first."""


def decode_tag(data):
    latitude = struct.unpack(">i", data[0:4])[0] / 10000000.0
    longitude = struct.unpack(">i", data[4:8])[0] / 10000000.0
    confidence = int.from_bytes(data[8:9], "big")
    status = int.from_bytes(data[9:10], "big")
    return {"lat": latitude, "lon": longitude, "conf": confidence, "status": status}


def get_auth(keys_dir):
    path = auth_path(keys_dir)
    if not os.path.exists(path):
        raise AuthMissing("Not signed in to Apple yet.")
    with open(path) as f:
        j = json.load(f)
    return (j["dsid"], j["searchPartyToken"])


def _load_keys(keys_dir, prefix=""):
    privkeys = {}
    names = {}
    for keyfile in glob.glob(os.path.join(keys_dir, prefix + "*.keys")):
        with open(keyfile) as f:
            hashed_adv = priv = ""
            name = os.path.basename(keyfile)[len(prefix):-5]
            for line in f:
                key = line.rstrip("\n").split(": ")
                if key[0] == "Private key":
                    priv = key[1]
                elif key[0] == "Hashed adv key":
                    hashed_adv = key[1]
        if priv and hashed_adv:
            privkeys[hashed_adv] = priv
            names[hashed_adv] = name
    return privkeys, names


def fetch_reports(keys_dir, hours=24, prefix=""):
    """Request, decrypt, and cache location reports for the matching keys.

    Returns a summary dict: report count, the reports used (oldest-first), and
    which keys were found vs. still missing from the network.
    """
    auth = get_auth(keys_dir)

    privkeys, names = _load_keys(keys_dir, prefix)
    if not names:
        return {"status_code": 0, "reports": [], "found": [], "missing": [], "total": 0}

    con = sqlite3.connect(reports_db_path(keys_dir))
    sq3 = con.cursor()
    sq3.execute(
        """CREATE TABLE IF NOT EXISTS reports (
        id_short TEXT, timestamp INTEGER, datePublished INTEGER, payload TEXT,
        id TEXT, statusCode INTEGER, lat TEXT, lon TEXT, conf INTEGER,
        PRIMARY KEY(id_short,timestamp));"""
    )

    unix_epoch = int(datetime.datetime.now().timestamp())
    startdate = unix_epoch - (60 * 60 * hours)
    data = {"search": [{"startDate": startdate * 1000, "endDate": unix_epoch * 1000, "ids": list(names.keys())}]}

    r = requests.post(
        "https://gateway.icloud.com/acsnservice/fetch",
        auth=auth,
        headers=generate_anisette_headers(),
        json=data,
    )
    res = json.loads(r.content.decode())["results"]

    ordered = []
    found = set()
    for report in res:
        if report["id"] not in privkeys:
            continue
        priv = int.from_bytes(base64.b64decode(privkeys[report["id"]]), byteorder="big")
        payload = base64.b64decode(report["payload"])
        timestamp = int.from_bytes(payload[0:4], "big") + 978307200
        if timestamp < startdate:
            continue

        decrypted = Decryptor(payload, priv).Decrypt()
        tag = decode_tag(decrypted)
        tag["timestamp"] = timestamp
        tag["isodatetime"] = datetime.datetime.fromtimestamp(timestamp).isoformat()
        tag["key"] = names[report["id"]]
        tag["goog"] = f"https://maps.google.com/maps?q={tag['lat']},{tag['lon']}"
        found.add(tag["key"])
        ordered.append(tag)

        sq3.execute(
            "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (names[report["id"]], timestamp, report["datePublished"], report["payload"],
             report["id"], report["statusCode"], str(tag["lat"]), str(tag["lon"]), tag["conf"]),
        )

    con.commit()
    con.close()

    ordered.sort(key=lambda item: item.get("timestamp"))
    return {
        "status_code": r.status_code,
        "received": len(res),
        "reports": ordered,
        "found": sorted(found),
        "missing": [name for name in names.values() if name not in found],
        "total": len(ordered),
    }
