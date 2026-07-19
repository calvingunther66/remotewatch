# RemoteWatch

A clean web frontend for **Apple FindMy AirTag emulation and monitoring**, built on the
key-generation and location-reporting code from
[MatthewKuKanich/FindMyFlipper](https://github.com/MatthewKuKanich/FindMyFlipper)
(`AirTagGeneration/`).

Generate OpenHaystack / FindMy key pairs (`.keys` files you can drop onto a Flipper Zero
or any BLE beacon), then track them on Apple's FindMy network — decrypted location reports
plotted on a map — from one page styled with the IntegratedOS design system.

## What's inside

- **Create `.keys`** — mint SECP224R1 key pairs. Files are byte-compatible with the
  FindMyFlipper app (`Apps_Data/FindMyFlipper/`) and carry the BLE MAC + advertisement
  payload for manual entry.
- **Track them** — pull location reports from Apple's `acsnservice`, decrypt each fix with
  the tracker's private key, cache them in SQLite, and render the latest position + trail
  per tracker on an interactive map.
- **Apple ID sign-in** — a web-driven login that handles two-factor auth (SMS or
  trusted-device) without any terminal prompts. Only the resulting search-party token is
  stored on the server (`keys/auth.json`, mode `600`); your password is never written to disk.

## Layout

```
backend/
  app.py                    FastAPI: JSON API + serves the frontend
  keygen.py                 key-pair generation  (from generate_keys.py)
  reports.py                fetch + decrypt reports  (from request_reports.py)
  apple_auth.py             resumable web login / 2FA flow
  store.py                  keyfile + SQLite helpers
  Decryptor.py              report payload decryption  (vendored verbatim)
  cores/pypush_gsa_icloud.py   Apple GSA auth  (vendored, de-prompted)
frontend/
  index.html  styles.css  app.js
keys/                       runtime data — .keys, auth.json, reports.db (gitignored)
```

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app:app --host 0.0.0.0 --port 8100
```

Then open <http://localhost:8100>.

### Anisette server (required for tracking)

Querying Apple's FindMy network needs anisette headers. Run an
[anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) and point RemoteWatch at it:

```bash
docker run -d --restart always --name anisette -p 6969:6969 dadoum/anisette-v3-server
export ANISETTE_URL=http://localhost:6969   # default
```

Creating `.keys` works without any of this — anisette and Apple sign-in are only needed to
pull location reports.

## Credits

Key generation, the ECIES report decryptor, and the Apple GSA/MobileMe auth are derived from
**FindMyFlipper** by Matthew KuKanich (which builds on
[pypush](https://github.com/JJTech0130/pypush) and
[openhaystack-python](https://github.com/hatomist/openhaystack-python)). This project
re-packages that logic behind an HTTP API and a browser UI.

> Only track devices and belongings you own. Using the FindMy network to track people
> without consent is illegal.
