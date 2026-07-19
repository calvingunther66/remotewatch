# CLAUDE.md — agent handoff & working notes

Context for any agent session picking up **RemoteWatch**. Read this first; it
captures decisions, provenance, and environment quirks that are expensive to
rediscover. Keep it current — when you change architecture, deps, or the
run/verify recipe, update the relevant section in the same commit.

---

## 1. What this project is

A web app for **Apple FindMy AirTag emulation + monitoring**. Two jobs:

1. **Create `.keys`** — generate OpenHaystack/FindMy key pairs. The `.keys`
   files are byte-compatible with the Flipper Zero
   [FindMyFlipper](https://github.com/MatthewKuKanich/FindMyFlipper) app and any
   BLE beacon; they carry the private key plus the broadcast MAC + advertisement
   payload.
2. **Track them** — query Apple's FindMy network for location reports, decrypt
   each fix with the tracker's private key, cache in SQLite, and plot the latest
   position + trail per tracker on a map.

It's part of Calvin's self-hosted suite (Raspberry Pi behind Cloudflare Tunnel)
and is styled with his **IntegratedOS design system** (see §6).

> Ethics/legal: this only tracks things the operator owns. The README carries
> the consent warning; keep it there.

---

## 2. Provenance — what came from where

The crypto/network core is vendored from
**MatthewKuKanich/FindMyFlipper**, `AirTagGeneration/`. It was *refactored into
importable modules*, not copied wholesale. Mapping:

| RemoteWatch file | Upstream origin | Change |
|---|---|---|
| `backend/keygen.py` | `generate_keys.py` | CLI `main()` → `generate_keys(count, prefix, keys_dir)`. Crypto (SECP224R1, payload layout, the `s256_b64[:7]` retry, on-disk `.keys` format) is **unchanged**. |
| `backend/reports.py` | `request_reports.py` | `__main__` block → `fetch_reports(keys_dir, hours, prefix)`. Same request→decrypt→SQLite pipeline; returns a summary dict instead of printing. |
| `backend/Decryptor.py` | `Decryptor.py` | **Verbatim.** ECIES report-payload decryptor (from openhaystack-python). |
| `backend/cores/pypush_gsa_icloud.py` | `cores/pypush_gsa_icloud.py` | Apple GSA/MobileMe auth. See §3 — the interactive prompts were removed and 2FA made resumable. |

Everything else (`apple_auth.py`, `store.py`, `app.py`, the whole `frontend/`)
is original to RemoteWatch.

---

## 3. Two deliberate departures from upstream (don't "fix" these)

1. **PBKDF2 uses the stdlib.** Upstream pins `pbkdf2~=1.3` + `pycryptodome`.
   `pbkdf2` does not build on modern setuptools (`AttributeError: install_layout`).
   `encrypt_password()` now calls `hashlib.pbkdf2_hmac("sha256", …, dklen=32)`,
   which is the *identical* algorithm (PBKDF2-HMAC-SHA256, 32-byte key). Both
   `pbkdf2` and `pycryptodome` were dropped from `requirements.txt`. Do not
   re-add them.

2. **Apple auth is de-prompted and resumable.** Upstream drives 2FA with
   `getpass()`/`input()`, which can't work behind HTTP. In
   `pypush_gsa_icloud.py`:
   - `gsa_authenticate()` **raises `TwoFactorRequired(adsid, idms_token, method)`**
     instead of prompting.
   - The SMS/trusted-device second factor is split into `*_request` (send the
     code) and `*_submit` (validate the code) helpers.
   - `ANISETTE_URL` is read from the environment (default `http://localhost:6969`).

   `backend/apple_auth.py` orchestrates the two phases: `begin()` runs SRP and,
   if 2FA is needed, fires the code request and returns a `session_id`;
   `submit(session_id, code)` validates and completes the login. Sessions live
   in a process-local dict (`_SESSIONS`, 10-min TTL) and hold the password **in
   memory only**. On success only the search-party token is written to
   `keys/auth.json` (chmod 600).

   The crypto itself is untouched — only the control flow changed.

---

## 4. Architecture

```
backend/
  app.py          FastAPI: JSON API + serves frontend/ (StaticFiles mounted at / last)
  gate.py         BasicAuthMiddleware — gates the whole app (GUI + API) behind a username/password
  keygen.py       generate SECP224R1 key pairs → .keys files
  reports.py      fetch + decrypt FindMy reports → SQLite; AuthMissing if not signed in
  apple_auth.py   two-phase web login (begin/submit), auth.json read/write, sign_out
  Decryptor.py    report payload decryptor (verbatim)
  cores/pypush_gsa_icloud.py   Apple GSA/MobileMe auth (de-prompted)
  store.py        keyfile parsing/listing/deletion, SQLite report reads, path helpers
frontend/
  index.html      shell: sidebar + Trackers/Map views, modal-root
  app.js          vanilla JS SPA (no build step): data load, render, modals, Leaflet map
  styles.css      design-system tokens + components vendored verbatim (see §6)
keys/             runtime data — .keys, auth.json, reports.db, gate.env (all gitignored; .gitkeep tracked)
requirements.txt  fastapi, uvicorn, requests, urllib3, cryptography, srp, certifi, python-multipart
```

**API surface** (all JSON unless noted):
- `GET  /api/keys` — list keys, each enriched with `last_report` + `report_count`
- `POST /api/keys` `{count, prefix}` — generate; returns **public data only**
- `GET  /api/keys/{name}/download` — raw `.keys` file (text/plain)
- `DELETE /api/keys/{name}` — delete a `.keys` file
- `GET  /api/reports` — cached decrypted fixes (no Apple round-trip)
- `POST /api/reports/refresh` `{hours, prefix}` — pull fresh from Apple; 401 if not signed in
- `GET  /api/auth/status` · `POST /api/auth/login` · `POST /api/auth/verify` · `POST /api/auth/logout`
- `GET  /` (index), `GET /health` → `ok`

**Env vars:** `REMOTEWATCH_KEYS_DIR` (default `<repo>/keys`), `ANISETTE_URL`
(default `http://localhost:6969`), `REMOTEWATCH_USERNAME` / `REMOTEWATCH_PASSWORD`
(GUI Basic Auth gate — see §5 and §7b).

---

## 5. Security invariants — do not regress

- **Private key material never goes to the browser.** `POST /api/keys` and
  `GET /api/keys` return only `name`, `file`, `mac`, `hashed_adv_key`,
  `advertisement_key`, `payload`. The private key exists only in the `.keys`
  file on disk (and via the explicit download endpoint). If you add a response
  field, re-check this.
- **`auth.json` holds only `{dsid, searchPartyToken}`**, never the password.
  Written chmod 600.
- **Path traversal is blocked** in `store.key_path()` (used by download/delete).
  Keep that guard if you add file-addressing endpoints.
- The `.gitignore` excludes `keys/*.keys`, `auth.json`, `reports.db`,
  `gate.env`. Never commit runtime data.
- **The whole app sits behind `BasicAuthMiddleware` (`backend/gate.py`).**
  This is a separate concern from Apple auth (`apple_auth.py`) — it gates
  *entry to RemoteWatch itself*, not the FindMy network. Credentials come
  from `REMOTEWATCH_USERNAME` / `REMOTEWATCH_PASSWORD`; if either is unset
  the gate no-ops (this is intentional, for local dev — see §7's smoke-test
  recipe, which relies on it being open). `/health` is always open, everything
  else 401s without valid creds. Constant-time compare via
  `secrets.compare_digest`. Production credentials live in `keys/gate.env`
  (chmod 600, gitignored), loaded by the systemd unit's `EnvironmentFile=`.
  Do not weaken this to a session cookie / JWT without a real reason — Basic
  Auth was chosen deliberately here: no extra dependency, no session state to
  manage, and the browser's native credential caching is enough for a
  single-operator dashboard.

---

## 6. Design system — how to stay on-brand

The look is **Calvin's IntegratedOS "warm hand-drawn paper"** aesthetic. It is
**not** freehand — it comes from a real design-system project.

- **Source of truth:** the `DesignSync` tool, project **"Calvin Gunther Design
  System"**, id `8af73221-bfad-46e0-80f7-c25aaa928751` (also available as the
  user-invocable skill `calvingunther-design` / `/calvingunther-design`). Use
  `DesignSync method=list_files` / `get_file` to read tokens and component
  source.
- **What's vendored here:** `frontend/styles.css` contains the tokens
  (`tokens/colors.css`, `typography.css`, `shape.css`, `spacing.css`, fonts) and
  the IntegratedOS component classes (`ui/integratedos.css`) copied **verbatim**,
  followed by a small app-specific block (map, toolbar, spinner) clearly marked
  at the bottom. If you restyle, pull the canonical values from the DesignSync
  project rather than inventing them.
- **Signatures to preserve:** paper `#faf7f1` page / white cards / dark-brown
  ink `#2a2521` (never pure black) / terracotta `#c15f3c` accent; serif type
  (Source Serif 4), mono numbers (IBM Plex Mono, tabular-nums), Caveat for hand
  notes; wobbly multi-value border-radii; hard **zero-blur** offset shadows;
  1.5px borders; italic-muted table headers with dashed row rules; sentence
  case everywhere; the hand-drawn SVG squiggle under page titles; status/brand
  dots as wobbly CSS circles. No gradients (except meter hatching), no soft
  shadows, no emoji in prose (only as nav icons).

---

## 7. Running & verifying (recipes that actually worked in the sandbox)

### Run
```bash
pip install -r requirements.txt
uvicorn backend.app:app --host 0.0.0.0 --port 8100
# override data dir: REMOTEWATCH_KEYS_DIR=/tmp/rw-keys uvicorn ...
```

### Environment gotchas discovered (Python 3.11 sandbox)
- **`cryptography` is system-installed (41.0.7) but `cffi` was missing** → its
  Rust bindings panic with `ModuleNotFoundError: No module named '_cffi_backend'`.
  Fix: `pip install cffi`. (May already be present in a fresh session; if
  imports panic, this is the cause.)
- **CDNs are blocked by the sandbox proxy.** `frontend/` loads Leaflet from
  unpkg and fonts from Google Fonts. In the sandbox these `ERR_CONNECTION_RESET`,
  so the map can't render and fonts fall back to serif — **this is an
  environment limit, not a bug**; it works on the real Pi. `app.js` guards
  `typeof L === "undefined"` so a blocked CDN shows a message instead of
  throwing.

### Quick API smoke test
```bash
B=http://127.0.0.1:8100
curl -s $B/health
curl -s -X POST $B/api/keys -H 'Content-Type: application/json' -d '{"count":2,"prefix":"bag"}'
curl -s $B/api/keys | python3 -m json.tool
```

### Key-generation invariant check
```bash
python3 -c "
from backend.keygen import generate_keys; import tempfile
k = generate_keys(1,'t',tempfile.mkdtemp())[0]
assert int(k['mac'][:2],16) & 0xC0 == 0xC0   # top 2 addr bits set
assert len(k['payload']) == 62               # 31-byte adv template, hex
print('ok', k['name'])"
```

### Browser screenshot (Playwright) — note the NODE_PATH trap
Playwright lives at `/opt/node22/lib/node_modules`, and **ESM ignores
`NODE_PATH`**. Use a CommonJS script that `require`s it by absolute path, and
point at the preinstalled Chromium:
```js
// shot.cjs — run with: node shot.cjs
const { chromium } = require('/opt/node22/lib/node_modules/playwright');
(async () => {
  const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' });
  const pg = await b.newPage({ viewport: { width: 1280, height: 900 } });
  pg.on('pageerror', e => console.log('PAGEERR', e.message));
  await pg.goto('http://127.0.0.1:8100/', { waitUntil: 'networkidle' });
  await pg.screenshot({ path: '/tmp/rw.png' });
  await b.close();
})();
```
To exercise the Map/fixes views without real Apple data, seed
`keys/reports.db` directly (table `reports(id_short, timestamp, datePublished,
payload, id, statusCode, lat, lon, conf)`; `id_short` = the key `name`,
`lat`/`lon` stored as TEXT).

---

## 7b. Production deployment — this is live, not hypothetical

RemoteWatch runs on the Pi right now at **https://track.calvingunther.com**,
gated by the Basic Auth in `backend/gate.py`. This section documents the
actual deployed state so a future session doesn't have to rediscover it.

- **App process:** `~/.config/systemd/user/remotewatch.service` — a **user**
  systemd unit (not `/etc/systemd/system`), matching the convention already
  established by the sibling `location-vault` project on this box. Linger is
  enabled for `calvingunther66`, so it survives logout/reboot.
  `systemctl --user status|restart|logs remotewatch.service`.
  Binds to `127.0.0.1:8100` only — it's reached exclusively through the
  tunnel, not the LAN, so there's no reason to expose it on `0.0.0.0` in
  production (the §7 dev recipe still uses `0.0.0.0` for local network
  testing, which is fine — that path has no tunnel in front of it).
- **Venv:** `backend/.venv` (gitignored), created with
  `python3 -m venv backend/.venv && backend/.venv/bin/pip install -r requirements.txt cffi`.
- **Credentials:** `keys/gate.env` (chmod 600, gitignored — added to
  `.gitignore` alongside the other runtime secrets), loaded via the unit's
  `EnvironmentFile=`. Contains `REMOTEWATCH_USERNAME` and
  `REMOTEWATCH_PASSWORD`. To rotate the password: edit the file, then
  `systemctl --user restart remotewatch.service`.
- **Tunnel:** reuses the existing **`integratedos`** Cloudflare tunnel
  (id `effaf65b-5c9b-4269-b937-e14aac518bcc`, system-level
  `cloudflared.service`, config at `/etc/cloudflared/config.yml` — root-owned,
  edits need `sudo`). The ingress list now has a `track.calvingunther.com` →
  `http://localhost:8100` rule ahead of the catch-all `http_status:404`. A
  backup of the pre-RemoteWatch config was left at
  `/etc/cloudflared/config.yml.bak-pre-remotewatch`. Before this change the
  tunnel had zero hostname routes (catch-all 404 only) and no subdomains of
  `calvingunther.com` were registered — so this was the first service wired
  through it; if you add another, add another ingress `hostname:` entry
  above the catch-all rather than standing up a second tunnel.
- **DNS:** the CNAME was created with
  `sudo TUNNEL_ORIGIN_CERT=/root/.cloudflared/cert.pem cloudflared tunnel route dns integratedos track.calvingunther.com`
  (proxied/orange-cloud, so public resolvers see Cloudflare edge IPs, not a
  literal CNAME — that's expected). **Gotcha:** the Pi's own local resolver
  (Tailscale MagicDNS at `100.100.100.100`, chained through pi-hole) can
  negative-cache a freshly-created record for a while — if `curl
  https://track.calvingunther.com/...` fails to resolve *from the Pi itself*
  right after a DNS change, that's local cache staleness, not a real
  problem. Verify with `dig track.calvingunther.com @1.1.1.1` or
  `curl --resolve track.calvingunther.com:443:<edge-ip> ...` instead of
  trusting the local resolver immediately after a change.
- **Restart order after touching the tunnel config:** edit
  `/etc/cloudflared/config.yml` → `sudo systemctl restart cloudflared.service`.
  That service is shared infra (other future subdomains will hang off the
  same tunnel) — treat edits to it with more care than app-level changes.

---

## 8. Not yet verified / known limitations

- **The live Apple path is untested end-to-end.** It requires real Apple ID
  credentials *and* a reachable anisette server
  ([anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) on
  `:6969`), neither available in the sandbox. Key generation + management +
  map rendering are fully verified; sign-in, `fetch_reports`, and decryption
  are exercised only up to the network boundary. When testing for real, watch:
  the SMS phone-id is hardcoded to `1` (`sms_second_factor_*`) — fine for most
  single-number accounts, may need discovery otherwise.
- No automated tests yet. If you add a test suite, wire it into a
  `SessionStart` hook (see the `session-start-hook` skill) so web sessions can
  run it.
- Single-user assumption: auth sessions are a process-local dict; there's no
  multi-user isolation or persistence across restarts (only `auth.json` is
  persisted).

---

## 9. Git / branch / PR state

- Working branch: **`claude/find-my-flipper-airtag-ui-8u4ok0`**. This is also
  the repository's **default branch** — the repo was created empty and this
  branch is currently the only one.
- **No PR exists** because a PR needs a base branch distinct from the head, and
  head == default here. If a review flow is wanted, create a `main` base from
  the current tree and open this work against it; otherwise this branch *is* the
  mainline.
- Commit trailers in use: `Co-Authored-By: Claude Fable 5` and a
  `Claude-Session:` link. Do **not** put the model identifier anywhere in
  committed artifacts (commit messages, PR text, code) — chat only.
