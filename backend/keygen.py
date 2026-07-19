"""Generate OpenHaystack / FindMy key pairs and write ``.keys`` files.

Refactored from MatthewKuKanich/FindMyFlipper (AirTagGeneration/generate_keys.py)
into an importable function. The cryptography (SECP224R1 key generation, the
advertisement-payload layout, and the base64/hex encodings written to disk) is
unchanged so the resulting ``.keys`` files are byte-compatible with the Flipper
FindMyFlipper app and with ``request_reports``.
"""
import base64
import os
import re

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def advertisement_template():
    adv = ""
    adv += "1e"  # length (30)
    adv += "ff"  # manufacturer specific data
    adv += "4c00"  # company ID (Apple)
    adv += "1219"  # offline finding type and length
    adv += "00"  # state
    for _ in range(22):
        adv += "00"
    adv += "00"  # first two bits of key[0]
    adv += "00"  # hint
    return bytearray.fromhex(adv)


def convert_key_to_hex(private_key, public_key):
    private_key_hex = (
        private_key.private_numbers().private_value.to_bytes(28, byteorder="big").hex()
    )
    public_key_hex = public_key.public_numbers().x.to_bytes(28, byteorder="big").hex()
    return private_key_hex, public_key_hex


def generate_mac_and_payload(public_key):
    key = public_key.public_numbers().x.to_bytes(28, byteorder="big")

    addr = bytearray(key[:6])
    addr[0] |= 0b11000000

    adv = advertisement_template()
    adv[7:29] = key[6:28]
    adv[29] = key[0] >> 6

    return addr.hex(), adv.hex()


# A prefix must be safe to embed in a filename; report parsing splits on the MAC.
_PREFIX_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_prefix(prefix):
    return _PREFIX_RE.sub("", (prefix or "").strip())


def generate_key():
    """Generate a single valid FindMy key pair.

    Retries until the hashed advertisement key has no ``/`` in its first 7
    base64 chars — matching the original generator, which avoids keys whose
    server-side id prefix would be awkward.
    """
    while True:
        private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
        public_key = private_key.public_key()

        private_key_bytes = private_key.private_numbers().private_value.to_bytes(28, byteorder="big")
        public_key_bytes = public_key.public_numbers().x.to_bytes(28, byteorder="big")

        private_key_b64 = base64.b64encode(private_key_bytes).decode("ascii")
        public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

        private_key_hex, public_key_hex = convert_key_to_hex(private_key, public_key)
        mac, payload = generate_mac_and_payload(public_key)

        public_key_hash = hashes.Hash(hashes.SHA256())
        public_key_hash.update(public_key_bytes)
        s256_b64 = base64.b64encode(public_key_hash.finalize()).decode("ascii")

        if "/" not in s256_b64[:7]:
            return {
                "private_key": private_key_b64,
                "advertisement_key": public_key_b64,
                "hashed_adv_key": s256_b64,
                "private_key_hex": private_key_hex,
                "advertisement_key_hex": public_key_hex,
                "mac": mac,
                "payload": payload,
            }


def keyfile_contents(key):
    """Render a key dict into the exact ``.keys`` file body FindMyFlipper writes."""
    return (
        f"Private key: {key['private_key']}\n"
        f"Advertisement key: {key['advertisement_key']}\n"
        f"Hashed adv key: {key['hashed_adv_key']}\n"
        f"Private key (Hex): {key['private_key_hex']}\n"
        f"Advertisement key (Hex): {key['advertisement_key_hex']}\n"
        f"MAC: {key['mac']}\n"
        f"Payload: {key['payload']}\n"
    )


def generate_keys(count, prefix, keys_dir):
    """Generate ``count`` key pairs, writing each to ``<keys_dir>/<name>.keys``.

    ``name`` is ``<prefix>_<mac>`` when a prefix is given, else ``<mac>`` — the
    same convention ``request_reports`` relies on to label reports.
    Returns a list of key dicts, each augmented with its ``name`` and ``file``.
    """
    prefix = sanitize_prefix(prefix)
    os.makedirs(keys_dir, exist_ok=True)

    results = []
    for _ in range(count):
        key = generate_key()
        fname = f"{prefix}_{key['mac']}.keys" if prefix else f"{key['mac']}.keys"
        path = os.path.join(keys_dir, fname)
        with open(path, "w") as f:
            f.write(keyfile_contents(key))
        key["name"] = fname[:-5]
        key["file"] = fname
        results.append(key)
    return results
