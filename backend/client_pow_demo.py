# client_pow_demo.py
#
# Minimal Python client to:
#   1) solve signup PoW -> get account_id
#   2) request a PoW challenge
#   3) solve PoW for that challenge
#   4) submit PoW -> earn 1 credit
#
# Requirements:
#   pip install requests
#
# Server assumptions:
#   - FastAPI app running at BASE_URL
#   - /signup_pow expects msg = "signup|ts=<rounded>|cn=<client_nonce>"
#   - /challenge and /submit_pow as in app.py

import time
import json
import base64
import hashlib
from typing import Dict, Any

import os
from dotenv import load_dotenv

import requests

from backend.pow_utils import solve_pow

load_dotenv()

# ---------------------------
# Config
# ---------------------------
BASE_URL = os.getenv("FAUCET_BASE_URL", "http://127.0.0.1:8000")
SIGNUP_BITS = int(os.getenv("SIGNUP_BITS", "24"))  # must match SERVER SIGNUP_BITS
VERBOSE = True


# ---------------------------
# Helpers
# ---------------------------
def b64url_random(n: int = 18) -> str:
    """Simple pseudo-random base64url string."""
    raw = hashlib.sha256(str(time.time_ns()).encode()).digest()[:n]
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ---------------------------
# API calls
# ---------------------------
def signup_pow() -> str:
    """
    Performs signup PoW and returns a new account_id.

    Muss exakt zum Server passen:
      msg = f"signup|ts={rounded}|cn={client_nonce}"
      rounded = (ts // 60) * 60
    """
    ts = int(time.time())
    client_nonce = b64url_random(18)

    rounded = (ts // 60) * 60
    msg = f"signup|ts={rounded}|cn={client_nonce}"

    print(f"[signup] solving PoW: bits={SIGNUP_BITS}")
    pow_nonce, _ = solve_pow(msg, SIGNUP_BITS, verbose=VERBOSE)

    payload = {
        "client_nonce": client_nonce,
        "pow_nonce": pow_nonce,
        "ts": ts,
    }
    r = requests.post(f"{BASE_URL}/signup_pow", json=payload, timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"signup_pow failed {r.status_code}: {r.text}")

    data = r.json()
    account_id = data["account_id"]
    print(f"[signup] account_id={account_id}")
    return account_id


def get_challenge(account_id: str) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {account_id}"}
    r = requests.post(
        f"{BASE_URL}/challenge",
        json={"action": "earn_credit"},
        headers=headers,
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"challenge failed {r.status_code}: {r.text}")
    data = r.json()
    if VERBOSE:
        print(f"[challenge] bits={data['bits']} exp={data['expires_at']}")
    return data


def submit_pow(account_id: str, stamp: str, sig: str, nonce: str) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {account_id}"}
    payload = {"stamp": stamp, "sig": sig, "nonce": nonce}
    r = requests.post(
        f"{BASE_URL}/submit_pow",
        json=payload,
        headers=headers,
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"submit_pow failed {r.status_code}: {r.text}")
    return r.json()


# ---------------------------
# Demo main
# ---------------------------
def main():
    # 1) Signup – nur einmal nötig; account_id kannst du danach speichern.
    account_id = signup_pow()

    # 2) Challenge holen
    ch = get_challenge(account_id)
    stamp = ch["stamp"]
    bits = ch["bits"]
    sig = ch["sig"]

    # 3) PoW für diesen Stamp lösen
    print(f"[claim] solving PoW for claim: bits={bits}")
    nonce, _ = solve_pow(stamp, bits, verbose=VERBOSE)

    # 4) Submit -> sollte credits +1 geben
    res = submit_pow(account_id, stamp, sig, nonce)
    print("[submit]", json.dumps(res, indent=2))


if __name__ == "__main__":
    main()