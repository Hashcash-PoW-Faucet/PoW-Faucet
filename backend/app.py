from __future__ import annotations
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import json
import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

# Redeem request models
from typing import Optional as TypingOptional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
# Local imports (support running as `app:app` and as `backend.app:app`)
try:
    from .pow_utils import pow_ok  # type: ignore
except ImportError:
    from pow_utils import pow_ok  # type: ignore

from pathlib import Path
try:
    from .dex import create_dex_router, create_dex_admin_router  # type: ignore
except ImportError:
    from dex import create_dex_router, create_dex_admin_router  # type: ignore

# Load environment variables from .env file
BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BACKEND_DIR / ".env")

# ---------------------------
# Config
# ---------------------------
# Always resolve paths relative to this backend/ directory, not the current working directory.
# This prevents accidentally creating a new empty `faucet.db` in the project root when starting
# uvicorn from a different CWD.
BASE_DIR = Path(__file__).resolve().parent  # .../backend

_env_db = (os.getenv("FAUCET_DB") or "").strip()
if _env_db:
    _p = Path(_env_db)
    # If FAUCET_DB is a relative path (e.g. "faucet.db"), interpret it relative to backend/.
    DB_PATH = str((BASE_DIR / _p).resolve()) if not _p.is_absolute() else str(_p)
else:
    DB_PATH = str((BASE_DIR / "faucet.db").resolve())

STAMP_HMAC_KEY = os.getenv("STAMP_HMAC_KEY", "change-me-stamp-key").encode()
IPTAG_HMAC_KEY = os.getenv("IPTAG_HMAC_KEY", "change-me-iptag-key").encode()

# PoW parameters
CLAIM_BITS = int(os.getenv("CLAIM_BITS", "26"))          # ~low effort
SIGNUP_BITS = int(os.getenv("SIGNUP_BITS", "28"))        # harder than claim
STAMP_TTL_SEC = int(os.getenv("STAMP_TTL_SEC", "3600"))   # stamp expiry
COOLDOWN_SEC = int(os.getenv("COOLDOWN_SEC", "60"))     # 15 min cooldown
DAILY_EARN_CAP = int(os.getenv("DAILY_EARN_CAP", "20"))  # max credits/day
MAX_SIGNUPS_PER_IP_PER_DAY = int(os.getenv("MAX_SIGNUPS_PER_IP_PER_DAY", "2"))  # max new accounts per IP tag per day
DEX_ADMIN_TOKEN = os.getenv("DEX_ADMIN_TOKEN", "")
DEX_MIN_CONFS = int(os.getenv("DEX_MIN_CONFS", "6"))
#
# Redeem / tip parameters
MIN_REDEEM_CREDITS = int(os.getenv("MIN_REDEEM_CREDITS", "100"))      # minimum credits required to even request a redeem
REDEEM_COST_CREDITS = int(os.getenv("REDEEM_COST_CREDITS", "100"))    # credits deducted per redeem attempt

# File where redeem requests are queued for an external pay script (JSON lines)
REDEEM_QUEUE_FILE = os.getenv("REDEEM_QUEUE_FILE", str(BACKEND_DIR / "redeem_queue.jsonl"))

# Whether /redeem_log may return entries for *all* accounts (privacy-sensitive).
# Default: only return entries for the authenticated account.
REDEEM_LOG_PUBLIC = os.getenv("REDEEM_LOG_PUBLIC", "0") == "1"

# ---------------------------
# Micro-DEX parameters
# ---------------------------
# TTLs are side-dependent:
# - SELL_CREDITS: short window for the taker to pay on-chain
# - BUY_CREDITS:  longer window because the maker might be offline
DEX_TRADE_TTL_SELL_SEC = int(os.getenv("DEX_TRADE_TTL_SELL_SEC", "1200"))      # 20 min
DEX_TRADE_TTL_BUY_SEC = int(os.getenv("DEX_TRADE_TTL_BUY_SEC", "172800"))      # 48 h
DEX_ALLOWED_SIDES = {"SELL_CREDITS", "BUY_CREDITS"}  # BUY_CREDITS: escrow happens on taker side


def tail_jsonl_lines(path: str, n: int) -> List[str]:
    """Return the last n lines of a text file (best-effort), without loading the whole file."""
    if n <= 0:
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return []

            block_size = 4096
            data = b""
            lines: list[bytes] = []
            pos = end

            # Read blocks from the end until we have enough lines.
            while pos > 0 and len(lines) <= n:
                step = block_size if pos >= block_size else pos
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
                lines = data.splitlines()

            tail = lines[-n:]
            return [b.decode("utf-8", errors="replace") for b in tail]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[redeem_log] failed to tail '{path}': {e}")
        return []

# Path to a JSON config describing supported coins and their RPC / tip settings.
# Example (coins.json):
# {
#  "BTC": {
#    "name": "Bitcoin",
#    "short": "BTC",
#    "homepage": "https://bitcoin.org",
#    "rpc_url": "http://192.168.178.1:8332/",
#    "rpc_user": "BTC_user",
#    "rpc_password": "BTC_pw",
#    "address_validate_method": "validateaddress",
#    "min_tip": "0",
#    "max_tip": "0.000001"
#  },
#  "LTC": {
#    "name": "Litecoin",
#    "short": "LTC",
#    "homepage": "https://vecocoin.com/",
#    "rpc_url": "http://192.168.178.3:9332/",
#    "rpc_user": "LTC_user",
#    "rpc_password": "LTC_pw",
#    "address_validate_method": "validateaddress",
#    "min_tip": "0.00001",
#    "max_tip": "0.0001"
#  }
#}

# ---------------------------
# Coin config, validation, and redeem queue helpers
# ---------------------------
# Keep your env default
COINS_CONFIG_PATH = os.getenv("COINS_CONFIG_PATH", str(BASE_DIR / "coins.json"))

# Resolve relative paths against the directory this file lives in (backend/)
def _resolve_backend_path(p: str) -> Path:
    path = Path(p)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path

def load_coins_config() -> dict:
    """
    Load coin configuration from COINS_CONFIG_PATH.

    The file is expected to be a JSON object mapping currency codes (e.g. "SLM")
    to dicts containing at least rpc_url / rpc_user / rpc_password for coins
    that need RPC-based address validation.
    """
    cfg_path = _resolve_backend_path(COINS_CONFIG_PATH)

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("coins config must be a JSON object")
        return data

    except FileNotFoundError:
        print(f"[coins] config file '{cfg_path}' not found; running without coin-specific RPC config.")
        return {}

    except Exception as e:
        print(f"[coins] failed to load config '{cfg_path}': {e}")
        return {}

COINS_CONFIG = load_coins_config()


def call_coin_rpc(currency: str, method: str, params: Optional[list] = None):
    """
    Call a coin JSON-RPC daemon using settings from COINS_CONFIG.

    This is used primarily for address validation (e.g. 'verifyaddress' or 'validateaddress').
    """
    if params is None:
        params = []
    cfg = COINS_CONFIG.get(currency)
    if not cfg:
        raise RuntimeError(f"No RPC config for currency {currency}")
    url = cfg.get("rpc_url")
    user = cfg.get("rpc_user")
    password = cfg.get("rpc_password")
    if not url or user is None or password is None:
        raise RuntimeError(f"Incomplete RPC config for currency {currency}")

    payload = {
        "jsonrpc": "1.0",
        "id": "faucet",
        "method": method,
        "params": params,
    }
    try:
        resp = requests.post(
            url,
            json=payload,
            auth=(user, password),
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"{currency} RPC request failed: {e}") from e

    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(f"{currency} RPC error: {data['error']}")
    return data.get("result")


def is_valid_address(currency: str, addr: str) -> bool:
    """
    Generic address validation using coin config.

    If no config is present for the currency, this function returns True
    (no validation). If an RPC config exists, it will call the method
    specified by 'address_validate_method' (default: 'verifyaddress') and:
    - if the result is a dict with 'isvalid', return that flag
    - if the result is a boolean, return it
    - otherwise, treat as invalid.
    """
    cfg = COINS_CONFIG.get(currency)
    if not cfg:
        # No validation configured for this currency.
        return True

    method = cfg.get("address_validate_method", "verifyaddress")
    try:
        res = call_coin_rpc(currency, method, [addr])
    except Exception:
        return False

    if isinstance(res, dict) and "isvalid" in res:
        return bool(res.get("isvalid"))
    if isinstance(res, bool):
        return res
    return False


def maybe_send_tip(currency: str, tip_address: str) -> tuple[float, Optional[str], Optional[str]]:
    """
    Attempt to send a discretionary crypto tip for the given currency and address.

    Returns (amount, txid, rpc_error):
    - amount == 0.0 and txid is None if no tip was sent.
    - rpc_error is a short diagnostic string (best-effort) that explains why a tip was not sent
      when a coin config exists (e.g. "insufficient faucet balance", "RPC error: ...").

    This function makes no guarantees and is best-effort only.
    """
    cfg = COINS_CONFIG.get(currency)
    if not cfg:
        # No RPC/tip config → no on-chain tip, just record the redeem.
        return 0.0, None, None

    # Parse min/max tip from config (strings or numbers).
    try:
        min_tip = float(cfg.get("min_tip", 0))
    except (TypeError, ValueError):
        min_tip = 0.0
    try:
        max_tip = float(cfg.get("max_tip", 0))
    except (TypeError, ValueError):
        max_tip = 0.0

    if max_tip <= 0:
        # Tipping disabled or misconfigured.
        return 0.0, None, "tipping disabled or misconfigured (max_tip <= 0)"

    if min_tip < 0:
        min_tip = 0.0
    if min_tip > max_tip:
        min_tip = max_tip

    # Pick a random amount in [min_tip, max_tip].
    rng = secrets.SystemRandom()
    amount = rng.uniform(min_tip, max_tip)
    # Round to 8 decimal places to be friendly to Bitcoin-like RPCs.
    amount = float(f"{amount:.8f}")
    if amount <= 0:
        return 0.0, None, "computed tip amount <= 0"

    try:
        # Check wallet balance first (best-effort).
        bal = call_coin_rpc(currency, "getbalance")
        if isinstance(bal, str):
            bal = float(bal)
        if not isinstance(bal, (int, float)):
            return 0.0, None, f"unexpected getbalance result type: {type(bal).__name__}"
        if bal < amount:
            return 0.0, None, f"insufficient faucet balance (balance={bal}, needed={amount})"

        txid = call_coin_rpc(currency, "sendtoaddress", [tip_address, amount])
        if not isinstance(txid, str):
            txid = str(txid)
        return amount, txid, None
    except Exception as e:
        # Any RPC error is treated as "no tip sent"; caller can still record the redeem.
        # Keep error short to avoid leaking details.
        msg = str(e)
        if len(msg) > 300:
            msg = msg[:300] + "..."
        return 0.0, None, f"RPC error: {type(e).__name__}: {msg}"


def enqueue_redeem_request(
    request_id: int,
    ts: int,
    account_id: str,
    tip_address: str,
    currency: str,
    credits_before: int,
    credits_spent: int,
    tip_amount: float,
    txid: Optional[str],
    rpc_error: Optional[str],
) -> None:
    """
    Append a redeem request entry to a JSONL queue file for an external pay script or audit log.

    This file is an implementation detail for automation and does not imply
    any guarantee of payout or fixed exchange rate.
    """
    entry = {
        "id": request_id,
        "created_at": ts,
        "account_id": account_id,
        "tip_address": tip_address,
        "currency": currency,
        "credits_before": credits_before,
        "credits_spent": credits_spent,
        "tip_amount": tip_amount,
        "txid": txid,
        "rpc_error": rpc_error,
    }

    # Attach coin-specific internal config, if available
    cfg = COINS_CONFIG.get(currency, {})
    if "min_tip" in cfg:
        entry["min_tip"] = str(cfg["min_tip"])
    if "max_tip" in cfg:
        entry["max_tip"] = str(cfg["max_tip"])

    if entry.get("rpc_error") and len(str(entry["rpc_error"])) > 300:
        entry["rpc_error"] = str(entry["rpc_error"])[:300] + "..."
    # Append as a single JSON line
    with open(REDEEM_QUEUE_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------
# Helpers: encoding / crypto
# ---------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def address_from_secret(secret: str) -> str:
    # Derive a stable public address from the secret (private key), hex-only (0-9a-f)
    digest_hex = hashlib.sha256(secret.encode()).hexdigest()
    # Use 160 bits (40 hex characters) as a shortened, stable address
    return digest_hex[:40]


def b64url_bytes(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())


def hmac_sha256(key: bytes, msg: str) -> str:
    return b64url(hmac.new(key, msg.encode(), hashlib.sha256).digest())


def consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def now_unix() -> int:
    return int(time.time())


def day_key(ts: Optional[int] = None) -> str:
    # simple UTC day key YYYY-MM-DD
    ts = ts or now_unix()
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


# ---------------------------
# IP tag (privacy-preserving)
# ---------------------------
def ip_tag(ip: str) -> str:
    # Rotate daily to reduce linkability; still stable for 120s stamp TTL.
    msg = f"{ip}|{day_key()}"
    digest = hmac.new(IPTAG_HMAC_KEY, msg.encode(), hashlib.sha256).digest()
    return b64url(digest[:12])  # short tag


def get_client_ip(req: Request) -> str:
    # NOTE: If behind a reverse proxy, DO NOT trust X-Forwarded-For unless you control it.
    return req.client.host


# ---------------------------
# Stateless stamp
# ---------------------------
def make_stamp(action: str, account_id: str, seq: int, bits: int, exp: int, ipt: str) -> str:
    rnd = b64url(secrets.token_bytes(12))
    # v1|k=v style is easy to parse
    return f"v1|act={action}|acct={account_id}|seq={seq}|bits={bits}|exp={exp}|ip={ipt}|rand={rnd}"


def parse_stamp(stamp: str) -> dict:
    parts = stamp.split("|")
    if not parts or parts[0] != "v1":
        raise ValueError("bad version")
    kv = {}
    for p in parts[1:]:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        kv[k] = v
    # required keys
    for k in ("act", "acct", "seq", "bits", "exp", "ip", "rand"):
        if k not in kv:
            raise ValueError(f"missing {k}")
    kv["seq"] = int(kv["seq"])
    kv["bits"] = int(kv["bits"])
    kv["exp"] = int(kv["exp"])
    return kv


# ---------------------------
# In-memory IP lock with TTL
# (OK for 1 process; use Redis for multi-worker)
# ---------------------------
@dataclass
class IpLock:
    account_id: str
    expires_at: int


class IpLockMap:
    def __init__(self):
        self._locks: dict[str, IpLock] = {}

    def try_acquire(self, ipt: str, account_id: str, ttl_sec: int) -> bool:
        now = now_unix()
        lock = self._locks.get(ipt)
        if lock and lock.expires_at > now and lock.account_id != account_id:
            return False
        self._locks[ipt] = IpLock(account_id=account_id, expires_at=now + ttl_sec)
        return True

    def release(self, ipt: str, account_id: str) -> None:
        lock = self._locks.get(ipt)
        if lock and lock.account_id == account_id:
            del self._locks[ipt]


IP_LOCKS = IpLockMap()


# ---------------------------
# DB
# ---------------------------
def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)  # autocommit
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    return con


def init_db():
    con = db()
    con.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
      account_id TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      next_seq INTEGER NOT NULL,
      credits INTEGER NOT NULL,
      locked_credits INTEGER NOT NULL DEFAULT 0,
      cooldown_until INTEGER NOT NULL,
      earn_day TEXT NOT NULL,
      earned_today INTEGER NOT NULL
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS signup_limits (
      ip_tag TEXT NOT NULL,
      day TEXT NOT NULL,
      count INTEGER NOT NULL,
      PRIMARY KEY(ip_tag, day)
    );
    """)
    con.execute("""
    CREATE TABLE IF NOT EXISTS redeem_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at INTEGER NOT NULL,
      account_id TEXT NOT NULL,
      tip_address TEXT NOT NULL,
      currency TEXT NOT NULL,
      credits_before INTEGER NOT NULL,
      credits_spent INTEGER NOT NULL,
      state TEXT NOT NULL,
      note TEXT
    );
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dex_orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at INTEGER NOT NULL,
      maker_account_id TEXT NOT NULL,
      side TEXT NOT NULL,
      currency TEXT NOT NULL,
      credits_amount INTEGER NOT NULL,
      price_sat_per_credit INTEGER NOT NULL,
      pay_to_address TEXT NOT NULL,
      status TEXT NOT NULL
    );
    """)

    con.execute("""
    CREATE TABLE IF NOT EXISTS dex_trades (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at INTEGER NOT NULL,
      order_id INTEGER NOT NULL,
      maker_account_id TEXT NOT NULL,
      taker_account_id TEXT NOT NULL,
      side TEXT NOT NULL,
      currency TEXT NOT NULL,
      credits_amount INTEGER NOT NULL,
      pay_to_address TEXT NOT NULL,
      expected_sats INTEGER NOT NULL,
      txid TEXT,
      confs INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      state TEXT NOT NULL,
      settled_at INTEGER
    );
    """)

    con.execute("CREATE INDEX IF NOT EXISTS idx_dex_orders_open ON dex_orders(status, currency, side, price_sat_per_credit);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_dex_trades_state ON dex_trades(state, currency);")

    con.close()


def get_account(con: sqlite3.Connection, account_id: str):
    cur = con.execute("SELECT account_id, created_at, next_seq, credits, cooldown_until, earn_day, earned_today FROM accounts WHERE account_id=?",
                      (account_id,))
    row = cur.fetchone()
    return row


def create_account(con: sqlite3.Connection) -> tuple[str, str]:
    """
    Create a new account using a freshly generated secret.
    Only the derived address is stored in the DB; the secret is returned to the caller.
    """
    while True:
        # Hex secret: only characters 0-9a-f, no '-' or '_'
        secret = secrets.token_hex(24)  # 24 bytes -> 48 hex characters
        addr = address_from_secret(secret)
        ts = now_unix()
        try:
            con.execute(
                "INSERT INTO accounts(account_id, created_at, next_seq, credits, cooldown_until, earn_day, earned_today) VALUES(?,?,?,?,?,?,?)",
                (addr, ts, 0, 0, 0, day_key(ts), 0)
            )
            return secret, addr
        except sqlite3.IntegrityError:
            # Extremely unlikely address collision; try again with a new secret.
            continue


def reset_daily_if_needed(con: sqlite3.Connection, account_id: str):
    ts = now_unix()
    dk = day_key(ts)
    con.execute("""
        UPDATE accounts
        SET earn_day=?, earned_today=0
        WHERE account_id=? AND earn_day<>?
    """, (dk, account_id, dk))


def require_admin(req: Request) -> None:
    token = (req.headers.get("x-admin-token") or "").strip()
    if not DEX_ADMIN_TOKEN or token != DEX_ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin only")


# Atomic accept of seq (prevents replay/races)

def accept_pow_and_credit(con: sqlite3.Connection, account_id: str, expected_seq: int) -> bool:
    ts = now_unix()
    dk = day_key(ts)

    # Reset daily counter if day changed
    reset_daily_if_needed(con, account_id)

    # Enforce daily cap + cooldown + atomic seq increment
    # We do it in a transaction to be safe.
    con.execute("BEGIN IMMEDIATE;")
    try:
        row = con.execute(
            "SELECT next_seq, credits, cooldown_until, earn_day, earned_today FROM accounts WHERE account_id=?",
            (account_id,)
        ).fetchone()
        if not row:
            raise ValueError("no account")
        next_seq, credits, cooldown_until, earn_day, earned_today = row

        if next_seq != expected_seq:
            con.execute("ROLLBACK;")
            return False

        if cooldown_until > ts:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=429, detail="cooldown")

        if earned_today >= DAILY_EARN_CAP:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=429, detail="daily cap reached")

        con.execute("""
            UPDATE accounts
            SET next_seq = next_seq + 1,
                credits  = credits + 1,
                cooldown_until = ?,
                earned_today = earned_today + 1
            WHERE account_id=? AND next_seq=?
        """, (ts + COOLDOWN_SEC, account_id, expected_seq))

        if con.total_changes == 0:
            con.execute("ROLLBACK;")
            return False

        con.execute("COMMIT;")
        return True
    except HTTPException:
        raise
    except Exception:
        con.execute("ROLLBACK;")
        raise


# ---------------------------
# API models
# ---------------------------
class SignupPowIn(BaseModel):
    client_nonce: str
    pow_nonce: str
    ts: int


class SignupPowOut(BaseModel):
    account_id: str


class SignupStatusOut(BaseModel):
    allowed: bool           # whether a new signup is allowed for this IP today
    remaining: int          # how many signups are left for this IP today
    cap: int                # daily signup cap per IP
    detail: str             # short status string, e.g. "ok" or "signup cap per ip"


class ChallengeIn(BaseModel):
    action: str = "earn_credit"


class ChallengeOut(BaseModel):
    stamp: str
    sig: str
    bits: int
    expires_at: int


class SubmitPowIn(BaseModel):
    stamp: str
    sig: str
    nonce: str


class SubmitPowOut(BaseModel):
    ok: bool
    credits: int
    next_seq: int
    cooldown_until: int

# Transfer models

class TransferIn(BaseModel):
    to_address: str
    amount: int


class TransferOut(BaseModel):
    ok: bool
    from_credits: int
    to_credits: int


# Response model for account info
class AccountInfoOut(BaseModel):
    account_id: str
    credits: int
    cooldown_until: int
    earned_today: int
    daily_earn_cap: int
    next_seq: int
    server_time: int


class RedeemRequestIn(BaseModel):
    tip_address: str
    currency: TypingOptional[str] = None  # e.g. "BCH", "LTC" – purely informational for now



class RedeemRequestOut(BaseModel):
    ok: bool
    message: str
    credits_left: int
    min_credits: int
    currency: TypingOptional[str] = None
    tip_amount: TypingOptional[float] = None
    txid: TypingOptional[str] = None
    rpc_error: TypingOptional[str] = None


class RedeemLogEntryOut(BaseModel):
    request_id: int
    ts: int
    account_id: str
    currency: str
    tip_amount: TypingOptional[float] = None
    txid: TypingOptional[str] = None
    rpc_error: TypingOptional[str] = None


# Config model for public API
class ConfigOut(BaseModel):
    claim_bits: int
    signup_bits: int
    stamp_ttl_sec: int
    cooldown_sec: int
    daily_earn_cap: int
    min_redeem_credits: int
    redeem_cost_credits: int
    supported_currencies: List[str]
    coins: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------
# App
# ---------------------------
app = FastAPI()

origins = [
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "https://hashcash-demo.dynv6.net",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    init_db()


def auth_account(req: Request) -> str:
    # Bearer token is the account secret (private key); derive address from it.
    # Header: Authorization: Bearer <secret>
    auth = req.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    secret = auth.split(" ", 1)[1].strip()
    if not secret:
        raise HTTPException(status_code=401, detail="empty bearer token")
    return address_from_secret(secret)


@app.get("/signup_status", response_model=SignupStatusOut)
def signup_status(req: Request):
    """
    Return the current signup status for the caller's IP address.

    This is a convenience endpoint for the frontend so it can decide whether
    to start an expensive signup PoW. It is *advisory* only: an IP could still
    hit the cap between this check and the actual /signup_pow call.
    """
    ipt = ip_tag(get_client_ip(req))
    today = day_key()

    con = db()
    try:
        row = con.execute(
            "SELECT count FROM signup_limits WHERE ip_tag=? AND day=?",
            (ipt, today),
        ).fetchone()
        current = row[0] if row else 0
        remaining = max(0, MAX_SIGNUPS_PER_IP_PER_DAY - current)
        allowed = remaining > 0
        detail = "ok" if allowed else "signup cap per ip"
        return SignupStatusOut(
            allowed=allowed,
            remaining=remaining,
            cap=MAX_SIGNUPS_PER_IP_PER_DAY,
            detail=detail,
        )
    finally:
        con.close()


@app.post("/signup_pow", response_model=SignupPowOut)
def signup_pow(data: SignupPowIn, req: Request):
    # anonymous signup, but costly
    # Use rounded ts to avoid infinite new challenges.
    ts_now = now_unix()
    if abs(data.ts - ts_now) > 3600:
        raise HTTPException(status_code=400, detail="bad ts window")

    rounded = (data.ts // 60) * 60
    # Signup PoW message must be reconstructible by the client.
    # Do NOT include any server-secret here; rely on PoW difficulty + IP rate limiting instead.
    msg = f"signup|ts={rounded}|cn={data.client_nonce}"
    if not pow_ok(msg, data.pow_nonce, SIGNUP_BITS):
        raise HTTPException(status_code=400, detail="invalid signup pow")

    ipt = ip_tag(get_client_ip(req))
    today = day_key()

    con = db()
    try:
        row = con.execute(
            "SELECT count FROM signup_limits WHERE ip_tag=? AND day=?",
            (ipt, today),
        ).fetchone()
        current = row[0] if row else 0
        if current >= MAX_SIGNUPS_PER_IP_PER_DAY:
            raise HTTPException(status_code=429, detail="signup cap per ip")

        # Create a new account: secret is the private key, addr is the stored address
        secret, addr = create_account(con)

        if row:
            con.execute(
                "UPDATE signup_limits SET count = count + 1 WHERE ip_tag=? AND day=?",
                (ipt, today),
            )
        else:
            con.execute(
                "INSERT INTO signup_limits(ip_tag, day, count) VALUES(?,?,1)",
                (ipt, today),
            )

        # For backward compatibility, the field is still named account_id,
        # but semantically it is now the private secret.
        return SignupPowOut(account_id=secret)
    finally:
        con.close()


@app.post("/challenge", response_model=ChallengeOut)
def challenge(data: ChallengeIn, req: Request):
    account_id = auth_account(req)
    ipt = ip_tag(get_client_ip(req))

    con = db()
    try:
        row = get_account(con, account_id)
        if not row:
            raise HTTPException(status_code=401, detail="unknown account")

        # daily reset if needed
        reset_daily_if_needed(con, account_id)

        # read current state
        _, _, next_seq, credits, cooldown_until, earn_day, earned_today = row
        ts = now_unix()
        if cooldown_until > ts:
            raise HTTPException(status_code=429, detail="cooldown")
        if earned_today >= DAILY_EARN_CAP:
            raise HTTPException(status_code=429, detail="daily cap reached")

        # IP lock: deny parallel mining from same IP tag
        if not IP_LOCKS.try_acquire(ipt, account_id, STAMP_TTL_SEC):
            raise HTTPException(status_code=429, detail="ip busy (no parallel mining)")

        exp = ts + STAMP_TTL_SEC
        bits = CLAIM_BITS  # could adapt per account/ip
        stamp = make_stamp(action=data.action, account_id=account_id, seq=next_seq, bits=bits, exp=exp, ipt=ipt)
        sig = hmac_sha256(STAMP_HMAC_KEY, stamp)
        return ChallengeOut(stamp=stamp, sig=sig, bits=bits, expires_at=exp)
    finally:
        con.close()


@app.post("/submit_pow", response_model=SubmitPowOut)
def submit_pow(data: SubmitPowIn, req: Request):
    account_id = auth_account(req)
    ipt = ip_tag(get_client_ip(req))

    # 1) verify signature
    expected_sig = hmac_sha256(STAMP_HMAC_KEY, data.stamp)
    if not consteq(expected_sig, data.sig):
        raise HTTPException(status_code=400, detail="bad sig")

    # 2) parse stamp
    try:
        kv = parse_stamp(data.stamp)
    except Exception:
        raise HTTPException(status_code=400, detail="bad stamp")

    if kv["acct"] != account_id:
        raise HTTPException(status_code=400, detail="acct mismatch")
    if kv["ip"] != ipt:
        raise HTTPException(status_code=400, detail="ip mismatch")
    if kv["exp"] < now_unix():
        # release lock (best-effort)
        IP_LOCKS.release(ipt, account_id)
        raise HTTPException(status_code=400, detail="expired")

    # 3) verify PoW
    if not pow_ok(data.stamp, data.nonce, kv["bits"]):
        raise HTTPException(status_code=400, detail="bad pow")

    # 4) atomically accept seq and credit
    con = db()
    try:
        ok = accept_pow_and_credit(con, account_id, kv["seq"])
        if not ok:
            raise HTTPException(status_code=409, detail="stale seq / replay")

        # fetch updated state for response
        row = get_account(con, account_id)
        _, _, next_seq, credits, cooldown_until, _, _ = row
        return SubmitPowOut(ok=True, credits=credits, next_seq=next_seq, cooldown_until=cooldown_until)
    finally:
        con.close()
        # release IP lock on success (best-effort)
        IP_LOCKS.release(ipt, account_id)


# New endpoint: /cancel_pow
@app.post("/cancel_pow")
def cancel_pow(req: Request):
    """Release the current IP mining lock for this account (best-effort).

    Useful when the user cancels mining client-side and will not submit a PoW,
    which would otherwise keep the IP lock until STAMP_TTL_SEC expires.

    NOTE: This is in-memory and only works within the same backend process.
    """
    account_id = auth_account(req)
    ipt = ip_tag(get_client_ip(req))
    IP_LOCKS.release(ipt, account_id)
    return {"ok": True}


#
# ---------------------------
# /config endpoint: Public PoW & faucet parameters
# ---------------------------
@app.get("/config", response_model=ConfigOut)
def get_config():
    """
    Public configuration values for the frontend.
    This avoids duplicating difficulty and policy settings in the browser.
    Also exposes a minimal set of coin metadata so the UI can describe
    supported redemption coins without hardcoding them.
    """
    # Build a lightweight metadata dict for coins that the frontend can use
    coins_meta: Dict[str, Any] = {}
    for sym, cfg in COINS_CONFIG.items():
        # cfg is a dict from coins.json; be defensive about missing keys
        coins_meta[sym] = {
            "symbol": sym,
            "name": cfg.get("name") or sym,
            "short": cfg.get("short") or sym,
            "homepage": cfg.get("homepage") or "",
            "dex_min_confs": int(cfg.get("dex_min_confs") or cfg.get("min_confs") or DEX_MIN_CONFS),
            "dex_enabled": bool(cfg.get("dex_enabled") or False),
            # Public redeem/tip range metadata (safe to expose):
            # Keep as strings to avoid float formatting surprises in the UI.
            "min_tip": str(cfg.get("min_tip", "")) if cfg.get("min_tip") is not None else "",
            "max_tip": str(cfg.get("max_tip", "")) if cfg.get("max_tip") is not None else "",
        }

    return ConfigOut(
        claim_bits=CLAIM_BITS,
        signup_bits=SIGNUP_BITS,
        stamp_ttl_sec=STAMP_TTL_SEC,
        cooldown_sec=COOLDOWN_SEC,
        daily_earn_cap=DAILY_EARN_CAP,
        min_redeem_credits=MIN_REDEEM_CREDITS,
        redeem_cost_credits=REDEEM_COST_CREDITS,
        supported_currencies=sorted(COINS_CONFIG.keys()),
        coins=coins_meta,
    )


# ---------------------------
# /me endpoint: Account info
# ---------------------------
@app.get("/me", response_model=AccountInfoOut)
def get_me(req: Request):
    account_id = auth_account(req)
    con = db()
    try:
        # Ensure daily counters are reset if the day has changed
        reset_daily_if_needed(con, account_id)
        row = get_account(con, account_id)
        if not row:
            raise HTTPException(status_code=401, detail="unknown account")
        _, _, next_seq, credits, cooldown_until, earn_day, earned_today = row
        return AccountInfoOut(
            account_id=account_id,
            credits=credits,
            cooldown_until=cooldown_until,
            earned_today=earned_today,
            daily_earn_cap=DAILY_EARN_CAP,
            next_seq=next_seq,
            server_time=now_unix(),
        )
    finally:
        con.close()


# ---------------------------
# /transfer endpoint: Move credits to another address
# ---------------------------

@app.post("/transfer", response_model=TransferOut)
def transfer(data: TransferIn, req: Request):
    from_addr = auth_account(req)
    to_addr = data.to_address.strip()
    amount = data.amount

    if amount <= 0:
        raise HTTPException(status_code=400, detail="amount must be positive")
    if not to_addr:
        raise HTTPException(status_code=400, detail="missing recipient address")
    if from_addr == to_addr:
        raise HTTPException(status_code=400, detail="cannot send to self")

    con = db()
    try:
        # Use an explicit transaction to avoid race conditions
        con.execute("BEGIN IMMEDIATE;")

        # Load sender
        row_from = get_account(con, from_addr)
        if not row_from:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=401, detail="unknown sender account")
        _, _, _, from_credits, _, _, _ = row_from
        # Note: locked_credits are escrowed and are NOT part of `credits`; therefore they cannot be transferred.

        if from_credits < amount:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="insufficient credits")

        # Load recipient
        row_to = get_account(con, to_addr)
        if not row_to:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=404, detail="unknown recipient address")

        # Perform transfer
        con.execute(
            "UPDATE accounts SET credits = credits - ? WHERE account_id=?",
            (amount, from_addr),
        )
        con.execute(
            "UPDATE accounts SET credits = credits + ? WHERE account_id=?",
            (amount, to_addr),
        )

        con.execute("COMMIT;")

        # Fetch updated balances
        row_from2 = get_account(con, from_addr)
        row_to2 = get_account(con, to_addr)
        _, _, _, from_credits2, _, _, _ = row_from2
        _, _, _, to_credits2, _, _, _ = row_to2

        return TransferOut(
            ok=True,
            from_credits=from_credits2,
            to_credits=to_credits2,
        )
    except HTTPException:
        # Re-raise HTTP exceptions after rollback
        raise
    except Exception:
        con.execute("ROLLBACK;")
        raise
    finally:
        con.close()


def _supported_currency(sym: str) -> bool:
    sym = (sym or "").strip().upper()
    return bool(sym) and sym in COINS_CONFIG


def _lock_credits_atomic(con: sqlite3.Connection, account_id: str, amount: int) -> None:
    """Move credits -> locked_credits atomically. Raises ValueError on failure."""
    if amount <= 0:
        raise ValueError("amount must be positive")

    cur = con.execute(
        """
        UPDATE accounts
        SET credits = credits - ?,
            locked_credits = locked_credits + ?
        WHERE account_id = ?
          AND credits >= ?
        """,
        (amount, amount, account_id, amount),
    )
    if cur.rowcount != 1:
        raise ValueError("insufficient credits or unknown account")



def _unlock_credits_atomic(con: sqlite3.Connection, account_id: str, amount: int) -> None:
    """Move locked_credits -> credits atomically. Raises ValueError on failure."""
    if amount <= 0:
        raise ValueError("amount must be positive")

    cur = con.execute(
        """
        UPDATE accounts
        SET credits = credits + ?,
            locked_credits = locked_credits - ?
        WHERE account_id = ?
          AND locked_credits >= ?
        """,
        (amount, amount, account_id, amount),
    )
    if cur.rowcount != 1:
        raise ValueError("insufficient locked credits or unknown account")


def _transfer_locked_credits_atomic(
    con: sqlite3.Connection,
    from_account_id: str,
    to_account_id: str,
    amount: int,
) -> None:
    """Move `amount` credits from `from_account_id.locked_credits` -> `to_account_id.credits`.

    IMPORTANT:
    - This function assumes the caller already started a DB transaction (e.g., BEGIN IMMEDIATE).
    - It does not COMMIT/ROLLBACK by itself.
    """
    amount = int(amount)
    if amount <= 0:
        raise ValueError("amount must be positive")

    # Deduct from source locked balance
    cur = con.execute(
        """
        UPDATE accounts
        SET locked_credits = locked_credits - ?
        WHERE account_id = ? AND locked_credits >= ?
        """,
        (amount, str(from_account_id), amount),
    )
    if cur.rowcount != 1:
        raise ValueError("insufficient locked balance or unknown source account")

    # Credit recipient available balance
    cur = con.execute(
        """
        UPDATE accounts
        SET credits = credits + ?
        WHERE account_id = ?
        """,
        (amount, str(to_account_id)),
    )
    if cur.rowcount != 1:
        raise ValueError("recipient account not found")

# ---------------------------
# Micro-DEX: mount router
# ---------------------------
app.include_router(
    create_dex_router(
        db_func=db,
        auth_func=auth_account,
        now_unix_func=now_unix,
        is_valid_address_func=is_valid_address,
        supported_currency_func=_supported_currency,
        trade_ttl_sell_sec=DEX_TRADE_TTL_SELL_SEC,
        trade_ttl_buy_sec=DEX_TRADE_TTL_BUY_SEC,
        allowed_sides=set(DEX_ALLOWED_SIDES),
        lock_credits_atomic_func=_lock_credits_atomic,
        unlock_credits_atomic_func=_unlock_credits_atomic,
    ),
    prefix="/dex",
)

app.include_router(
    create_dex_admin_router(
        db,
        require_admin,
        now_unix,
        _transfer_locked_credits_atomic,
    ),
    prefix="/admin/dex",
)


def settle_trade_if_confirmed(con: sqlite3.Connection, trade_id: int) -> bool:
    """Settle exactly once if trade is CONFIRMED.

    Settlement rule:
      maker.locked_credits -> taker.credits

    Returns True if settled, False if not eligible.
    """
    con.execute("BEGIN IMMEDIATE;")
    try:
        row = con.execute(
            """
            SELECT state, side, maker_account_id, taker_account_id, credits_amount
            FROM dex_trades
            WHERE id=?
            """,
            (trade_id,),
        ).fetchone()

        if not row:
            con.execute("ROLLBACK;")
            raise ValueError("unknown trade")

        state, side, maker, taker, amt = row
        side = str(side).upper()
        amt = int(amt)

        if state != "CONFIRMED":
            con.execute("ROLLBACK;")
            return False

        # Guard: flip state first to prevent double-settlement on retries/races.
        cur = con.execute(
            """
            UPDATE dex_trades
            SET state='SETTLED', settled_at=?
            WHERE id=? AND state='CONFIRMED'
            """,
            (now_unix(), trade_id),
        )
        if cur.rowcount != 1:
            con.execute("ROLLBACK;")
            return False

        # Side-aware settlement:
        # - SELL_CREDITS: maker.locked_credits -> taker.credits
        # - BUY_CREDITS:  taker.locked_credits -> maker.credits
        if side == "SELL_CREDITS":
            src = str(maker)
            dst = str(taker)
        elif side == "BUY_CREDITS":
            src = str(taker)
            dst = str(maker)
        else:
            con.execute("ROLLBACK;")
            raise ValueError(f"unsupported trade side for settlement: {side}")

        # Debit source locked
        cur = con.execute(
            """
            UPDATE accounts
            SET locked_credits = locked_credits - ?
            WHERE account_id=? AND locked_credits >= ?
            """,
            (amt, src, amt),
        )
        if cur.rowcount != 1:
            con.execute("ROLLBACK;")
            raise ValueError("insufficient locked credits for settlement")

        # Credit destination available credits
        cur = con.execute(
            "UPDATE accounts SET credits = credits + ? WHERE account_id=?",
            (amt, dst),
        )
        if cur.rowcount != 1:
            con.execute("ROLLBACK;")
            raise ValueError("unknown destination account")

        con.execute("COMMIT;")
        return True

    except Exception:
        try:
            con.execute("ROLLBACK;")
        except Exception:
            pass
        raise


@app.get("/redeem_log", response_model=List[RedeemLogEntryOut])
def redeem_log(req: Request, limit: int = 10, all: bool = False):
    """Return recent redeem audit entries from the JSONL queue.

    Privacy default: only return entries for the authenticated account.
    If REDEEM_LOG_PUBLIC=1 and all=true, return entries across all accounts.
    """
    account_id = None
    scope_all = bool(all) and REDEEM_LOG_PUBLIC
    if not scope_all:
        account_id = auth_account(req)
    limit = int(limit) if isinstance(limit, int) else 10
    if limit < 1:
        limit = 1
    if limit > 50:
        limit = 50

    # Read more than `limit` lines to compensate for filtering.
    # (If scope_all is enabled, we still keep a sane bound.)
    read_lines = max(200, limit * 50)
    raw_lines = tail_jsonl_lines(REDEEM_QUEUE_FILE, read_lines)

    parsed: list[dict] = []
    for line in raw_lines:
        line = (line or "").strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if not scope_all and obj.get("account_id") != account_id:
            continue
        parsed.append(obj)

    # Sort ascending so we can take the last `limit` entries.
    parsed.sort(key=lambda x: (int(x.get("created_at", 0) or 0), int(x.get("id", 0) or 0)))
    parsed = parsed[-limit:]

    out: list[RedeemLogEntryOut] = []
    for e in parsed:
        try:
            rid = int(e.get("id", 0) or 0)
        except Exception:
            rid = 0
        try:
            ts = int(e.get("created_at", 0) or 0)
        except Exception:
            ts = 0
        cur = str(e.get("currency", "") or "")
        acc = str(e.get("account_id", "") or "")
        txid = e.get("txid")
        if txid is not None:
            txid = str(txid)
        rpc_error = e.get("rpc_error")
        if rpc_error is not None:
            rpc_error = str(rpc_error)
        tip_amount = e.get("tip_amount")
        try:
            tip_amount_f = float(tip_amount) if tip_amount is not None else None
        except Exception:
            tip_amount_f = None

        out.append(RedeemLogEntryOut(
            request_id=rid,
            ts=ts,
            account_id=acc,
            currency=cur,
            tip_amount=tip_amount_f,
            txid=txid,
            rpc_error=rpc_error,
        ))

    return out

# ---------------------------
# /redeem_request endpoint: Ask for an external crypto tip
# ---------------------------
@app.post("/redeem_request", response_model=RedeemRequestOut)
def redeem_request(data: RedeemRequestIn, req: Request):
    """
    Log a redeem/tip request and optionally send a best-effort crypto tip.

    This does NOT guarantee any payout or fixed exchange rate.
    The endpoint:
    - checks that the user has at least MIN_REDEEM_CREDITS,
    - deducts REDEEM_COST_CREDITS from their balance,
    - records the request in the redeem_requests table,
    - and, if configured and funded, attempts to send a discretionary on-chain tip
      via JSON-RPC from the faucet operator's own funds.
    """
    account_id = auth_account(req)
    tip_address = data.tip_address.strip()
    currency = (data.currency or "UNKNOWN").strip().upper() or "UNKNOWN"

    if not tip_address:
        raise HTTPException(status_code=400, detail="missing tip address")

    # If we have validation configured for this currency, enforce it.
    if not is_valid_address(currency, tip_address):
        raise HTTPException(status_code=400, detail=f"invalid address for currency {currency}")

    con = db()
    try:
        ts = now_unix()
        con.execute("BEGIN IMMEDIATE;")

        row = con.execute(
            "SELECT credits FROM accounts WHERE account_id=?",
            (account_id,)
        ).fetchone()
        if not row:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=401, detail="unknown account")

        credits_before = row[0]
        if credits_before < MIN_REDEEM_CREDITS:
            con.execute("ROLLBACK;")
            msg = (
                f"Insufficient credits for redeem. You need at least {MIN_REDEEM_CREDITS} credits "
                f"before you can request a tip."
            )
            raise HTTPException(status_code=400, detail=msg)

        # Deduct the redeem cost (bounded so we never go negative)
        cost = min(REDEEM_COST_CREDITS, credits_before)
        credits_after = credits_before - cost

        con.execute(
            "UPDATE accounts SET credits=? WHERE account_id=?",
            (credits_after, account_id),
        )

        cur = con.execute(
            """
            INSERT INTO redeem_requests(created_at, account_id, tip_address, currency, credits_before, credits_spent, state, note)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (ts, account_id, tip_address, currency, credits_before, cost, "pending", None),
        )
        request_id = cur.lastrowid

        # Commit the credit deduction and the recorded request before attempting any RPC calls.
        con.execute("COMMIT;")

        # Best-effort attempt to send an on-chain tip via RPC, based on the coin config.
        tip_amount, txid, rpc_error = maybe_send_tip(currency, tip_address)

        # Update the redeem_requests row with the outcome.
        state = "pending"
        note = None
        if tip_amount > 0 and txid:
            state = "sent"
            note = f"{currency} {tip_amount} txid={txid}"
        elif COINS_CONFIG.get(currency):
            # We had a coin config but no tip could be sent this time; keep the reason for diagnosis
            note = rpc_error or "no tip sent (faucet funds or RPC conditions not met)"

        # Use a new transaction for the state update (best-effort).
        try:
            con.execute("BEGIN IMMEDIATE;")
            con.execute(
                "UPDATE redeem_requests SET state=?, note=? WHERE id=?",
                (state, note, request_id),
            )
            con.execute("COMMIT;")
        except Exception:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass

        # Log this redeem request and outcome to the JSONL queue/audit file.
        enqueue_redeem_request(
            request_id=request_id,
            ts=ts,
            account_id=account_id,
            tip_address=tip_address,
            currency=currency,
            credits_before=credits_before,
            credits_spent=cost,
            tip_amount=tip_amount,
            txid=txid,
            rpc_error=rpc_error,
        )

        if tip_amount > 0 and txid:
            message = (
                f"Redeem request recorded and a discretionary tip of {tip_amount} {currency} has been sent. "
                "There is still no guarantee of future payouts or any fixed exchange rate."
            )
        else:
            message = (
                "Redeem request recorded. This faucet may occasionally send small crypto tips "
                "from its own funds, but there is no guarantee of payout or any fixed exchange rate."
            )

        return RedeemRequestOut(
            ok=True,
            message=message,
            credits_left=credits_after,
            min_credits=MIN_REDEEM_CREDITS,
            currency=currency,
            tip_amount=tip_amount if tip_amount > 0 else None,
            txid=txid,
            rpc_error=rpc_error,
        )
    except HTTPException:
        # Rollback already done or we are about to return an error
        raise
    except Exception:
        try:
            con.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        con.close()


@app.get("/admin/ping")
def admin_ping(req: Request):
    require_admin(req)
    return {"ok": True}