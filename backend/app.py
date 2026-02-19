from __future__ import annotations
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import threading
import json
import requests
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

# Redeem request models
from typing import Optional as TypingOptional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
# Local imports (support running as `app:app` and as `backend.app:app`)
try:
    from .pow_utils import pow_ok  # type: ignore
except ImportError:
    from pow_utils import pow_ok  # type: ignore

from pathlib import Path

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

# Rate limiting (in-memory, single-process). For multi-worker deployments, use Redis.
SUBMIT_RL_MAX = int(os.getenv("SUBMIT_RL_MAX", "30"))                 # max submit attempts per window
SUBMIT_RL_WINDOW_SEC = int(os.getenv("SUBMIT_RL_WINDOW_SEC", "10"))  # window length (seconds)


# ---------------------------
# In-memory rate limiter
# (OK for 1 process; use Redis for multi-worker)
# ---------------------------
@dataclass
class _RlState:
    window_start: int
    count: int


class FixedWindowRateLimiter:
    """Very small in-memory rate limiter (fixed window).

    Keyed by an arbitrary string (e.g. ip tag or account+ip).

    This protects endpoints like /submit_pow against request-spam.
    """

    def __init__(self, max_requests: int, window_sec: int):
        self.max_requests = max(1, int(max_requests))
        self.window_sec = max(1, int(window_sec))
        self._lock = threading.Lock()
        self._state: dict[str, _RlState] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_sec)."""
        now = now_unix()
        with self._lock:
            st = self._state.get(key)
            if st is None:
                self._state[key] = _RlState(window_start=now, count=1)
                return True, 0

            # Reset window if expired
            if now - st.window_start >= self.window_sec:
                st.window_start = now
                st.count = 1
                return True, 0

            # Still in same window
            if st.count >= self.max_requests:
                retry_after = max(1, st.window_start + self.window_sec - now)
                return False, retry_after

            st.count += 1
            return True, 0


SUBMIT_RL = FixedWindowRateLimiter(SUBMIT_RL_MAX, SUBMIT_RL_WINDOW_SEC)

# PoW parameters
CLAIM_BITS = int(os.getenv("CLAIM_BITS", "26"))          # normal mining mode
EXTREME_BITS = int(os.getenv("EXTREME_BITS", "35"))      # extreme mode
SIGNUP_BITS = int(os.getenv("SIGNUP_BITS", "28"))
STAMP_TTL_SEC = int(os.getenv("STAMP_TTL_SEC", "3600"))
COOLDOWN_SEC = int(os.getenv("COOLDOWN_SEC", "60"))     # cooldown in normal mode
EXTREME_DAILY_CAP = int(os.getenv("EXTREME_DAILY_CAP", "300"))
DAILY_EARN_CAP = int(os.getenv("DAILY_EARN_CAP", "20"))  # max credits/day
MAX_SIGNUPS_PER_IP_PER_DAY = int(os.getenv("MAX_SIGNUPS_PER_IP_PER_DAY", "2"))  # max new accounts per IP tag per day

#
# Redeem / tip parameters
MIN_REDEEM_CREDITS = int(os.getenv("MIN_REDEEM_CREDITS", "100"))      # minimum credits required to even request a redeem
REDEEM_COST_CREDITS = int(os.getenv("REDEEM_COST_CREDITS", "100"))    # credits deducted per redeem attempt

# File where redeem requests are queued for an external pay script (JSON lines)
REDEEM_QUEUE_FILE = os.getenv("REDEEM_QUEUE_FILE", str(BACKEND_DIR / "redeem_queue.jsonl"))

# Whether /redeem_log may return entries for *all* accounts (privacy-sensitive).
# Default: only return entries for the authenticated account.
REDEEM_LOG_PUBLIC = os.getenv("REDEEM_LOG_PUBLIC", "0") == "1"


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
            timeout=15,
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


def maybe_send_tip(currency: str, tip_address: str) -> tuple[float, Optional[str], Optional[str], bool]:
    """
    Attempt to send a discretionary crypto tip for the given currency and address.

    Returns (amount, txid, rpc_error, safe_to_unlock):
    - amount == 0.0 and txid is None if no tip was sent.
    - rpc_error is a short diagnostic string (best-effort) that explains why a tip was not sent
      when a coin config exists (e.g. "insufficient faucet balance", "RPC error: ...").
    - safe_to_unlock indicates whether it is safe to unlock previously locked credits because
      we can be sure that no coins left the faucet wallet for this attempt.

    This function makes no guarantees and is best-effort only.
    """
    cfg = COINS_CONFIG.get(currency)
    if not cfg:
        # No RPC/tip config → no on-chain tip, just record the redeem.
        # Safe to unlock credits, since we will never attempt to send coins.
        return 0.0, None, None, True

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
        return 0.0, None, "tipping disabled or misconfigured (max_tip <= 0)", True

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
        return 0.0, None, "computed tip amount <= 0", True

    # Step 1: check wallet balance first (best-effort). Any error here is guaranteed to happen
    # before any attempt to send coins, so it is safe to unlock credits again.
    try:
        bal = call_coin_rpc(currency, "getbalance")
    except Exception as e:
        msg = str(e)
        if len(msg) > 300:
            msg = msg[:300] + "..."
        return 0.0, None, f"RPC error (getbalance): {type(e).__name__}: {msg}", True

    if isinstance(bal, str):
        try:
            bal = float(bal)
        except ValueError:
            return 0.0, None, "unexpected getbalance result string", True

    if not isinstance(bal, (int, float)):
        return 0.0, None, f"unexpected getbalance result type: {type(bal).__name__}", True

    if bal < amount:
        return 0.0, None, f"insufficient faucet balance (balance={bal}, needed={amount})", True

    # Step 2: attempt to send coins. Any error here is ambiguous: coins may or may not have left
    # the wallet (e.g. timeout after broadcast). To protect the faucet, we must *not* unlock
    # credits in this case.
    try:
        txid = call_coin_rpc(currency, "sendtoaddress", [tip_address, amount])
        if not isinstance(txid, str):
            txid = str(txid)
        return amount, txid, None, False
    except Exception as e:
        msg = str(e)
        if len(msg) > 300:
            msg = msg[:300] + "..."
        return 0.0, None, f"RPC error (sendtoaddress): {type(e).__name__}: {msg}", False


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


def _is_hex_40(s: str) -> bool:
    s = (s or "").strip()
    if len(s) != 40:
        return False
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def day_key(ts: Optional[int] = None) -> str:
    # simple UTC day key YYYY-MM-DD
    ts = ts or now_unix()
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _safe_json(obj: Any) -> str:
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return "{}"


def log_event(
    con: sqlite3.Connection,
    *,
    ts: int,
    type: str,
    account_id: Optional[str] = None,
    amount: Optional[int] = None,
    other: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    """Append one explorer/audit event. Best-effort; never raises."""
    try:
        con.execute(
            "INSERT INTO events(ts, type, account_id, amount, other, meta) VALUES(?,?,?,?,?,?)",
            (
                int(ts),
                str(type),
                str(account_id) if account_id else None,
                int(amount) if amount is not None else None,
                str(other) if other else None,
                _safe_json(meta or {}),
            ),
        )
    except Exception:
        pass


# ---------------------------
# IP tag (privacy-preserving)
# ---------------------------
def ip_tag(ip: str) -> str:
    # Rotate daily to reduce linkability; still stable for 120s stamp TTL.
    msg = f"{ip}|{day_key()}"
    digest = hmac.new(IPTAG_HMAC_KEY, msg.encode(), hashlib.sha256).digest()
    return b64url(digest[:12])  # short tag


def get_client_ip(req: Request) -> str:
    """Best-effort client IP extraction.

    We only trust proxy headers when the immediate peer is a trusted proxy.
    Typically, the backend is reached via a reverse proxy / WireGuard hop,
    so `req.client.host` may be a local/WG address (e.g., 127.0.0.1 or 10.8.0.1).

    Configure additional trusted proxies via TRUSTED_PROXY_IPS (comma-separated).
    """
    peer = (req.client.host or "").strip()

    trusted = {"127.0.0.1", "::1", "10.8.0.1"}
    extra = (os.getenv("TRUSTED_PROXY_IPS") or "").strip()
    if extra:
        for part in extra.split(","):
            part = part.strip()
            if part:
                trusted.add(part)

    # Only trust forwarded headers from known reverse proxies.
    if peer in trusted:
        # Prefer X-Real-IP (your VPS Nginx sets this correctly).
        xri = (req.headers.get("x-real-ip") or "").strip()
        if xri:
            return xri

        # Fall back to the first entry in X-Forwarded-For.
        xff = (req.headers.get("x-forwarded-for") or "").strip()
        if xff:
            # XFF can be a comma-separated chain: client, proxy1, proxy2...
            first = xff.split(",", 1)[0].strip()
            if first:
                return first

    return peer


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
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      type TEXT NOT NULL,
      account_id TEXT,
      amount INTEGER,
      other TEXT,
      meta TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_account_ts ON events(account_id, ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type, ts);")
    con.execute("CREATE INDEX IF NOT EXISTS idx_events_account_id_id ON events(account_id, id);")
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


# Atomic accept of seq (prevents replay/races)
def accept_pow_and_credit(
    con: sqlite3.Connection,
    account_id: str,
    expected_seq: int,
    mode: str = "normal",  # "normal" oder "extreme"
) -> bool:
    ts = now_unix()
    dk = day_key(ts)

    # Reset daily counter if day changed
    reset_daily_if_needed(con, account_id)

    con.execute("BEGIN IMMEDIATE;")
    try:
        row = con.execute(
            "SELECT next_seq, credits, cooldown_until, earn_day, earned_today "
            "FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            raise ValueError("no account")

        next_seq, credits, cooldown_until, earn_day, earned_today = row

        if next_seq != expected_seq:
            con.execute("ROLLBACK;")
            return False

        # Mode-dependent checks
        if mode == "normal":
            if cooldown_until > ts:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=429, detail="cooldown")
            if earned_today >= DAILY_EARN_CAP:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=429, detail="daily cap reached")
            new_cooldown = ts + COOLDOWN_SEC

        elif mode == "extreme":
            # No cooldown in extreme mode, but global higher daily cap
            if earned_today >= EXTREME_DAILY_CAP:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=429, detail="extreme daily cap reached")
            # Do not touch cooldown; keep whatever was set by normal mining
            new_cooldown = cooldown_until

        else:
            con.execute("ROLLBACK;")
            raise ValueError(f"unknown mode: {mode}")

        con.execute(
            """
            UPDATE accounts
            SET next_seq = next_seq + 1,
                credits  = credits + 1,
                cooldown_until = ?,
                earned_today = earned_today + 1
            WHERE account_id=? AND next_seq=?
            """,
            (new_cooldown, account_id, expected_seq),
        )

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


class AccountPublicOut(BaseModel):
    account_id: str
    credits: int
    locked_credits: int
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
    state: TypingOptional[str] = None
    note: TypingOptional[str] = None


class EventOut(BaseModel):
    id: int
    ts: int
    type: str
    account_id: TypingOptional[str] = None
    amount: TypingOptional[int] = None
    other: TypingOptional[str] = None
    meta: TypingOptional[Dict[str, Any]] = None


class EventsPageOut(BaseModel):
    newest_id: int
    next_before_id: TypingOptional[int] = None   # use as before_id for the next (older) page
    events: List[EventOut]

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


@app.post("/challenge_extreme", response_model=ChallengeOut)
def challenge_extreme(req: Request):
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

        # EXTREME mode: no cooldown; only a higher daily cap
        if earned_today >= EXTREME_DAILY_CAP:
            raise HTTPException(status_code=429, detail="extreme daily cap reached")

        # IP lock: deny parallel mining from same IP tag (normal + extreme teilen sich das Lock)
        if not IP_LOCKS.try_acquire(ipt, account_id, STAMP_TTL_SEC):
            raise HTTPException(status_code=429, detail="ip busy (no parallel mining)")

        exp = ts + STAMP_TTL_SEC
        bits = EXTREME_BITS
        # Important: distinguish via action
        stamp = make_stamp(
            action="earn_extreme",
            account_id=account_id,
            seq=next_seq,
            bits=bits,
            exp=exp,
            ipt=ipt,
        )
        sig = hmac_sha256(STAMP_HMAC_KEY, stamp)
        return ChallengeOut(stamp=stamp, sig=sig, bits=bits, expires_at=exp)
    finally:
        con.close()


@app.post("/submit_pow", response_model=SubmitPowOut)
def submit_pow(data: SubmitPowIn, req: Request):
    account_id = auth_account(req)
    ipt = ip_tag(get_client_ip(req))

    # Rate limit submit attempts per IP tag
    allowed, retry_after = SUBMIT_RL.allow(ipt)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"rate limited (retry after {retry_after}s)",
            headers={"Retry-After": str(retry_after)},
        )

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
        IP_LOCKS.release(ipt, account_id)
        raise HTTPException(status_code=400, detail="expired")

    # Determine mode from action
    act = str(kv.get("act", "earn_credit"))
    if act == "earn_extreme":
        mode = "extreme"
    else:
        mode = "normal"

    # 3) verify PoW
    if not pow_ok(data.stamp, data.nonce, kv["bits"]):
        raise HTTPException(status_code=400, detail="bad pow")

    # 4) atomically accept seq and credit
    con = db()
    try:
        ok = accept_pow_and_credit(con, account_id, kv["seq"], mode=mode)
        if not ok:
            raise HTTPException(status_code=409, detail="stale seq / replay")

        row = get_account(con, account_id)
        _, _, next_seq, credits, cooldown_until, _, _ = row
        # Explorer: record mining event (best-effort)
        try:
            evt_type = "mine_extreme" if mode == "extreme" else "mine"
            log_event(
                con,
                ts=now_unix(),
                type=evt_type,
                account_id=account_id,
                amount=1,
                other=None,
                meta={
                    "seq": int(kv["seq"]),
                    "bits": int(kv["bits"]),
                },
            )
        except Exception:
            pass
        return SubmitPowOut(
            ok=True,
            credits=credits,
            next_seq=next_seq,
            cooldown_until=cooldown_until,
        )
    finally:
        con.close()
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


@app.get("/account", response_model=AccountPublicOut)
def get_account_public(account_id: str = ""):
    """Public read-only account balance lookup.

    Used by the community explorer to display the current HCC balance for a given address.
    """
    acc = (account_id or "").strip()
    if not _is_hex_40(acc):
        raise HTTPException(status_code=400, detail="invalid account_id")

    con = db()
    try:
        row = con.execute(
            "SELECT account_id, credits, locked_credits FROM accounts WHERE account_id=?",
            (acc,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="unknown account")

        return AccountPublicOut(
            account_id=str(row[0]),
            credits=int(row[1] or 0),
            locked_credits=int(row[2] or 0),
            server_time=now_unix(),
        )
    finally:
        con.close()


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


@app.get("/events", response_model=List[EventOut])
def events(req: Request, limit: int = 50, account_id: str = ""):
    limit = int(limit) if isinstance(limit, int) else 50
    if limit < 1:
        limit = 1
    MAX_EVENTS = 5000
    if limit > MAX_EVENTS:
        limit = MAX_EVENTS

    acc = (account_id or "").strip()

    con = db()
    try:
        if acc:
            rows = con.execute(
                "SELECT id, ts, type, account_id, amount, other, meta "
                "FROM events WHERE account_id=? ORDER BY id DESC LIMIT ?",
                (acc, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT id, ts, type, account_id, amount, other, meta "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()

        out: List[EventOut] = []
        for r in rows:
            meta_obj: Dict[str, Any] = {}
            mid = r[6]
            if isinstance(mid, str) and mid:
                try:
                    meta_obj = json.loads(mid)
                    if not isinstance(meta_obj, dict):
                        meta_obj = {}
                except Exception:
                    meta_obj = {}
            out.append(EventOut(
                id=int(r[0]),
                ts=int(r[1] or 0),
                type=str(r[2] or ""),
                account_id=str(r[3]) if r[3] is not None else None,
                amount=int(r[4]) if r[4] is not None else None,
                other=str(r[5]) if r[5] is not None else None,
                meta=meta_obj,
            ))

        out.reverse()  # ascending
        return out
    finally:
        con.close()


# ---------------------------
# Explorer cache (in-memory)
# ---------------------------
# Tiny TTL cache to reduce repeated SQLite reads (single-process).
# Keyed by (account_id, before_id, limit).
_EVENTS_PAGE_CACHE_TTL_SEC = int(os.getenv("EVENTS_PAGE_CACHE_TTL_SEC", "5"))
_EVENTS_PAGE_CACHE_MAX_ITEMS = int(os.getenv("EVENTS_PAGE_CACHE_MAX_ITEMS", "256"))
_EVENTS_PAGE_CACHE_LOCK = threading.Lock()
_EVENTS_PAGE_CACHE: dict[tuple[str, int, int], tuple[float, dict[str, Any], str]] = {}


def _events_page_cache_get(key: tuple[str, int, int]) -> tuple[dict[str, Any], str] | None:
    if _EVENTS_PAGE_CACHE_TTL_SEC <= 0:
        return None
    now = time.time()
    with _EVENTS_PAGE_CACHE_LOCK:
        item = _EVENTS_PAGE_CACHE.get(key)
        if not item:
            return None
        ts, payload, etag = item
        if (now - ts) > float(_EVENTS_PAGE_CACHE_TTL_SEC):
            try:
                del _EVENTS_PAGE_CACHE[key]
            except Exception:
                pass
            return None
        return payload, etag


def _events_page_cache_put(key: tuple[str, int, int], payload: dict[str, Any], etag: str) -> None:
    if _EVENTS_PAGE_CACHE_TTL_SEC <= 0:
        return
    now = time.time()
    with _EVENTS_PAGE_CACHE_LOCK:
        # Simple eviction: keep dict bounded.
        if len(_EVENTS_PAGE_CACHE) >= max(8, int(_EVENTS_PAGE_CACHE_MAX_ITEMS)):
            # Drop oldest ~25% entries.
            items = sorted(_EVENTS_PAGE_CACHE.items(), key=lambda kv: kv[1][0])
            drop_n = max(1, len(items) // 4)
            for i in range(drop_n):
                try:
                    del _EVENTS_PAGE_CACHE[items[i][0]]
                except Exception:
                    pass
        _EVENTS_PAGE_CACHE[key] = (now, payload, etag)


def _make_etag(*parts: Any) -> str:
    # Stable weak ETag (quoted) derived from a short SHA1.
    s = "|".join(str(p) for p in parts)
    h = hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f'W/"{h}"'


@app.get("/events_page", response_model=EventsPageOut)
def events_page(req: Request, limit: int = 100, account_id: str = "", before_id: int = 0):
    """
    Cursor-paginated events for the explorer.

    - Returns up to `limit` events.
    - If `before_id` is provided (>0), only return events with id < before_id.
    - If `account_id` is provided, filter by that account.

    Caching:
    - Small in-memory TTL cache (default 5s) keyed by (account_id, before_id, limit).

    HTTP cache:
    - Returns an ETag and honors If-None-Match with 304 Not Modified.
    """
    limit = int(limit) if isinstance(limit, int) else 100
    if limit < 1:
        limit = 1

    # keep pages small-ish for UX and server
    MAX_EVENTS_PAGE = 500
    if limit > MAX_EVENTS_PAGE:
        limit = MAX_EVENTS_PAGE

    acc = (account_id or "").strip()
    try:
        before_id = int(before_id or 0)
    except Exception:
        before_id = 0

    cache_key = (acc, int(before_id), int(limit))

    # 1) Serve from TTL cache if present.
    cached = _events_page_cache_get(cache_key)
    if cached is not None:
        payload, etag = cached
        inm = (req.headers.get("if-none-match") or "").strip()
        if inm and inm == etag:
            # Not modified
            return Response(status_code=304, headers={
                "ETag": etag,
                "Cache-Control": "private, max-age=10",
            })
        return Response(
            content=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
            media_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "private, max-age=10",
            },
        )

    con = db()
    try:
        row = con.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
        newest_id = int(row[0] or 0) if row else 0

        where = []
        params: list[Any] = []

        if acc:
            where.append("account_id=?")
            params.append(acc)
        if before_id > 0:
            where.append("id < ?")
            params.append(before_id)

        sql = (
            "SELECT id, ts, type, account_id, amount, other, meta "
            "FROM events "
        )
        if where:
            sql += "WHERE " + " AND ".join(where) + " "
        sql += "ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = con.execute(sql, tuple(params)).fetchall()

        events_out: list[dict[str, Any]] = []
        min_id: TypingOptional[int] = None

        for r in rows:
            meta_obj: Dict[str, Any] = {}
            mid = r[6]
            if isinstance(mid, str) and mid:
                try:
                    meta_obj = json.loads(mid)
                    if not isinstance(meta_obj, dict):
                        meta_obj = {}
                except Exception:
                    meta_obj = {}

            rid = int(r[0])
            if min_id is None or rid < min_id:
                min_id = rid

            events_out.append({
                "id": rid,
                "ts": int(r[1] or 0),
                "type": str(r[2] or ""),
                "account_id": (str(r[3]) if r[3] is not None else None),
                "amount": (int(r[4]) if r[4] is not None else None),
                "other": (str(r[5]) if r[5] is not None else None),
                "meta": meta_obj,
            })

        # Ascending for UI rendering
        events_out.reverse()

        next_before_id = int(min_id) if (min_id is not None and min_id > 1) else None

        payload: dict[str, Any] = {
            "newest_id": newest_id,
            "next_before_id": next_before_id,
            "events": events_out,
        }

        # ETag: include newest_id (global freshness), the cursor params, and the page content fingerprint.
        # Using min_id + count makes it stable and cheap.
        etag = _make_etag(newest_id, acc, before_id, limit, (min_id or 0), len(events_out))

        # Store in TTL cache
        _events_page_cache_put(cache_key, payload, etag)

        inm = (req.headers.get("if-none-match") or "").strip()
        if inm and inm == etag:
            return Response(status_code=304, headers={
                "ETag": etag,
                "Cache-Control": "private, max-age=10",
            })

        return Response(
            content=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
            media_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "private, max-age=10",
            },
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

        ts = now_unix()
        log_event(con, ts=ts, type="transfer_out", account_id=from_addr, amount=-amount, other=to_addr, meta={})
        log_event(con, ts=ts, type="transfer_in", account_id=to_addr, amount=amount, other=from_addr, meta={})

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


# Burn locked credits helper for redeem finalization
def _burn_locked_credits_atomic(con: sqlite3.Connection, account_id: str, amount: int) -> None:
    """Permanently burn `amount` credits from `account_id.locked_credits`.

    Used for finalizing redeems after a successful on-chain tip.
    Raises ValueError on failure.
    """
    if amount <= 0:
        raise ValueError("amount must be positive")

    cur = con.execute(
        """
        UPDATE accounts
        SET locked_credits = locked_credits - ?
        WHERE account_id = ?
          AND locked_credits >= ?
        """,
        (amount, str(account_id), amount),
    )
    if cur.rowcount != 1:
        raise ValueError("insufficient locked credits or unknown account")


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

    con = db()
    try:
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

            # Look up the current state/note from the redeem_requests table (best-effort).
            state = None
            note = None
            if rid > 0:
                try:
                    row = con.execute(
                        "SELECT state, note FROM redeem_requests WHERE id=?",
                        (rid,),
                    ).fetchone()
                    if row:
                        state = str(row[0]) if row[0] is not None else None
                        note = str(row[1]) if row[1] is not None else None
                except Exception:
                    # Log lookup is best-effort; ignore DB errors here.
                    pass

            out.append(RedeemLogEntryOut(
                request_id=rid,
                ts=ts,
                account_id=acc,
                currency=cur,
                tip_amount=tip_amount_f,
                txid=txid,
                rpc_error=rpc_error,
                state=state,
                note=note,
            ))

        return out
    finally:
        con.close()

# ---------------------------
# /redeem_request endpoint: Ask for an external crypto tip
# ---------------------------


# New redeem_request implementation: lock credits, burn on tip, unlock if no payout
@app.post("/redeem_request", response_model=RedeemRequestOut)
def redeem_request(data: RedeemRequestIn, req: Request):
    """Log a redeem/tip request and optionally send a best-effort crypto tip.

    New behavior:
    - First move the redeem cost from `credits` -> `locked_credits` atomically.
    - Only if an on-chain tip is successfully sent, the locked credits are permanently burned.
    - If no tip is sent (RPC error, empty faucet wallet, etc.), the locked credits are returned
      to the user's available balance.

    This still does NOT guarantee any payout or fixed exchange rate, but avoids the case where
    credits are permanently deducted without any chance of a payout.
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
    request_id: int | None = None
    credits_before: int = 0
    cost: int = 0
    tip_amount: float = 0.0
    txid: str | None = None
    rpc_error: str | None = None
    final_state: str = "locked"
    note: str | None = None

    try:
        ts = now_unix()
        # Phase 1: lock credits and record the redeem request.
        con.execute("BEGIN IMMEDIATE;")

        row = con.execute(
            "SELECT credits FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        if not row:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=401, detail="unknown account")

        credits_before = int(row[0] or 0)
        if credits_before < MIN_REDEEM_CREDITS:
            con.execute("ROLLBACK;")
            msg = (
                f"Insufficient credits for redeem. You need at least {MIN_REDEEM_CREDITS} credits "
                f"before you can request a tip."
            )
            raise HTTPException(status_code=400, detail=msg)

        # Determine how many credits to lock for this redeem attempt.
        cost = min(REDEEM_COST_CREDITS, credits_before)
        if cost <= 0:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail="redeem cost must be positive")

        # Move `cost` credits -> locked_credits atomically.
        try:
            _lock_credits_atomic(con, account_id, cost)
        except ValueError as e:
            con.execute("ROLLBACK;")
            raise HTTPException(status_code=400, detail=str(e))

        # Insert redeem request in 'locked' state.
        cur = con.execute(
            """
            INSERT INTO redeem_requests(
              created_at, account_id, tip_address, currency,
              credits_before, credits_spent, state, note
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (ts, account_id, tip_address, currency, credits_before, cost, "locked", None),
        )
        request_id = int(cur.lastrowid)

        log_event(
            con,
            ts=now_unix(),
            type="redeem_lock",
            account_id=account_id,
            amount=0,
            other=currency,  # oder "lock"
            meta={"request_id": int(request_id), "tip_address": tip_address, "locked": int(cost)},
        )

        # Commit Phase 1: credits are now locked and the request is recorded.
        con.execute("COMMIT;")

        # Phase 2: attempt to send on-chain tip (best-effort, outside the credit-locking txn).
        tip_amount, txid, rpc_error, safe_to_unlock = maybe_send_tip(currency, tip_address)

        # Phase 3: finalize according to tip outcome.
        if tip_amount > 0 and txid:
            # Successful tip: burn the locked credits and mark as sent.
            final_state = "sent"
            note = f"{currency} {tip_amount} txid={txid}"
            try:
                con.execute("BEGIN IMMEDIATE;")
                _burn_locked_credits_atomic(con, account_id, cost)
                log_event(
                    con,
                    ts=now_unix(),
                    type="redeem_burn",
                    account_id=account_id,
                    amount=-cost,
                    other="burn",
                    meta={"request_id": int(request_id)},
                )
                con.execute(
                    "UPDATE redeem_requests SET state=?, note=? WHERE id=?",
                    (final_state, note, request_id),
                )
                # Explorer: record redeem sent (best-effort)
                log_event(
                    con,
                    ts=now_unix(),
                    type="redeem_sent",
                    account_id=account_id,
                    amount=0,
                    other=currency,
                    meta={
                        "request_id": int(request_id),
                        "tip_amount": float(tip_amount),
                        "txid": str(txid),
                    },
                )
                con.execute("COMMIT;")
            except Exception:
                # If this fails, credits remain locked; better to leave them frozen than silently
                # re-credit them after coins were sent.
                try:
                    con.execute("ROLLBACK;")
                except Exception:
                    pass
        else:
            # No tip was sent: best-effort attempt to unlock credits again *only* if we are sure
            # that no coins left the faucet wallet. If the RPC state is ambiguous (e.g. a timeout
            # after sendtoaddress), we keep the credits locked to avoid draining the faucet.
            final_state = "no_payout"
            if COINS_CONFIG.get(currency):
                note = rpc_error or "no tip sent (faucet funds or RPC conditions not met)"
            else:
                note = "no on-chain tip configured for this currency"

            try:
                con.execute("BEGIN IMMEDIATE;")
                if safe_to_unlock:
                    try:
                        _unlock_credits_atomic(con, account_id, cost)
                        log_event(
                            con,
                            ts=now_unix(),
                            type="redeem_unlock",
                            account_id=account_id,
                            amount=0,
                            other="unlock",
                            meta={"request_id": int(request_id), "unlocked": int(cost)},
                        )
                    except ValueError as e:
                        # If unlocking fails, keep them locked and annotate the note for later manual fix.
                        note = (note or "") + f" [unlock_failed: {e}]"
                else:
                    # Ambiguous RPC state: credits stay locked for safety.
                    note = (note or "") + " [credits remain locked due to uncertain RPC state]"
                con.execute(
                    "UPDATE redeem_requests SET state=?, note=? WHERE id=?",
                    (final_state, note, request_id),
                )
                log_event(
                    con,
                    ts=now_unix(),
                    type="redeem_no_payout",
                    account_id=account_id,
                    amount=0,
                    other=currency,
                    meta={"request_id": int(request_id), "safe_to_unlock": bool(safe_to_unlock), "rpc_error": (rpc_error or "")},
                )
                con.execute("COMMIT;")
            except Exception:
                try:
                    con.execute("ROLLBACK;")
                except Exception:
                    pass

        # Fetch final visible credits for the response.
        row_final = con.execute(
            "SELECT credits FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        credits_left = int(row_final[0] or 0) if row_final else 0

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
            credits_left=credits_left,
            min_credits=MIN_REDEEM_CREDITS,
            currency=currency,
            tip_amount=tip_amount if tip_amount > 0 else None,
            txid=txid,
            rpc_error=rpc_error,
        )
    except HTTPException:
        raise
    except Exception:
        try:
            con.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        con.close()


@app.get("/debug/ip")
def debug_ip(req: Request):
    return {
        "client_host": req.client.host,
        "x_real_ip": req.headers.get("x-real-ip"),
        "x_forwarded_for": req.headers.get("x-forwarded-for"),
        "forwarded": req.headers.get("forwarded"),
    }