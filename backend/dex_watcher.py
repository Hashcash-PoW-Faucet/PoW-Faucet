# dex_watcher.py
import os
import json
import time
from decimal import Decimal, ROUND_DOWN
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union, Set, List

import requests
from requests.auth import HTTPBasicAuth

BACKEND_DIR = Path(__file__).resolve().parent

# Load backend/.env for local runs (python doesn't auto-load .env).
# In production you typically export env vars in systemd, so this is a no-op.
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv(BACKEND_DIR / ".env")
except Exception:
    # If python-dotenv is not installed or .env is missing, just continue.
    pass

BASE_URL = os.getenv("DEX_BASE_URL", "http://127.0.0.1:8200").rstrip("/")
ADMIN_TOKEN = (os.getenv("DEX_ADMIN_TOKEN", "") or "").strip()
MIN_CONFS = int(os.getenv("DEX_MIN_CONFS", "6"))
POLL_SEC = int(os.getenv("DEX_POLL_SEC", "10"))

COINS_CONFIG_PATH = os.getenv("COINS_CONFIG_PATH", "coins.json")
coins_path = Path(COINS_CONFIG_PATH)
if not coins_path.is_absolute():
    coins_path = BACKEND_DIR / coins_path

STATE_PATH = BACKEND_DIR / "dex_watcher_state.json"  # persists start blockhash per trade


SAT_FACTOR = Decimal("100000000")  # assume 8 decimals for UTXO coins


def _http_detail(resp: requests.Response) -> str:
    """Best-effort extraction of a useful error detail string from a FastAPI response."""
    try:
        j = resp.json()
        if isinstance(j, dict) and "detail" in j:
            return str(j.get("detail"))
        return json.dumps(j)
    except Exception:
        return (resp.text or "").strip()


def coin_min_confs(coin: Dict[str, Any]) -> int:
    """Return min confirmations for a specific coin.

    Priority:
      1) coin["dex_min_confs"] (or coin["min_confs"]) if present
      2) global MIN_CONFS from env

    This allows per-coin safety/UX tuning while keeping a global fallback.
    """
    for key in ("dex_min_confs", "min_confs"):
        if key in coin:
            try:
                return int(str(coin.get(key)).strip())
            except Exception:
                # Bad config value -> fall back to global
                break
    return int(MIN_CONFS)


def load_coins_config() -> Dict[str, Any]:
    with open(coins_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError("coins.json must be a JSON object")
    # Normalize keys
    return {str(k).strip().upper(): v for k, v in data.items()}


def sat_from_amount(amount_coin: Any) -> int:
    # amount_coin is usually float; convert safely via Decimal(str(x))
    d = Decimal(str(amount_coin))
    sat = (d * SAT_FACTOR).to_integral_value(rounding=ROUND_DOWN)
    return int(sat)


def rpc_call(coin: Dict[str, Any], method: str, params: list) -> Any:
    """Call a coin JSON-RPC endpoint.

    Some forks return HTTP 500 even for standard JSON-RPC errors.
    So we parse JSON first and surface the real RPC error message.
    """
    url = str(coin["rpc_url"])
    user = str(coin["rpc_user"])
    pw = str(coin["rpc_password"])
    payload = {"jsonrpc": "1.0", "id": "dex_watcher", "method": method, "params": params}

    r = requests.post(url, json=payload, auth=HTTPBasicAuth(user, pw), timeout=15)

    # Try to parse JSON even if HTTP status is 500
    try:
        j = r.json()
    except Exception:
        # Not JSON -> fall back to HTTP error
        try:
            r.raise_for_status()
        except Exception as e:
            raise RuntimeError(f"rpc http error: {e}; body={(r.text or '').strip()[:300]}")
        raise RuntimeError(f"rpc non-json response; body={(r.text or '').strip()[:300]}")

    # JSON-RPC error inside body
    if isinstance(j, dict) and j.get("error"):
        err = j.get("error")
        if isinstance(err, dict):
            code = err.get("code")
            msg = err.get("message")
            raise RuntimeError(f"rpc error {code}: {msg}")
        raise RuntimeError(f"rpc error: {err}")

    # HTTP error without structured RPC error
    if r.status_code >= 400:
        raise RuntimeError(f"rpc http {r.status_code}: {(r.text or '').strip()[:300]}")

    if not isinstance(j, dict):
        raise RuntimeError(f"rpc invalid json result type: {type(j)}")

    return j.get("result")


def load_state() -> Dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    tmp = STATE_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    tmp.replace(STATE_PATH)


def get_pending_trades(states: str = "WAIT_PAYMENT,CONFIRMED") -> Dict[str, Any]:
    headers = {"X-Admin-Token": ADMIN_TOKEN}
    r = requests.get(
        f"{BASE_URL}/admin/dex/trades/pending",
        headers=headers,
        params={"state": states},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()



def confirm_trade(trade_id: int, txid: str) -> None:
    headers = {"X-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json"}
    r = requests.post(
        f"{BASE_URL}/admin/dex/trades/{trade_id}/confirm",
        headers=headers,
        json={"txid": txid},
        timeout=20,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"confirm http {r.status_code}: {_http_detail(r)}")



def settle_trade(trade_id: int, txid: str) -> None:
    headers = {"X-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json"}
    r = requests.post(
        f"{BASE_URL}/admin/dex/trades/{trade_id}/settle",
        headers=headers,
        json={"txid": txid},
        timeout=20,
    )
    # Some backends may use 409 for idempotent repeats or mismatches.
    if r.status_code >= 400:
        raise RuntimeError(f"settle http {r.status_code}: {_http_detail(r)}")


# --- New: expire_trade helper ---
def expire_trade(trade_id: int) -> None:
    """Mark a trade as expired in the backend.

    The backend error messages reference `/dex/trades/{id}/expire`.
    We try that first. For robustness we also try an admin-prefixed variant.

    This endpoint should be idempotent: expiring an already-failed trade is OK.
    """
    headers = {"X-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json"}

    # Try admin first (our watcher authenticates via X-Admin-Token)
    for path in (
        f"{BASE_URL}/admin/dex/trades/{trade_id}/expire",
        # Fallback: public (some backends reference this path, but it may require Bearer auth)
        f"{BASE_URL}/dex/trades/{trade_id}/expire",
    ):
        try:
            r = requests.post(path, headers=headers, json={}, timeout=20)
            # Treat OK and idempotent conflicts as success
            if r.status_code in (200, 204):
                return
            if r.status_code == 409:
                # e.g. already expired / already settled
                return
            if r.status_code in (401, 403):
                # Wrong auth scheme for this endpoint (e.g. expects Bearer), try the next variant.
                continue
            if r.status_code == 404:
                # try next path
                continue
            raise RuntimeError(f"expire http {r.status_code}: {_http_detail(r)}")
        except requests.RequestException as e:
            # network-ish errors: re-raise so caller can log
            raise RuntimeError(f"expire request failed: {e}")

    raise RuntimeError("expire endpoint not found (or unauthorized for all variants)")


def update_trade_confs(trade_id: int, confs: int, txid: str = "") -> None:
    """Update backend-stored confirmations for a trade.

    This allows the UI to show live confirmations without re-querying the coin daemon.
    Endpoint (Option A): POST /admin/dex/trades/{trade_id}/confs  { "confs": N, "txid": "..."? }
    """
    try:
        confs_i = int(confs)
    except Exception:
        confs_i = 0
    if confs_i < 0:
        confs_i = 0

    headers = {"X-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json"}
    payload: Dict[str, Any] = {"confs": confs_i}

    txid_s = (txid or "").strip()
    if txid_s:
        payload["txid"] = txid_s

    r = requests.post(
        f"{BASE_URL}/admin/dex/trades/{trade_id}/confs",
        headers=headers,
        json=payload,
        timeout=20,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"confs http {r.status_code}: {_http_detail(r)}")

def ensure_import_address(coin: Dict[str, Any], address: str, label: str) -> None:
    try:
        rpc_call(coin, "importaddress", [address, label, False])
    except Exception as e:
        msg = str(e).strip().lower()

        # common "already imported / already in wallet" variants
        if any(s in msg for s in (
                "already",
                "already have",
                "already exists",
                "already contains",
                "is already",
                "key already exists",
                "the wallet already",
        )):
            return

        # If it's code -4 and mentions contain/exists, also treat as OK
        if "rpc error -4" in msg and ("contain" in msg or "exist" in msg):
            return

        raise


def scan_sinceblock_for_payment(
    coin: Dict[str, Any],
    from_blockhash: str,
    pay_to_address: str,
    expected_sats: int,
    exclude_txids: Optional[Set[str]] = None,
) -> Optional[Tuple[str, int, int]]:
    """Scan wallet activity since a blockhash and find a candidate payment.

    IMPORTANT: This returns a candidate as soon as the *amount* requirement is met,
    regardless of confirmations. Confirmations are returned for phase-2 settling.

    `exclude_txids` allows the caller to ignore txids already used by other trades
    (or previously rejected), preventing duplicate assignment.

    Returns: (txid, total_sat_to_address, confirmations)
    """
    res = rpc_call(coin, "listsinceblock", [from_blockhash, 1, True])

    ex: Set[str] = set()
    if exclude_txids:
        ex = {str(x).strip() for x in exclude_txids if str(x).strip()}

    # Aggregate sums by txid for our address
    sums: Dict[str, int] = {}
    confs: Dict[str, int] = {}

    for tx in res.get("transactions", []):
        if tx.get("category") != "receive":
            continue
        if str(tx.get("address", "")).strip() != pay_to_address:
            continue

        txid = str(tx.get("txid", "")).strip()
        if not txid:
            continue
        if txid in ex:
            continue

        amount_sat = sat_from_amount(tx.get("amount", 0))
        c = int(tx.get("confirmations", 0))

        sums[txid] = sums.get(txid, 0) + amount_sat
        confs[txid] = max(confs.get(txid, 0), c)

    # Choose the best candidate meeting the amount requirement.
    # Prefer the highest confirmations; tie-breaker: higher total.
    best: Optional[Tuple[str, int, int]] = None
    for txid, total_sat in sums.items():
        if total_sat < int(expected_sats):
            continue
        c = confs.get(txid, 0)
        if best is None:
            best = (txid, int(total_sat), int(c))
            continue
        _, best_total, best_c = best
        if c > best_c:
            best = (txid, int(total_sat), int(c))
        elif c == best_c and int(total_sat) > int(best_total):
            best = (txid, int(total_sat), int(c))

    return best


def _state_entry(state: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Return a mutable per-trade state entry.

    Backward compatible:
      - older state files stored a string blockhash at state[key]
      - newer versions store a dict

    We also track `last_confs` to avoid spamming the backend with redundant conf updates.
    """
    v = state.get(key)
    if isinstance(v, dict):
        v.setdefault("from_blockhash", "")
        v.setdefault("txid", "")
        v.setdefault("last_confs", None)
        v.setdefault("expired", False)
        v.setdefault("last_expire_try", 0)
        v.setdefault("rejected_txids", [])
        return v

    if isinstance(v, str) and v:
        d = {"from_blockhash": v, "txid": "", "last_confs": None, "expired": False, "last_expire_try": 0, "rejected_txids": []}
        state[key] = d
        return d

    d = {"from_blockhash": "", "txid": "", "last_confs": None, "expired": False, "last_expire_try": 0, "rejected_txids": []}
    state[key] = d
    return d


def get_tx_confirmations(coin: Dict[str, Any], txid: str) -> int:
    """Best-effort confirmations for a txid.

    Try gettransaction (wallet-aware). Fallback to getrawtransaction verbose.
    Return 0 if unknown/unconfirmed.
    """
    txid = (txid or "").strip()
    if not txid:
        return 0

    # 1) Wallet-aware
    try:
        res = rpc_call(coin, "gettransaction", [txid])
        c = int(res.get("confirmations", 0))
        return max(0, c)
    except Exception:
        pass

    # 2) Raw tx (verbose)
    # Some older forks expect the verbose flag as an int (0/1) rather than a bool.
    # Try int first for compatibility, then bool.
    for verbose in (1, True):
        try:
            res = rpc_call(coin, "getrawtransaction", [txid, verbose])
            c = int(res.get("confirmations", 0))
            return max(0, c)
        except Exception:
            continue
    return 0


def get_one_block_back_hash(coin: Dict[str, Any]) -> str:
    """Return a safe starting blockhash: one block behind the current tip.

    This reduces the chance to miss a payment that arrives before the watcher
    first sees the trade.
    """
    try:
        height = int(rpc_call(coin, "getblockcount", []))
        start_h = max(0, height - 1)
        return str(rpc_call(coin, "getblockhash", [start_h]))
    except Exception:
        # Fallback
        return str(rpc_call(coin, "getbestblockhash", []))


def main() -> None:
    if not ADMIN_TOKEN:
        raise SystemExit("DEX_ADMIN_TOKEN missing")

    coins = load_coins_config()
    state = load_state()

    print(f"[watcher] base={BASE_URL} coins={list(coins.keys())} min_confs_default={MIN_CONFS} poll={POLL_SEC}s")
    print(f"[watcher] coins.json: {coins_path}")
    print(f"[watcher] state file: {STATE_PATH}")

    while True:
        try:
            pending = get_pending_trades(states="WAIT_PAYMENT,CONFIRMED")
            trades = pending.get("trades", [])
        except Exception as e:
            print(f"[watcher] failed to fetch pending trades: {e}")
            time.sleep(POLL_SEC)
            continue

        changed = False

        # Build a set of txids already used by any pending trade (per currency).
        # This prevents assigning the same txid to two different trades, even if
        # two trades have identical payment parameters.
        used_by_currency: Dict[str, Set[str]] = {}
        for t0 in trades:
            cur0 = str(t0.get("currency") or "").strip().upper()
            tx0 = str(t0.get("txid") or "").strip()
            if not cur0:
                continue
            if cur0 not in used_by_currency:
                used_by_currency[cur0] = set()
            if tx0:
                used_by_currency[cur0].add(tx0)

        # Also include pinned txids from our local state (covers cases where backend
        # txid isn’t populated yet for some reason).
        for k0, v0 in (state or {}).items():
            if not isinstance(k0, str) or ":" not in k0:
                continue
            cur0 = k0.split(":", 1)[0].strip().upper()
            if not cur0:
                continue
            if cur0 not in used_by_currency:
                used_by_currency[cur0] = set()
            if isinstance(v0, dict):
                tx0 = str(v0.get("txid") or "").strip()
            else:
                tx0 = ""
            if tx0:
                used_by_currency[cur0].add(tx0)

        for t in trades:
            trade_id = int(t["trade_id"])
            trade_state = str(t.get("state", "")).strip().upper()
            currency = str(t["currency"]).strip().upper()
            pay_to_address = str(t["pay_to_address"]).strip()
            expected_sats = int(t["expected_sats"])

            key = f"{currency}:{trade_id}"
            entry = _state_entry(state, key)

            # Prefer txid provided by backend once confirmed/settled
            backend_txid = str(t.get("txid") or "").strip()
            if backend_txid and backend_txid != str(entry.get("txid") or "").strip():
                entry["txid"] = backend_txid
                changed = True

            # IMPORTANT: expiry should only apply while we have NOT detected any payment.
            # Once a txid is known (trade is confirmed), the trade must NOT be auto-expired.
            expires_at = int(t.get("expires_at") or 0)
            now = int(time.time())
            has_txid = bool(backend_txid) or bool(str(entry.get("txid") or "").strip())

            if expires_at and now >= expires_at and trade_state == "WAIT_PAYMENT" and not has_txid:
                last_try = int(entry.get("last_expire_try") or 0)
                if now - last_try >= 60 and not bool(entry.get("expired")):
                    entry["last_expire_try"] = now
                    changed = True
                    try:
                        expire_trade(trade_id)
                        entry["expired"] = True
                        changed = True
                        print(f"[watcher] trade {trade_id}: expired by time (expires_at={expires_at}), marked expired")
                    except Exception as e:
                        print(f"[watcher] trade {trade_id}: expire failed: {e}")
                continue

            # If we previously marked it expired, don't waste work.
            if bool(entry.get("expired")) and trade_state in ("WAIT_PAYMENT", "CONFIRMED"):
                continue

            coin = coins.get(currency)
            if not coin:
                print(f"[watcher] trade {trade_id}: currency {currency} not in coins.json")
                continue

            min_confs = coin_min_confs(coin)


            from_blockhash = str(entry.get("from_blockhash") or "").strip()
            if not from_blockhash:
                # First time we see this trade: start from one block behind the current tip
                try:
                    from_blockhash = get_one_block_back_hash(coin)
                    entry["from_blockhash"] = from_blockhash
                    changed = True
                except Exception as e:
                    print(f"[watcher] trade {trade_id}: getbestblockhash failed: {e}")
                    continue

            # Ensure watch-only import
            try:
                ensure_import_address(coin, pay_to_address, f"dex_trade_{trade_id}")
            except Exception as e:
                print(f"[watcher] trade {trade_id}: importaddress failed: {e}")
                continue

            # If we already have a pinned txid, just track confirmations and settle when ready.
            pinned_txid = str(entry.get("txid") or "").strip()
            if pinned_txid:
                c = get_tx_confirmations(coin, pinned_txid)

                # Push confirmations to backend for UI display (only when changed)
                last_confs = entry.get("last_confs")
                if last_confs is None or int(last_confs) != int(c):
                    try:
                        update_trade_confs(trade_id, c, pinned_txid)
                        entry["last_confs"] = int(c)
                        changed = True
                    except Exception as e:
                        print(f"[watcher] trade {trade_id}: confs update failed: {e}")

                # If backend says CONFIRMED, settle once we have enough confirmations.
                if trade_state == "CONFIRMED" and c >= int(min_confs):
                    print(f"[watcher] trade {trade_id}: pinned txid={pinned_txid} confs={c} -> settle")
                    try:
                        settle_trade(trade_id, pinned_txid)
                    except Exception as e:
                        msg = str(e)
                        print(f"[watcher] trade {trade_id}: settle failed: {msg}")
                        if "trade expired" in msg.lower():
                            try:
                                expire_trade(trade_id)
                                entry["expired"] = True
                                changed = True
                                print(f"[watcher] trade {trade_id}: marked expired after settle rejection")
                            except Exception as e2:
                                print(f"[watcher] trade {trade_id}: expire after settle-fail failed: {e2}")
                            continue
                        # If backend rejects due to txid mismatch, drop pinned txid so we can resync from backend
                        if "txid" in msg.lower() and "mismatch" in msg.lower():
                            entry["txid"] = ""
                            entry["last_confs"] = None
                            changed = True

                continue

            # No pinned txid yet: scan since blockhash for an amount-matching candidate.
            # Exclude txids already used by other pending trades in this currency,
            # and also exclude txids previously rejected for this specific trade.
            exclude_txids: Set[str] = set()
            exclude_txids |= set(used_by_currency.get(currency, set()))
            rej = entry.get("rejected_txids")
            if isinstance(rej, list):
                exclude_txids |= {str(x).strip() for x in rej if str(x).strip()}
            try:
                found = scan_sinceblock_for_payment(coin, from_blockhash, pay_to_address, expected_sats, exclude_txids=exclude_txids)
            except Exception as e:
                print(f"[watcher] trade {trade_id}: listsinceblock failed: {e}")
                continue

            if not found:
                continue

            txid, total_sat, c = found

            # Phase-1: pin txid (CONFIRMED) as soon as amount matches, even with 0 confirmations.
            if trade_state == "WAIT_PAYMENT":
                print(f"[watcher] trade {trade_id}: FOUND candidate txid={txid} total_sat={total_sat} confs={c}/{min_confs} -> confirm")
                try:
                    confirm_trade(trade_id, txid)
                    entry["txid"] = txid
                    changed = True
                    trade_state = "CONFIRMED"
                except Exception as e:
                    msg = str(e)
                    print(f"[watcher] trade {trade_id}: confirm failed: {msg}")
                    if "trade expired" in msg.lower():
                        try:
                            expire_trade(trade_id)
                            entry["expired"] = True
                            changed = True
                            print(f"[watcher] trade {trade_id}: marked expired after confirm rejection")
                        except Exception as e2:
                            print(f"[watcher] trade {trade_id}: expire after confirm-fail failed: {e2}")
                    if "txid already used" in msg.lower():
                        # Remember this txid as rejected for this trade and try another one next loop.
                        rlist = entry.get("rejected_txids")
                        if not isinstance(rlist, list):
                            rlist = []
                            entry["rejected_txids"] = rlist
                        if txid not in rlist:
                            rlist.append(txid)
                            changed = True
                        # Also treat it as globally used for this currency.
                        if currency in used_by_currency:
                            used_by_currency[currency].add(txid)
                        else:
                            used_by_currency[currency] = {txid}
                    continue

            # Phase-2: settle only once confirmations reach MIN_CONFS.
            if trade_state == "CONFIRMED":
                # Refresh confirmations using a direct tx query (more reliable than listsinceblock).
                c2 = get_tx_confirmations(coin, txid)

                # Push confirmations to backend for UI display (only when changed)
                last_confs = entry.get("last_confs")
                if last_confs is None or int(last_confs) != int(c2):
                    try:
                        update_trade_confs(trade_id, c2, txid)
                        entry["last_confs"] = int(c2)
                        changed = True
                    except Exception as e:
                        print(f"[watcher] trade {trade_id}: confs update failed: {e}")

                if c2 >= int(min_confs):
                    print(f"[watcher] trade {trade_id}: txid={txid} confs={c2} -> settle")
                    try:
                        settle_trade(trade_id, txid)
                    except Exception as e:
                        msg = str(e)
                        print(f"[watcher] trade {trade_id}: settle failed: {msg}")
                        if "trade expired" in msg.lower():
                            try:
                                expire_trade(trade_id)
                                entry["expired"] = True
                                changed = True
                                print(f"[watcher] trade {trade_id}: marked expired after settle rejection")
                            except Exception as e2:
                                print(f"[watcher] trade {trade_id}: expire after settle-fail failed: {e2}")
                            continue
                        if "txid" in msg.lower() and "mismatch" in msg.lower():
                            entry["txid"] = ""
                            entry["last_confs"] = None
                            changed = True

        if changed:
            save_state(state)

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()