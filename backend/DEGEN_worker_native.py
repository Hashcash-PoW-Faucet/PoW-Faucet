#!/usr/bin/env python3
"""
EVM native-token payout worker for HashCash (DEGEN on Degen L3).

- Reads pending payouts from faucet.db (evm_payouts).
- Sends native DEGEN as a value transfer.
- Uses coins.json to retrieve RPC URL, chain ID, and decimals.

IMPORTANT:
- This worker is single-currency: PAYOUT_CURRENCY = “DEGEN”.
- The HCC -> DEGEN mapping is configured via DEGEN_PER_HCC (env).
"""

import json
import os
import time
import sqlite3
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3

from app import _burn_locked_credits_atomic, log_event

# -------------------------
# Env + paths
# -------------------------

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

BASE_DIR = BACKEND_DIR
REDEEM_QUEUE_FILE = BASE_DIR / "redeem_queue.jsonl"

DB_PATH = (os.getenv("FAUCET_DB") or str(BASE_DIR / "faucet.db")).strip()

POLL_SEC = max(1, int(os.getenv("EVM_PAYOUT_POLL_SEC", "5")))

PAYOUT_CURRENCY = "DEGEN"

DEGEN_PER_HCC = float(os.getenv("DEGEN_PER_HCC", "0.5"))

# Gas multiplier
GAS_MULT = float(os.getenv("PAYOUT_GAS_MULT", "1.15"))

# Treasury-Creds (nur in .env, niemals in coins.json!)
TREASURY_PRIV = (os.getenv("EVM_TREASURY_PRIVKEY_DEGEN") or "").strip()
TREASURY_ADDR = (os.getenv("EVM_TREASURY_ADDRESS_DEGEN") or "").strip()

COINS_CONFIG_PATH = os.getenv("COINS_CONFIG_PATH", str(BASE_DIR / "coins.json"))


def now_unix() -> int:
    return int(time.time())


def load_coins_config() -> dict:
    cfg_path = Path(COINS_CONFIG_PATH)
    if not cfg_path.is_absolute():
        cfg_path = BASE_DIR / cfg_path
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("coins.json must be a JSON object")
        return data
    except FileNotFoundError:
        raise SystemExit(f"[fatal] coins config '{cfg_path}' not found")
    except Exception as e:
        raise SystemExit(f"[fatal] failed to load coins config '{cfg_path}': {e}")


def resolve_evm_config() -> tuple[str, int, int]:
    """
    Resolve RPC URL, chain ID, decimals for PAYOUT_CURRENCY.

    Returns: (rpc_url, chain_id, decimals)
    """
    coins = load_coins_config()
    cfg = coins.get(PAYOUT_CURRENCY)
    if not cfg:
        raise SystemExit(f"[fatal] currency '{PAYOUT_CURRENCY}' not found in coins.json")

    ctype = str(cfg.get("type", "") or "").strip()
    if ctype != "evm_native":
        raise SystemExit(f"[fatal] currency '{PAYOUT_CURRENCY}' is not type 'evm_native' (got '{ctype}')")

    rpc_url = (cfg.get("rpc_url") or os.getenv("EVM_RPC_URL") or "").strip()
    if not rpc_url:
        raise SystemExit(f"[fatal] no rpc_url for '{PAYOUT_CURRENCY}' (set in coins.json or EVM_RPC_URL env)")

    chain_id_raw = cfg.get("chain_id") or os.getenv("EVM_CHAIN_ID")
    try:
        chain_id = int(chain_id_raw)
    except Exception:
        raise SystemExit(f"[fatal] invalid chain_id for '{PAYOUT_CURRENCY}' (coins.json or EVM_CHAIN_ID env)")

    decimals_cfg = cfg.get("decimals")
    try:
        decimals = int(decimals_cfg) if decimals_cfg is not None else 18
    except Exception:
        decimals = 18

    return rpc_url, chain_id, decimals


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA busy_timeout=30000;")
    return con


def ensure_tables(con: sqlite3.Connection) -> None:
    con.execute("""
    CREATE TABLE IF NOT EXISTS evm_payouts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created_at INTEGER NOT NULL,
      account_id TEXT NOT NULL,
      currency TEXT NOT NULL,
      to_address TEXT NOT NULL,
      hcc_locked INTEGER NOT NULL,
      redeem_request_id INTEGER NOT NULL,
      status TEXT NOT NULL,
      token_amount_wei TEXT,
      tx_hash TEXT,
      error TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_evm_payouts_status ON evm_payouts(status, currency, id);")


def fetch_next_pending(con: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """Fetch the next pending payout for this worker's currency."""
    return con.execute(
        "SELECT * FROM evm_payouts WHERE status='pending' AND currency=? ORDER BY id ASC LIMIT 1",
        (PAYOUT_CURRENCY,),
    ).fetchone()


def mark_sent(con: sqlite3.Connection, pid: int, txh: str) -> None:
    con.execute(
        "UPDATE evm_payouts SET status='sent', tx_hash=?, error='' WHERE id=?",
        (txh, pid),
    )


def mark_failed(con: sqlite3.Connection, pid: int, err: str) -> None:
    con.execute(
        "UPDATE evm_payouts SET status='failed', error=? WHERE id=?",
        (err[:500], pid),
    )


def append_redeem_jsonl(row: sqlite3.Row, tokens: float, tx_hash: str) -> None:
    """Append a redeem entry for the frontend/explorer."""
    try:
        entry = {
            "id": int(row["redeem_request_id"]),
            "payout_id": int(row["id"]),
            "ts": int(row["created_at"]),
            "account_id": str(row["account_id"]),
            "tip_address": str(row["to_address"]),
            "currency": str(row["currency"]),
            "credits_before": None,  # unknown hier
            "credits_spent": int(row["hcc_locked"]),
            "tip_amount": float(tokens),
            "txid": str(tx_hash),
            "rpc_error": None,
            "source": "evm_worker_native",
        }
        with open(REDEEM_QUEUE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[warn] failed to append redeem jsonl: {e}")


def main() -> None:
    if not TREASURY_PRIV or not TREASURY_ADDR:
        raise SystemExit("Missing EVM_TREASURY_PRIVKEY_DEGEN / EVM_TREASURY_ADDRESS_DEGEN in env.")

    rpc_url, chain_id, decimals = resolve_evm_config()

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise SystemExit(f"RPC not reachable: {rpc_url}")

    treasury = w3.to_checksum_address(TREASURY_ADDR)
    acct = w3.eth.account.from_key(TREASURY_PRIV)
    if acct.address.lower() != treasury.lower():
        raise SystemExit("EVM_TREASURY_ADDRESS_DEGEN does not match privkey address.")

    print(f"[worker-native] connected.")
    print(f"  currency={PAYOUT_CURRENCY}")
    print(f"  rpc_url={rpc_url}")
    print(f"  chain_id={chain_id}")
    print(f"  treasury={treasury}")
    print(f"  decimals={decimals}")
    print(f"  DEGEN_PER_HCC={DEGEN_PER_HCC}")
    print("  polling every", POLL_SEC, "seconds")

    while True:
        con = db()
        try:
            ensure_tables(con)
            row = fetch_next_pending(con)
            if not row:
                time.sleep(POLL_SEC)
                continue

            pid = int(row["id"])
            to_addr_raw = str(row["to_address"] or "").strip()

            # HCC -> DEGEN mapping
            hcc_locked = int(row["hcc_locked"])
            if hcc_locked <= 0 or DEGEN_PER_HCC <= 0:
                mark_failed(con, pid, f"invalid mapping: hcc_locked={hcc_locked}, DEGEN_PER_HCC={DEGEN_PER_HCC}")
                print(f"[fail] id={pid} invalid mapping hcc_locked={hcc_locked}")
                continue

            tokens = hcc_locked * DEGEN_PER_HCC
            amt_wei = int(tokens * (10 ** decimals))

            if amt_wei <= 0:
                mark_failed(con, pid, f"amount must be > 0 (got {amt_wei})")
                print(f"[fail] id={pid} non-positive amount_wei={amt_wei}")
                continue

            # Validate address
            try:
                to_addr = w3.to_checksum_address(to_addr_raw)
            except Exception:
                mark_failed(con, pid, f"invalid to_address: {to_addr_raw}")
                print(f"[fail] id={pid} invalid to={to_addr_raw}")
                continue

            # Persist amount_wei in table (optional, aber nice)
            try:
                con.execute(
                    "UPDATE evm_payouts SET token_amount_wei=? WHERE id=?",
                    (str(amt_wei), pid),
                )
            except Exception as e:
                print(f"[warn] failed to update token_amount_wei for id={pid}: {e}")

            try:
                # Build native token transaction
                nonce = w3.eth.get_transaction_count(treasury, "pending")
                tx = {
                    "chainId": chain_id,
                    "from": treasury,
                    "to": to_addr,
                    "nonce": nonce,
                    "value": amt_wei,
                }

                # Gas estimate + bump
                est = w3.eth.estimate_gas(tx)
                tx["gas"] = max(21000, int(est * GAS_MULT))

                # EIP-1559 vs legacy
                try:
                    latest = w3.eth.get_block("latest")
                    base_fee = latest.get("baseFeePerGas")
                    if base_fee is not None:
                        prio = w3.to_wei(1, "gwei")
                        tx["maxPriorityFeePerGas"] = prio
                        tx["maxFeePerGas"] = int(base_fee * 2 + prio)
                    else:
                        tx["gasPrice"] = w3.eth.gas_price
                except Exception:
                    tx["gasPrice"] = w3.eth.gas_price

                signed = w3.eth.account.sign_transaction(tx, private_key=TREASURY_PRIV)
                tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()

                mark_sent(con, pid, tx_hash)
                print(f"[sent] id={pid} currency={PAYOUT_CURRENCY} to={to_addr} amount_wei={amt_wei} (~{tokens} DEGEN) tx={tx_hash}")

                append_redeem_jsonl(row, tokens, tx_hash)

                # Nach erfolgreicher Auszahlung HCC burnen + Events loggen
                try:
                    con.execute("BEGIN IMMEDIATE;")
                    account_id = str(row["account_id"])
                    redeem_request_id = int(row["redeem_request_id"])

                    _burn_locked_credits_atomic(con, account_id, hcc_locked)
                    log_event(
                        con,
                        ts=now_unix(),
                        type="redeem_burn",
                        account_id=account_id,
                        amount=-hcc_locked,
                        other="burn",
                        meta={
                            "request_id": redeem_request_id,
                            "payout_id": pid,
                            "currency": PAYOUT_CURRENCY,
                        },
                    )

                    note = f"{PAYOUT_CURRENCY} {tokens} txid={tx_hash}"
                    con.execute(
                        "UPDATE redeem_requests SET state=?, note=? WHERE id=?",
                        ("sent", note, redeem_request_id),
                    )

                    log_event(
                        con,
                        ts=now_unix(),
                        type="redeem_sent",
                        account_id=account_id,
                        amount=0,
                        other=PAYOUT_CURRENCY,
                        meta={
                            "request_id": redeem_request_id,
                            "tip_amount": float(tokens),
                            "txid": tx_hash,
                        },
                    )

                    con.execute("COMMIT;")
                except Exception as e:
                    try:
                        con.execute("ROLLBACK;")
                    except Exception:
                        pass
                    print(f"[warn] failed to burn locked credits / log events for payout id={pid}: {e}")

            except Exception as e:
                err = f"send error: {repr(e)}"
                mark_failed(con, pid, err)
                print(f"[fail] id={pid} err={err}")

        finally:
            con.close()


if __name__ == "__main__":
    main()