#!/usr/bin/env python3
"""
EVM ERC20 payout worker for HashCash.

- Reads pending payouts from faucet.db (table evm_payouts).
- Sends ERC20 transfers on an EVM chain (e.g. Degenchain L3).
- Uses coins.json to get RPC URL, chain ID and token contract for one currency.

This script is intentionally single-currency:
    EVM_PAYOUT_CURRENCY = "LRGK"   (env, symbol must exist in coins.json)
    Gas is paid in the chain's native token (DEGEN on Degen L3).
"""

import json
import os
import time
import sqlite3
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import TransactionNotFound  # not used yet, but handy later
from app import _burn_locked_credits_atomic, log_event

# -------------------------
# Env + paths
# -------------------------

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

BASE_DIR = BACKEND_DIR

REDEEM_QUEUE_FILE = BASE_DIR / "redeem_queue.jsonl"

# Reuse the same DB env as the backend (FAUCET_DB), with a fallback.
DB_PATH = (os.getenv("FAUCET_DB") or str(BASE_DIR / "faucet.db")).strip()

# How often to poll for new payouts (seconds)
POLL_SEC = max(1, int(os.getenv("EVM_PAYOUT_POLL_SEC", "5")))

# Which currency from coins.json this worker handles
#PAYOUT_CURRENCY = (os.getenv("EVM_PAYOUT_CURRENCY") or "ETH").strip().upper()
PAYOUT_CURRENCY = "LRGK"

# Gas multiplier for the estimate
GAS_MULT = float(os.getenv("PAYOUT_GAS_MULT", "1.15"))

# Treasury credentials (never in coins.json, only in env!)
TREASURY_PRIV = (os.getenv("EVM_TREASURY_PRIVKEY_LRGK") or "").strip()
TREASURY_ADDR = (os.getenv("EVM_TREASURY_ADDRESS_LRGK") or "").strip()

# Path to coins.json (same as backend)
COINS_CONFIG_PATH = os.getenv("COINS_CONFIG_PATH", str(BASE_DIR / "coins.json"))

# Minimal ERC20 ABI: transfer + decimals
ERC20_ABI = json.loads("""
[
  {
    "constant": false,
    "inputs": [
      {"name": "_to", "type": "address"},
      {"name": "_value", "type": "uint256"}
    ],
    "name": "transfer",
    "outputs": [{"name": "", "type": "bool"}],
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "decimals",
    "outputs": [{"name": "", "type": "uint8"}],
    "type": "function"
  }
]
""")


# -------------------------
# Helpers
# -------------------------

def now_unix() -> int:
    return int(time.time())


def load_coins_config() -> dict:
    """Load coins.json and return it as dict."""
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


def resolve_evm_config() -> tuple[str, int, str, int]:
    """
    Resolve RPC URL, chain ID, token contract, decimals for PAYOUT_CURRENCY.

    Returns: (rpc_url, chain_id, token_contract, decimals)
    """
    coins = load_coins_config()
    cfg = coins.get(PAYOUT_CURRENCY)
    if not cfg:
        raise SystemExit(f"[fatal] currency '{PAYOUT_CURRENCY}' not found in coins.json")

    ctype = cfg.get("type", "").strip()
    if ctype != "evm_erc20":
        raise SystemExit(f"[fatal] currency '{PAYOUT_CURRENCY}' is not type 'evm_erc20' (got '{ctype}')")

    rpc_url = (cfg.get("rpc_url") or os.getenv("EVM_RPC_URL") or "").strip()
    if not rpc_url:
        raise SystemExit(f"[fatal] no rpc_url for '{PAYOUT_CURRENCY}' (set in coins.json or EVM_RPC_URL env)")

    chain_id_raw = cfg.get("chain_id") or os.getenv("EVM_CHAIN_ID")
    try:
        chain_id = int(chain_id_raw)
    except Exception:
        raise SystemExit(f"[fatal] invalid chain_id for '{PAYOUT_CURRENCY}' (coins.json or EVM_CHAIN_ID env)")

    contract = (cfg.get("contract") or "").strip()
    if not contract:
        raise SystemExit(f"[fatal] no 'contract' address for '{PAYOUT_CURRENCY}' in coins.json")

    decimals_cfg = cfg.get("decimals")
    try:
        decimals = int(decimals_cfg) if decimals_cfg is not None else int(os.getenv("EVM_TOKEN_DECIMALS", "18"))
    except Exception:
        decimals = 18

    return rpc_url, chain_id, contract, decimals


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA busy_timeout=30000;")
    return con


def ensure_tables(con: sqlite3.Connection) -> None:
    """
    Generic EVM payout table for faucet:

    - created_at    : timestamp when the redeem request was created
    - account_id    : HCC account ID (address) in faucet.db
    - currency      : symbol, e.g. "DEGEN"
    - to_address    : EVM address on target chain
    - token_amount_wei    : string representation of integer token amount in wei
    - hcc_locked    : number of HCC credits locked/burned for this payout
    - status        : 'pending' | 'sent' | 'failed'
    - tx_hash       : transaction hash (if sent)
    - error         : last error message, if any
    """
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


def append_redeem_jsonl(row: sqlite3.Row, decimals: int, tx_hash: str, tokens: float) -> None:
    try:
        entry = {
            "id": int(row["redeem_request_id"]),
            "payout_id": int(row["id"]),
            "ts": int(row["created_at"]),
            "account_id": str(row["account_id"]),
            "tip_address": str(row["to_address"]),
            "currency": str(row["currency"]),
            "credits_before": None,
            "credits_spent": int(row["hcc_locked"]),
            "tip_amount": float(tokens),
            "txid": str(tx_hash),
            "rpc_error": None,
            "source": "evm_worker",
        }
        with open(REDEEM_QUEUE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[warn] failed to append redeem jsonl: {e}")


# -------------------------
# Main worker loop
# -------------------------

def main() -> None:
    if not TREASURY_PRIV or not TREASURY_ADDR:
        raise SystemExit("Missing EVM_TREASURY_PRIVKEY / EVM_TREASURY_ADDRESS in env.")

    rpc_url, chain_id, token_addr, decimals = resolve_evm_config()

    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
    if not w3.is_connected():
        raise SystemExit(f"RPC not reachable: {rpc_url}")

    treasury = w3.to_checksum_address(TREASURY_ADDR)
    acct = w3.eth.account.from_key(TREASURY_PRIV)
    if acct.address.lower() != treasury.lower():
        raise SystemExit("EVM_TREASURY_ADDRESS does not match privkey address.")

    token = w3.eth.contract(address=w3.to_checksum_address(token_addr), abi=ERC20_ABI)

    # Optional: override decimals from chain if call works and env/coins.json was wrong/missing
    try:
        chain_dec = int(token.functions.decimals().call())
        if 0 <= chain_dec <= 36:
            decimals = chain_dec
    except Exception:
        pass

    print(f"[worker-erc20] connected.")
    print(f"  currency={PAYOUT_CURRENCY}")
    print(f"  rpc_url={rpc_url}")
    print(f"  chain_id={chain_id}")
    print(f"  token={token_addr}")
    print(f"  treasury={treasury}")
    print(f"  decimals={decimals}")
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
            amt_wei_str = str(row["token_amount_wei"] or "0").strip() or "0"

            try:
                amt_wei = int(amt_wei_str)
            except Exception:
                mark_failed(con, pid, f"invalid token_amount_wei: {amt_wei_str}")
                print(f"[fail] id={pid} invalid amount_wei={amt_wei_str}")
                continue

            # Validate address
            try:
                to_addr = w3.to_checksum_address(to_addr_raw)
            except Exception:
                mark_failed(con, pid, f"invalid to_address: {to_addr_raw}")
                print(f"[fail] id={pid} invalid to={to_addr_raw}")
                continue

            if amt_wei <= 0:
                mark_failed(con, pid, f"amount must be > 0 (got {amt_wei})")
                print(f"[fail] id={pid} non-positive token_amount_wei={amt_wei}")
                continue

            tokens = amt_wei / (10 ** decimals) if decimals >= 0 else 0.0

            try:
                # Build transaction
                nonce = w3.eth.get_transaction_count(treasury, "pending")
                tx = token.functions.transfer(to_addr, amt_wei).build_transaction({
                    "chainId": chain_id,
                    "from": treasury,
                    "nonce": nonce,
                })

                # Gas estimate + bump
                est = w3.eth.estimate_gas(tx)
                tx["gas"] = max(21000, int(est * GAS_MULT))

                # Try EIP-1559 first; fallback to legacy gasPrice
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
                print(f"[sent] id={pid} currency={PAYOUT_CURRENCY} to={to_addr} token_amount_wei={amt_wei} tx={tx_hash}")
                append_redeem_jsonl(row, decimals, tx_hash, tokens)

                # After a successful on-chain payout, burn the locked HCC credits and log events
                try:
                    con.execute("BEGIN IMMEDIATE;")
                    hcc_locked = int(row["hcc_locked"])
                    account_id = str(row["account_id"])
                    redeem_request_id = int(row["redeem_request_id"])

                    # Burn locked credits
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

                    # Mark redeem_request as sent with a human-readable note
                    note = f"{PAYOUT_CURRENCY} {tokens} txid={tx_hash}"
                    con.execute(
                        "UPDATE redeem_requests SET state=?, note=? WHERE id=?",
                        ("sent", note, redeem_request_id),
                    )

                    # Log a redeem_sent event for the explorer
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
                    # If anything fails here, keep the credits locked for safety
                    try:
                        con.execute("ROLLBACK;")
                    except Exception:
                        pass
                    print(f"[warn] failed to burn locked credits / log events for payout id={pid}: {e}")

            except Exception as e:
                # Note: some errors are ambiguous (e.g. timeout after broadcast).
                # For now we mark as 'failed' and log the error; we can later improve this
                # by keeping it 'pending' and adding manual inspection tools.
                err = f"send error: {repr(e)}"
                mark_failed(con, pid, err)
                print(f"[fail] id={pid} err={err}")

        finally:
            con.close()


if __name__ == "__main__":
    main()