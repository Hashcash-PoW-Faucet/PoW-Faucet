# migrate_escrow.py
import sqlite3
import os
from pathlib import Path

# Make default DB path stable even if you run the script from repo root.
HERE = Path(__file__).resolve().parent
DB_PATH = os.getenv("FAUCET_DB", str(HERE / "faucet.db"))


def column_exists(con: sqlite3.Connection, table: str, column: str) -> bool:
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)  # r[1] = name


def table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def add_column_if_missing(con: sqlite3.Connection, table: str, col: str, ddl: str) -> None:
    if not table_exists(con, table):
        return
    if column_exists(con, table, col):
        print(f"{table}.{col} already exists")
        return
    con.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    print(f"Added {table}.{col}")


def main():
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    try:
        # Optional: keep same pragmas as server
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")

        con.execute("BEGIN IMMEDIATE;")

        # 1) Add accounts.locked_credits (idempotent)
        if table_exists(con, "accounts"):
            add_column_if_missing(
                con,
                "accounts",
                "locked_credits",
                "locked_credits INTEGER NOT NULL DEFAULT 0",
            )
        else:
            print("accounts table does not exist yet (OK)")

        # 2) Create DEX tables (idempotent)
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

        # 2b) If tables already existed from an earlier migration, ensure new columns exist (idempotent)
        # dex_orders columns (only add if missing)
        add_column_if_missing(con, "dex_orders", "created_at", "created_at INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_orders", "maker_account_id", "maker_account_id TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_orders", "side", "side TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_orders", "currency", "currency TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_orders", "credits_amount", "credits_amount INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_orders", "price_sat_per_credit", "price_sat_per_credit INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_orders", "pay_to_address", "pay_to_address TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_orders", "status", "status TEXT NOT NULL DEFAULT 'OPEN'")

        # dex_trades columns (only add if missing)
        add_column_if_missing(con, "dex_trades", "created_at", "created_at INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "order_id", "order_id INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "maker_account_id", "maker_account_id TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_trades", "taker_account_id", "taker_account_id TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_trades", "side", "side TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_trades", "currency", "currency TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_trades", "credits_amount", "credits_amount INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "pay_to_address", "pay_to_address TEXT NOT NULL DEFAULT ''")
        add_column_if_missing(con, "dex_trades", "expected_sats", "expected_sats INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "txid", "txid TEXT")
        add_column_if_missing(con, "dex_trades", "confs", "confs INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "expires_at", "expires_at INTEGER NOT NULL DEFAULT 0")
        add_column_if_missing(con, "dex_trades", "state", "state TEXT NOT NULL DEFAULT 'WAIT_PAYMENT'")
        add_column_if_missing(con, "dex_trades", "settled_at", "settled_at INTEGER")

        # 3) Indexes (idempotent)
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_dex_orders_open "
            "ON dex_orders(status, currency, side, price_sat_per_credit);"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_dex_trades_state "
            "ON dex_trades(state, currency);"
        )

        # Helpful for expirer/cron scanning due trades
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_dex_trades_due "
            "ON dex_trades(state, expires_at);"
        )

        # Anti-abuse: prevent re-using a txid for multiple trades of the same currency
        # (We also exclude empty-string txids just in case.)
        con.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_dex_trades_txid_unique "
            "ON dex_trades(currency, txid) "
            "WHERE txid IS NOT NULL AND txid <> '';"
        )

        con.execute("COMMIT;")
        print("Migration OK.")

    except Exception:
        try:
            con.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        con.close()


if __name__ == "__main__":
    main()