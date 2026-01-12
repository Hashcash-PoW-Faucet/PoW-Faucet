# dex.py
import sqlite3
from typing import Callable, Optional, Set, List, Dict, Any

from fastapi import APIRouter, Request, HTTPException

# Local imports (support running as `app:app` and as `backend.app:app`)
try:
    from .dex_store import fetch_orders, fetch_orders_by_maker, fetch_trades_for_account  # type: ignore
    from .dex_models import (  # type: ignore
        DexOrderCreateIn,
        DexOrderTakeIn,
        DexOrderOut,
        DexOrderCancelOut,
        DexTradeOut,
    )
except ImportError:
    from dex_store import fetch_orders, fetch_orders_by_maker, fetch_trades_for_account  # type: ignore
    from dex_models import (  # type: ignore
        DexOrderCreateIn,
        DexOrderTakeIn,
        DexOrderOut,
        DexOrderCancelOut,
        DexTradeOut,
    )


def create_dex_router(
    db_func: Callable[[], sqlite3.Connection],
    auth_func: Callable[[Request], str],
    now_unix_func: Callable[[], int],
    is_valid_address_func: Callable[[str, str], bool],
    supported_currency_func: Callable[[str], bool],
    trade_ttl_sell_sec: int,
    trade_ttl_buy_sec: int,
    allowed_sides: Set[str],
    lock_credits_atomic_func: Callable[[sqlite3.Connection, str, int], None],
    unlock_credits_atomic_func: Callable[[sqlite3.Connection, str, int], None],
) -> APIRouter:
    router = APIRouter()

    @router.get("/orders")
    def dex_list_orders(
        req: Request,
        status: str = "OPEN",
        currency: Optional[str] = None,
        side: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ):
        _ = auth_func(req)
        con = db_func()
        try:
            return fetch_orders(
                con,
                status=status,
                currency=currency,
                side=side,
                limit=limit,
                offset=offset,
            )
        finally:
            con.close()

    @router.get("/orders/mine")
    def dex_list_my_orders(
        req: Request,
        status: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ):
        me = auth_func(req)
        con = db_func()
        try:
            return fetch_orders_by_maker(
                con,
                maker_account_id=me,
                status=status,
                limit=limit,
                offset=offset,
            )
        finally:
            con.close()

    @router.get("/trades/mine")
    def dex_list_my_trades(
        req: Request,
        state: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ):
        me = auth_func(req)
        con = db_func()
        try:
            return fetch_trades_for_account(
                con,
                account_id=me,
                state=state,
                limit=limit,
                offset=offset,
            )
        finally:
            con.close()

    @router.post("/orders", response_model=DexOrderOut)
    def dex_create_order(data: DexOrderCreateIn, req: Request):
        maker = auth_func(req)

        side = (data.side or "").strip().upper()
        currency = (data.currency or "").strip().upper()
        credits_amount = int(data.credits_amount)
        price = int(data.price_sat_per_credit)
        pay_to_address = (data.pay_to_address or "").strip()

        if side not in allowed_sides:
            raise HTTPException(status_code=400, detail=f"unsupported side: {side}")
        if not supported_currency_func(currency):
            raise HTTPException(status_code=400, detail=f"unsupported currency: {currency}")
        if credits_amount <= 0:
            raise HTTPException(status_code=400, detail="credits_amount must be positive")
        if price <= 0:
            raise HTTPException(status_code=400, detail="price_sat_per_credit must be positive")
        if side == "SELL_CREDITS":
            # Taker will pay on-chain to maker's address
            if not pay_to_address:
                raise HTTPException(status_code=400, detail="missing pay_to_address")
            if not is_valid_address_func(currency, pay_to_address):
                raise HTTPException(status_code=400, detail=f"invalid address for currency {currency}")
        elif side == "BUY_CREDITS":
            # Maker will pay on-chain to the taker; taker provides address when taking the order.
            # Keep a non-null placeholder to satisfy the current schema (pay_to_address is NOT NULL).
            pay_to_address = pay_to_address or ""

        con = db_func()
        try:
            ts = int(now_unix_func())
            con.execute("BEGIN IMMEDIATE;")

            # Ensure maker exists
            row = con.execute("SELECT account_id FROM accounts WHERE account_id=?", (maker,)).fetchone()
            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=401, detail="unknown account")

            # Escrow rules:
            # - SELL_CREDITS: maker escrows credits at order creation
            # - BUY_CREDITS:  taker escrows credits at order take time
            if side == "SELL_CREDITS":
                try:
                    lock_credits_atomic_func(con, maker, credits_amount)
                except ValueError as e:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=400, detail=str(e))

            cur = con.execute(
                """
                INSERT INTO dex_orders(created_at, maker_account_id, side, currency, credits_amount, price_sat_per_credit, pay_to_address, status)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (ts, maker, side, currency, credits_amount, price, pay_to_address, "OPEN"),
            )
            order_id = int(cur.lastrowid)

            con.execute("COMMIT;")
            return DexOrderOut(
                order_id=order_id,
                created_at=ts,
                maker_account_id=maker,
                side=side,
                currency=currency,
                credits_amount=credits_amount,
                price_sat_per_credit=price,
                pay_to_address=pay_to_address,
                status="OPEN",
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

    @router.post("/orders/{order_id}/cancel", response_model=DexOrderCancelOut)
    def dex_cancel_order(order_id: int, req: Request):
        maker = auth_func(req)
        con = db_func()
        try:
            con.execute("BEGIN IMMEDIATE;")
            row = con.execute(
                """
                SELECT maker_account_id, side, status, credits_amount
                FROM dex_orders
                WHERE id=?
                """,
                (order_id,),
            ).fetchone()
            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown order")

            maker_db, side, status, credits_amount = row
            side = str(side).upper()
            credits_amount = int(credits_amount)

            if str(maker_db) != maker:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=403, detail="not your order")
            if status != "OPEN":
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"cannot cancel order in state {status}")

            cur = con.execute(
                "UPDATE dex_orders SET status='CANCELLED' WHERE id=? AND status='OPEN'",
                (order_id,),
            )
            if cur.rowcount != 1:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="order not open")

            # Unlock only if the maker had escrowed credits (SELL_CREDITS).
            if side == "SELL_CREDITS":
                try:
                    unlock_credits_atomic_func(con, maker, credits_amount)
                except ValueError as e:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=500, detail=f"ledger error: {e}")

            con.execute("COMMIT;")
            return DexOrderCancelOut(ok=True, order_id=int(order_id), status="CANCELLED")

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

    @router.post("/orders/{order_id}/take", response_model=DexTradeOut)
    def dex_take_order(order_id: int, data: DexOrderTakeIn, req: Request):
        taker = auth_func(req)
        con = db_func()
        try:
            ts = int(now_unix_func())
            con.execute("BEGIN IMMEDIATE;")

            row = con.execute(
                """
                SELECT maker_account_id, side, currency, credits_amount, price_sat_per_credit, pay_to_address, status
                FROM dex_orders
                WHERE id=?
                """,
                (order_id,),
            ).fetchone()
            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown order")

            maker, side, currency, credits_amount, price, pay_to_address, status = row
            side = str(side).strip().upper()
            currency = str(currency).strip().upper()
            credits_amount = int(credits_amount)
            price = int(price)
            pay_to_address = str(pay_to_address or "")

            # In the trade we store the actual on-chain destination address:
            # - SELL_CREDITS: taker pays to maker's address from the order
            # - BUY_CREDITS:  maker pays to taker's provided address
            if side == "SELL_CREDITS":
                trade_pay_to_address = pay_to_address
            elif side == "BUY_CREDITS":
                trade_pay_to_address = (data.taker_pay_to_address or "").strip()
                if not trade_pay_to_address:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=400, detail="missing taker_pay_to_address for BUY_CREDITS")
                if not is_valid_address_func(currency, trade_pay_to_address):
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=400, detail=f"invalid address for currency {currency}")
            else:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

            if status != "OPEN":
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"order not open (status={status})")
            if str(maker) == taker:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail="cannot take your own order")
            if side not in allowed_sides:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

            expected_sats = credits_amount * price

            # Side-specific payment window (SELL: short; BUY: longer because maker might be offline)
            ttl = int(trade_ttl_sell_sec)
            if side == "BUY_CREDITS":
                ttl = int(trade_ttl_buy_sec)
            if ttl < 60:
                ttl = 60
            expires_at = ts + ttl

            # Mark order as taken
            cur = con.execute(
                "UPDATE dex_orders SET status='TAKEN' WHERE id=? AND status='OPEN'",
                (order_id,),
            )
            if cur.rowcount != 1:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="order was taken concurrently")

            # Escrow rules:
            # - SELL_CREDITS: maker already escrowed at order creation
            # - BUY_CREDITS:  taker must escrow credits now (because taker will deliver credits after maker pays on-chain)
            if side == "BUY_CREDITS":
                try:
                    lock_credits_atomic_func(con, taker, credits_amount)
                except ValueError as e:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=400, detail=str(e))

            cur = con.execute(
                """
                INSERT INTO dex_trades(created_at, order_id, maker_account_id, taker_account_id, side, currency, credits_amount,
                                      pay_to_address, expected_sats, txid, confs, expires_at, state, settled_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (ts, int(order_id), str(maker), taker, side, currency, credits_amount, trade_pay_to_address,
                 expected_sats, None, 0, expires_at, "WAIT_PAYMENT", None),
            )
            trade_id = int(cur.lastrowid)

            con.execute("COMMIT;")
            return DexTradeOut(
                trade_id=trade_id,
                order_id=int(order_id),
                created_at=ts,
                maker_account_id=str(maker),
                taker_account_id=taker,
                side=side,
                currency=currency,
                credits_amount=credits_amount,
                pay_to_address=trade_pay_to_address,
                expected_sats=expected_sats,
                txid=None,
                confs=0,
                expires_at=expires_at,
                state="WAIT_PAYMENT",
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

    # Expire a trade if it is due, and unlock escrowed credits as needed.
    @router.post("/trades/{trade_id}/expire")
    def dex_expire_trade(trade_id: int, req: Request):
        """Expire a trade if it is due, and unlock escrowed credits as needed.

        This is safe to call manually (e.g., from a cron job) or by a party to the trade.
        It only expires trades whose `expires_at` is in the past.

        Rules:
          - SELL_CREDITS: escrow is on the maker at order creation; on trade expiry we keep the order OPEN and keep maker escrow in place.
          - BUY_CREDITS: escrow is on the taker at take-time; on trade expiry we must unlock the taker's credits.

        The order is reopened (status=OPEN) so it can be taken again.
        """
        caller = auth_func(req)
        con = db_func()
        try:
            now = int(now_unix_func())
            con.execute("BEGIN IMMEDIATE;")

            row = con.execute(
                """
                SELECT id, order_id, state, expires_at, side, maker_account_id, taker_account_id, credits_amount
                FROM dex_trades
                WHERE id=?
                """,
                (trade_id,),
            ).fetchone()

            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown trade")

            tid, order_id, state, expires_at, side, maker, taker, credits_amount = row
            side = str(side).strip().upper()
            state = str(state)
            expires_at = int(expires_at)
            credits_amount = int(credits_amount)

            # Only participants may expire (you can relax this later for a public cron).
            if caller not in (str(maker), str(taker)):
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=403, detail="not a participant")

            if state != "WAIT_PAYMENT":
                con.execute("ROLLBACK;")
                return {"ok": True, "trade_id": int(tid), "state": state, "detail": "not in WAIT_PAYMENT"}

            if expires_at > now:
                con.execute("ROLLBACK;")
                return {"ok": True, "trade_id": int(tid), "state": state, "detail": "not expired yet",
                        "expires_at": expires_at, "now": now}

            # Mark trade expired (idempotent under this transaction)
            cur = con.execute(
                "UPDATE dex_trades SET state='EXPIRED' WHERE id=? AND state='WAIT_PAYMENT'",
                (trade_id,),
            )
            if cur.rowcount != 1:
                con.execute("ROLLBACK;")
                return {"ok": True, "trade_id": int(tid), "state": state, "detail": "already updated"}

            # Re-open the order so it can be taken again
            con.execute(
                "UPDATE dex_orders SET status='OPEN' WHERE id=? AND status='TAKEN'",
                (int(order_id),),
            )

            # Unlock escrow depending on side
            if side == "BUY_CREDITS":
                # Taker had locked credits at take-time
                unlock_credits_atomic_func(con, str(taker), credits_amount)
            elif side == "SELL_CREDITS":
                # Maker escrow remains, because the order is now OPEN again
                pass
            else:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

            con.execute("COMMIT;")
            return {"ok": True, "trade_id": int(tid), "state": "EXPIRED", "order_id": int(order_id)}

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

    @router.get("/trades/{trade_id}", response_model=DexTradeOut)
    def dex_get_trade(trade_id: int, req: Request):
        # Any authenticated user can query a trade (you can tighten this later).
        _ = auth_func(req)
        con = db_func()
        try:
            row = con.execute(
                """
                SELECT id, order_id, created_at, maker_account_id, taker_account_id, side, currency, credits_amount,
                       pay_to_address, expected_sats, txid, confs, expires_at, state
                FROM dex_trades
                WHERE id=?
                """,
                (trade_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown trade")

            (tid, oid, created_at, maker, taker, side, currency, credits_amount,
             pay_to_address, expected_sats, txid, confs, expires_at, state) = row

            return DexTradeOut(
                trade_id=int(tid),
                order_id=int(oid),
                created_at=int(created_at),
                maker_account_id=str(maker),
                taker_account_id=str(taker),
                side=str(side),
                currency=str(currency),
                credits_amount=int(credits_amount),
                pay_to_address=str(pay_to_address),
                expected_sats=int(expected_sats),
                txid=str(txid) if txid is not None else None,
                confs=int(confs),
                expires_at=int(expires_at),
                state=str(state),
            )
        finally:
            con.close()

    @router.post("/expire_due")
    def dex_expire_due(req: Request, limit: int = 200):
        """Expire all due WAIT_PAYMENT trades and unlock escrowed credits as needed.

        This is intended for a cron job or an operator script. It is safe and idempotent:
        - It only affects trades whose `expires_at` is in the past.
        - It only transitions state WAIT_PAYMENT -> EXPIRED.
        - For BUY_CREDITS, it unlocks the taker's escrowed credits.
        - For SELL_CREDITS, maker escrow remains, because the order is re-opened.

        Any authenticated account may call this; the checks are time-based.
        """
        _ = auth_func(req)

        try:
            limit = int(limit)
        except Exception:
            limit = 200
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000

        now = int(now_unix_func())
        con = db_func()
        try:
            con.execute("BEGIN IMMEDIATE;")

            rows = con.execute(
                """
                SELECT id, order_id, side, maker_account_id, taker_account_id, credits_amount
                FROM dex_trades
                WHERE state='WAIT_PAYMENT' AND expires_at <= ?
                ORDER BY expires_at ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()

            expired: List[int] = []

            for tid, order_id, side, maker, taker, credits_amount in rows:
                side = str(side).strip().upper()
                credits_amount = int(credits_amount)

                # Mark trade expired (idempotent)
                cur = con.execute(
                    "UPDATE dex_trades SET state='EXPIRED' WHERE id=? AND state='WAIT_PAYMENT'",
                    (int(tid),),
                )
                if cur.rowcount != 1:
                    continue

                # Re-open the order so it can be taken again
                con.execute(
                    "UPDATE dex_orders SET status='OPEN' WHERE id=? AND status='TAKEN'",
                    (int(order_id),),
                )

                # Unlock escrow depending on side
                if side == "BUY_CREDITS":
                    # Taker had locked credits at take-time
                    unlock_credits_atomic_func(con, str(taker), credits_amount)
                elif side == "SELL_CREDITS":
                    # Maker escrow remains, because the order is now OPEN again
                    pass
                else:
                    raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

                expired.append(int(tid))

            con.execute("COMMIT;")
            return {"ok": True, "count": len(expired), "expired": expired}

        except HTTPException:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        except Exception:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            con.close()

    return router


def create_dex_admin_router(
    db_func: Callable[[], sqlite3.Connection],
    require_admin_func: Callable[[Request], None],
    now_unix_func: Callable[[], int],
    transfer_locked_credits_atomic_func: Callable[[sqlite3.Connection, str, str, int], None],
) -> APIRouter:
    """Admin-only DEX endpoints.

    Mount this router with prefix `/admin/dex`.
    """
    router = APIRouter()

    @router.get("/trades/pending")
    def admin_dex_pending_trades(req: Request, limit: int = 200, state: str = "WAIT_PAYMENT"):
        """
        List trades by state(s). Default: WAIT_PAYMENT.
        You can pass e.g. state="WAIT_PAYMENT,CONFIRMED".
        """
        require_admin_func(req)

        try:
            limit_i = int(limit)
        except Exception:
            limit_i = 200
        limit_i = max(1, min(1000, limit_i))

        states = [s.strip().upper() for s in (state or "WAIT_PAYMENT").split(",") if s.strip()]
        if not states:
            states = ["WAIT_PAYMENT"]

        placeholders = ",".join(["?"] * len(states))

        con = db_func()
        try:
            rows = con.execute(
                f"""
                SELECT
                  id, order_id, created_at, maker_account_id, taker_account_id,
                  side, currency, credits_amount, pay_to_address, expected_sats,
                  txid, confs, expires_at, state
                FROM dex_trades
                WHERE state IN ({placeholders})
                ORDER BY expires_at ASC
                LIMIT ?
                """,
                (*states, limit_i),
            ).fetchall()

            trades: List[Dict[str, Any]] = []
            for r in rows:
                (tid, order_id, created_at, maker, taker, side, currency, credits_amount,
                 pay_to_address, expected_sats, txid, confs, expires_at, st) = r

                trades.append({
                    "trade_id": int(tid),
                    "order_id": int(order_id),
                    "created_at": int(created_at),
                    "maker_account_id": str(maker),
                    "taker_account_id": str(taker),
                    "side": str(side),
                    "currency": str(currency),
                    "credits_amount": int(credits_amount),
                    "pay_to_address": str(pay_to_address),
                    "expected_sats": int(expected_sats),
                    "txid": str(txid) if txid is not None else None,
                    "confs": int(confs),
                    "expires_at": int(expires_at),
                    "state": str(st),
                })

            return {"ok": True, "count": len(trades), "trades": trades}
        finally:
            con.close()

    @router.get("/trades/{trade_id}")
    def admin_dex_get_trade(trade_id: int, req: Request):
        """Admin: get full details for a single trade (debug-friendly)."""
        require_admin_func(req)

        con = db_func()
        try:
            row = con.execute(
                """
                SELECT
                  id, order_id, created_at, maker_account_id, taker_account_id,
                  side, currency, credits_amount, pay_to_address, expected_sats,
                  txid, confs, expires_at, state, settled_at
                FROM dex_trades
                WHERE id=?
                """,
                (int(trade_id),),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="unknown trade")

            (tid, order_id, created_at, maker, taker,
             side, currency, credits_amount, pay_to_address, expected_sats,
             txid, confs, expires_at, state, settled_at) = row

            # Extra debug info: order status + balances
            order_row = con.execute(
                "SELECT status FROM dex_orders WHERE id=?",
                (int(order_id),),
            ).fetchone()
            order_status = str(order_row[0]) if order_row else None

            maker_bal = con.execute(
                "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                (str(maker),),
            ).fetchone()
            maker_credits = int(maker_bal[0]) if maker_bal else None
            maker_locked = int(maker_bal[1]) if maker_bal else None

            taker_bal = con.execute(
                "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                (str(taker),),
            ).fetchone()
            taker_credits = int(taker_bal[0]) if taker_bal else None
            taker_locked = int(taker_bal[1]) if taker_bal else None

            return {
                "ok": True,
                "trade": {
                    "trade_id": int(tid),
                    "order_id": int(order_id),
                    "created_at": int(created_at),
                    "maker_account_id": str(maker),
                    "taker_account_id": str(taker),
                    "side": str(side),
                    "currency": str(currency),
                    "credits_amount": int(credits_amount),
                    "pay_to_address": str(pay_to_address),
                    "expected_sats": int(expected_sats),
                    "txid": str(txid) if txid is not None else None,
                    "confs": int(confs),
                    "expires_at": int(expires_at),
                    "state": str(state),
                    "settled_at": int(settled_at) if settled_at is not None else None,
                    "order_status": order_status,
                    "maker_balance": {"credits": maker_credits, "locked_credits": maker_locked},
                    "taker_balance": {"credits": taker_credits, "locked_credits": taker_locked},
                },
            }
        finally:
            con.close()

    @router.get("/orders/{order_id}")
    def admin_dex_get_order(order_id: int, req: Request):
        """Admin: get full details for a single order including its trade(s) and balances (debug-friendly)."""
        require_admin_func(req)

        con = db_func()
        try:
            order_row = con.execute(
                """
                SELECT
                  id, created_at, maker_account_id, side, currency, credits_amount,
                  price_sat_per_credit, pay_to_address, status
                FROM dex_orders
                WHERE id=?
                """,
                (int(order_id),),
            ).fetchone()
            if not order_row:
                raise HTTPException(status_code=404, detail="unknown order")

            (oid, created_at, maker, side, currency, credits_amount,
             price_sat_per_credit, pay_to_address, status) = order_row

            # Trades for this order (usually 0 or 1, but we keep it generic)
            trade_rows = con.execute(
                """
                SELECT
                  id, created_at, maker_account_id, taker_account_id, side, currency,
                  credits_amount, pay_to_address, expected_sats, txid, confs, expires_at, state, settled_at
                FROM dex_trades
                WHERE order_id=?
                ORDER BY id ASC
                """,
                (int(order_id),),
            ).fetchall()

            # Balances
            maker_bal = con.execute(
                "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                (str(maker),),
            ).fetchone()
            maker_credits = int(maker_bal[0]) if maker_bal else None
            maker_locked = int(maker_bal[1]) if maker_bal else None

            taker_ids = sorted({str(r[3]) for r in trade_rows if r and r[3] is not None})
            taker_balances: Dict[str, Any] = {}
            for tid in taker_ids:
                bal = con.execute(
                    "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                    (tid,),
                ).fetchone()
                taker_balances[tid] = {
                    "credits": int(bal[0]) if bal else None,
                    "locked_credits": int(bal[1]) if bal else None,
                }

            trades: List[Dict[str, Any]] = []
            for r in trade_rows:
                (trade_id, t_created_at, t_maker, t_taker, t_side, t_currency,
                 t_credits_amount, t_pay_to_address, t_expected_sats, t_txid, t_confs,
                 t_expires_at, t_state, t_settled_at) = r

                trades.append({
                    "trade_id": int(trade_id),
                    "created_at": int(t_created_at),
                    "maker_account_id": str(t_maker),
                    "taker_account_id": str(t_taker),
                    "side": str(t_side),
                    "currency": str(t_currency),
                    "credits_amount": int(t_credits_amount),
                    "pay_to_address": str(t_pay_to_address),
                    "expected_sats": int(t_expected_sats),
                    "txid": str(t_txid) if t_txid is not None else None,
                    "confs": int(t_confs),
                    "expires_at": int(t_expires_at),
                    "state": str(t_state),
                    "settled_at": int(t_settled_at) if t_settled_at is not None else None,
                })

            return {
                "ok": True,
                "order": {
                    "order_id": int(oid),
                    "created_at": int(created_at),
                    "maker_account_id": str(maker),
                    "side": str(side),
                    "currency": str(currency),
                    "credits_amount": int(credits_amount),
                    "price_sat_per_credit": int(price_sat_per_credit),
                    "pay_to_address": str(pay_to_address),
                    "status": str(status),
                },
                "maker_balance": {"credits": maker_credits, "locked_credits": maker_locked},
                "taker_balances": taker_balances,
                "trades": trades,
                "trade_count": len(trades),
            }
        finally:
            con.close()

    @router.post("/trades/{trade_id}/confirm")
    async def admin_dex_confirm_trade(trade_id: int, req: Request):
        """Phase 1: confirm payment manually.

        Sets trade.state = CONFIRMED and stores txid (once).
        Does NOT move credits. This is safe to do before RPC/watcher checks.
        """
        require_admin_func(req)

        try:
            body = await req.json()
        except Exception:
            body = {}

        txid = ""
        if isinstance(body, dict):
            txid = str(body.get("txid") or "").strip()
        if not txid:
            raise HTTPException(status_code=400, detail="missing txid")

        con = db_func()
        try:
            now = int(now_unix_func())
            con.execute("BEGIN IMMEDIATE;")

            row = con.execute(
                """
                SELECT id, order_id, state, expires_at, currency, txid
                FROM dex_trades
                WHERE id=?
                """,
                (int(trade_id),),
            ).fetchone()

            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown trade")

            tid, order_id, state, expires_at, currency, txid_db = row
            state = str(state)
            expires_at = int(expires_at)
            currency = str(currency).strip().upper()

            # Don’t allow confirming expired trades
            if state == "WAIT_PAYMENT" and expires_at <= now:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="trade expired; run /dex/trades/{id}/expire")

            # Idempotency rules
            if state == "SETTLED":
                # If already settled, only accept the same txid (defensive; prevents operator mistakes)
                pinned = str(txid_db or "").strip()
                if pinned and pinned != txid:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=409, detail="txid mismatch vs settled trade")
                con.execute("COMMIT;")
                return {"ok": True, "trade_id": int(tid), "state": "SETTLED", "txid": pinned or txid, "detail": "already settled"}

            if state == "EXPIRED":
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="trade is expired")

            if state == "CONFIRMED":
                # txid must match if already confirmed
                if txid_db is not None and str(txid_db).strip() and str(txid_db).strip() != txid:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=409, detail="trade already confirmed with different txid")
                con.execute("COMMIT;")
                return {"ok": True, "trade_id": int(tid), "state": "CONFIRMED", "txid": txid, "detail": "already confirmed"}

            if state != "WAIT_PAYMENT":
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail=f"trade not confirmable (state={state})")

            # If txid already set, don't allow changing it (safety)
            if txid_db is not None and str(txid_db).strip() and str(txid_db).strip() != txid:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="txid already set to a different value")

            try:
                # Store txid and mark confirmed
                con.execute(
                    "UPDATE dex_trades SET txid=?, confs=0, state='CONFIRMED' WHERE id=? AND state='WAIT_PAYMENT'",
                    (txid, int(trade_id)),
                )
            except sqlite3.IntegrityError:
                # Unique index (currency, txid) should cause this
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="txid already used for another trade (same currency)")

            con.execute("COMMIT;")
            return {"ok": True, "trade_id": int(tid), "state": "CONFIRMED", "order_id": int(order_id), "txid": txid, "currency": currency}

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

    def _settle_trade_in_tx(con: sqlite3.Connection, trade_id_i: int, txid: str) -> Dict[str, Any]:
        """Internal helper: assumes BEGIN IMMEDIATE already started."""
        ts = int(now_unix_func())

        row = con.execute(
            """
            SELECT id, order_id, state, side, maker_account_id, taker_account_id,
                   credits_amount, txid, expires_at
            FROM dex_trades
            WHERE id=?
            """,
            (int(trade_id_i),),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="unknown trade")

        tid, order_id, state, side, maker, taker, credits_amount, txid_db, expires_at = row
        state = str(state)
        side = str(side).strip().upper()
        maker = str(maker)
        taker = str(taker)
        credits_amount = int(credits_amount)
        expires_at = int(expires_at)

        # Idempotent settle
        if state == "SETTLED":
            pinned = str(txid_db or "").strip()
            if pinned and pinned != txid:
                raise HTTPException(status_code=409, detail="txid mismatch vs settled trade")
            return {"ok": True, "trade_id": int(tid), "state": "SETTLED", "txid": pinned or txid, "detail": "already settled"}

        if state == "EXPIRED":
            raise HTTPException(status_code=409, detail="trade is expired")

        # Recommended: only settle if CONFIRMED (watcher/admin already pinned txid)
        if state not in ("CONFIRMED",):
            raise HTTPException(status_code=409, detail=f"trade not in CONFIRMED (state={state})")

        # Require txid matches pinned value (or pin it if empty)
        pinned = str(txid_db or "").strip()
        if pinned and pinned != txid:
            raise HTTPException(status_code=409, detail="txid mismatch vs confirmed trade")
        if not pinned:
            # pin it now (rare; typically confirm pinned it already)
            try:
                con.execute("UPDATE dex_trades SET txid=?, confs=0 WHERE id=?", (txid, int(trade_id_i)))
            except sqlite3.IntegrityError:
                raise HTTPException(status_code=409, detail="txid already used for another trade (same currency)")

        # NOTE: `expires_at` is the payment window for WAIT_PAYMENT only.
        # Once a trade is CONFIRMED (txid pinned), we allow settlement even if
        # `expires_at` has passed, because on-chain confirmations may take longer
        # than the initial payment window.

        # Transfer escrowed credits:
        # - SELL_CREDITS: maker escrowed at order creation -> taker receives
        # - BUY_CREDITS:  taker escrowed at take-time -> maker receives
        if side == "SELL_CREDITS":
            transfer_locked_credits_atomic_func(con, maker, taker, credits_amount)
        elif side == "BUY_CREDITS":
            transfer_locked_credits_atomic_func(con, taker, maker, credits_amount)
        else:
            raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

        # Update trade + order
        con.execute(
            "UPDATE dex_trades SET state='SETTLED', settled_at=? WHERE id=?",
            (ts, int(trade_id_i)),
        )
        con.execute(
            "UPDATE dex_orders SET status='FILLED' WHERE id=?",
            (int(order_id),),
        )

        return {"ok": True, "trade_id": int(tid), "state": "SETTLED", "order_id": int(order_id), "txid": txid}

    @router.post("/trades/{trade_id}/settle")
    async def admin_dex_settle_trade(trade_id: int, req: Request):
        """Phase 2: finalize/settle after watcher RPC verified payment."""
        require_admin_func(req)

        try:
            body = await req.json()
        except Exception:
            body = {}

        txid = ""
        if isinstance(body, dict):
            txid = str(body.get("txid") or "").strip()
        if not txid:
            raise HTTPException(status_code=400, detail="missing txid")

        con = db_func()
        try:
            con.execute("BEGIN IMMEDIATE;")
            out = _settle_trade_in_tx(con, int(trade_id), txid)
            con.execute("COMMIT;")
            return out
        except HTTPException:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        except Exception:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            con.close()

    @router.post("/trades/{trade_id}/confs")
    async def admin_dex_update_trade_confs(trade_id: int, req: Request):
        """Update confirmations counter for a trade.

        This is meant to be called by the on-chain watcher so the frontend can show
        progress (confs / required) while the trade is in CONFIRMED.

        Safety rules:
          - Admin-only.
          - If a txid is already pinned in the DB, an optional provided txid must match.
          - Only updates trades that are not EXPIRED.
        """
        require_admin_func(req)

        try:
            body = await req.json()
        except Exception:
            body = {}

        confs_in: Optional[int] = None
        txid_in: str = ""
        if isinstance(body, dict):
            if body.get("confs") is not None:
                try:
                    confs_in = int(body.get("confs"))
                except Exception:
                    confs_in = None
            txid_in = str(body.get("txid") or "").strip()

        if confs_in is None:
            raise HTTPException(status_code=400, detail="missing confs")
        if confs_in < 0:
            confs_in = 0

        con = db_func()
        try:
            con.execute("BEGIN IMMEDIATE;")

            row = con.execute(
                """
                SELECT id, state, txid, confs
                FROM dex_trades
                WHERE id=?
                """,
                (int(trade_id),),
            ).fetchone()

            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown trade")

            tid, state, txid_db, confs_db = row
            state = str(state)
            pinned = str(txid_db or "").strip()
            confs_db_i = int(confs_db or 0)

            if state == "EXPIRED":
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="trade is expired")

            # If DB already has a pinned txid, the provided txid (if any) must match.
            if pinned and txid_in and txid_in != pinned:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=409, detail="txid mismatch vs trade")

            # If caller provides a txid and DB has none yet, allow pinning it here.
            # (Normally /confirm pins it first; this is just defensive.)
            if txid_in and not pinned:
                try:
                    con.execute(
                        "UPDATE dex_trades SET txid=?, confs=? WHERE id=?",
                        (txid_in, int(confs_in), int(trade_id)),
                    )
                except sqlite3.IntegrityError:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=409, detail="txid already used for another trade (same currency)")
                con.execute("COMMIT;")
                return {"ok": True, "trade_id": int(tid), "state": state, "txid": txid_in, "confs": int(confs_in), "detail": "txid pinned and confs updated"}

            # Otherwise only update confs.
            if int(confs_in) != confs_db_i:
                con.execute(
                    "UPDATE dex_trades SET confs=? WHERE id=?",
                    (int(confs_in), int(trade_id)),
                )

            con.execute("COMMIT;")
            return {"ok": True, "trade_id": int(tid), "state": state, "txid": pinned or None, "confs": int(confs_in)}

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

    @router.post("/trades/{trade_id}/expire")
    def admin_dex_expire_trade(trade_id: int, req: Request):
        """Admin: expire a trade if it is due, and unlock escrowed credits as needed.

        This is intended for the on-chain watcher (using X-Admin-Token) or operators.
        It only expires trades whose `expires_at` is in the past, and only when the
        trade is still in `WAIT_PAYMENT`.

        Rules:
          - SELL_CREDITS: maker escrow is kept (order is re-opened).
          - BUY_CREDITS: taker escrow is unlocked (order is re-opened).

        Idempotent: calling it multiple times is safe.
        """
        require_admin_func(req)

        con = db_func()
        try:
            now = int(now_unix_func())
            con.execute("BEGIN IMMEDIATE;")

            row = con.execute(
                """
                SELECT id, order_id, state, expires_at, side, maker_account_id, taker_account_id, credits_amount
                FROM dex_trades
                WHERE id=?
                """,
                (int(trade_id),),
            ).fetchone()

            if not row:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=404, detail="unknown trade")

            tid, order_id, state, expires_at, side, maker, taker, credits_amount = row
            side = str(side).strip().upper()
            state = str(state)
            expires_at = int(expires_at)
            credits_amount = int(credits_amount)

            # Only expire trades that are still waiting for payment.
            if state != "WAIT_PAYMENT":
                con.execute("ROLLBACK;")
                return {"ok": True, "trade_id": int(tid), "state": state, "detail": "not in WAIT_PAYMENT"}

            if expires_at > now:
                con.execute("ROLLBACK;")
                return {
                    "ok": True,
                    "trade_id": int(tid),
                    "state": state,
                    "detail": "not expired yet",
                    "expires_at": int(expires_at),
                    "now": int(now),
                }

            # Mark trade expired (idempotent under this transaction)
            cur = con.execute(
                "UPDATE dex_trades SET state='EXPIRED' WHERE id=? AND state='WAIT_PAYMENT'",
                (int(trade_id),),
            )
            if cur.rowcount != 1:
                con.execute("ROLLBACK;")
                return {"ok": True, "trade_id": int(tid), "state": state, "detail": "already updated"}

            # Re-open the order so it can be taken again
            con.execute(
                "UPDATE dex_orders SET status='OPEN' WHERE id=? AND status='TAKEN'",
                (int(order_id),),
            )

            # Unlock escrow depending on side
            if side == "BUY_CREDITS":
                # Taker had locked credits at take-time
                transfer_locked_credits_atomic_func  # keep linter happy in some environments
                # unlock uses the provided atomic funcs from create_dex_router, so here we must do it manually:
                # (Admin router doesn't have direct access to lock/unlock helpers; therefore we simply move
                #  credits from locked back to available by reversing the lock via SQL.)
                # However, in this codebase we DO have `accounts.locked_credits` column and use atomic helpers
                # in the public router. For admin expire we mirror that logic in SQL safely in this transaction.
                bal = con.execute(
                    "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                    (str(taker),),
                ).fetchone()
                if not bal:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=500, detail="unknown taker account")
                credits_i = int(bal[0])
                locked_i = int(bal[1])
                if locked_i < credits_amount:
                    con.execute("ROLLBACK;")
                    raise HTTPException(status_code=500, detail="ledger error: taker locked_credits too small")
                con.execute(
                    "UPDATE accounts SET credits=?, locked_credits=? WHERE account_id=?",
                    (credits_i + credits_amount, locked_i - credits_amount, str(taker)),
                )
            elif side == "SELL_CREDITS":
                # Maker escrow remains, because the order is now OPEN again
                pass
            else:
                con.execute("ROLLBACK;")
                raise HTTPException(status_code=400, detail=f"unsupported side: {side}")

            con.execute("COMMIT;")
            return {"ok": True, "trade_id": int(tid), "state": "EXPIRED", "order_id": int(order_id)}

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


    @router.post("/expire_due")
    def admin_dex_expire_due(req: Request, limit: int = 200):
        """Admin: expire all due WAIT_PAYMENT trades.

        This is intended for the watcher/ops. It is safe and idempotent.
        """
        require_admin_func(req)

        try:
            limit_i = int(limit)
        except Exception:
            limit_i = 200
        limit_i = max(1, min(1000, limit_i))

        now = int(now_unix_func())
        con = db_func()
        try:
            con.execute("BEGIN IMMEDIATE;")

            rows = con.execute(
                """
                SELECT id, order_id, side, taker_account_id, credits_amount
                FROM dex_trades
                WHERE state='WAIT_PAYMENT' AND expires_at <= ?
                ORDER BY expires_at ASC
                LIMIT ?
                """,
                (now, limit_i),
            ).fetchall()

            expired: List[int] = []

            for tid, order_id, side, taker, credits_amount in rows:
                side_u = str(side).strip().upper()
                credits_amount_i = int(credits_amount)

                cur = con.execute(
                    "UPDATE dex_trades SET state='EXPIRED' WHERE id=? AND state='WAIT_PAYMENT'",
                    (int(tid),),
                )
                if cur.rowcount != 1:
                    continue

                con.execute(
                    "UPDATE dex_orders SET status='OPEN' WHERE id=? AND status='TAKEN'",
                    (int(order_id),),
                )

                if side_u == "BUY_CREDITS":
                    bal = con.execute(
                        "SELECT credits, locked_credits FROM accounts WHERE account_id=?",
                        (str(taker),),
                    ).fetchone()
                    if not bal:
                        raise HTTPException(status_code=500, detail="unknown taker account")
                    credits_i = int(bal[0])
                    locked_i = int(bal[1])
                    if locked_i < credits_amount_i:
                        raise HTTPException(status_code=500, detail="ledger error: taker locked_credits too small")
                    con.execute(
                        "UPDATE accounts SET credits=?, locked_credits=? WHERE account_id=?",
                        (credits_i + credits_amount_i, locked_i - credits_amount_i, str(taker)),
                    )
                elif side_u == "SELL_CREDITS":
                    pass
                else:
                    raise HTTPException(status_code=400, detail=f"unsupported side: {side_u}")

                expired.append(int(tid))

            con.execute("COMMIT;")
            return {"ok": True, "count": len(expired), "expired": expired}

        except HTTPException:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        except Exception:
            try:
                con.execute("ROLLBACK;")
            except Exception:
                pass
            raise
        finally:
            con.close()

    # Backwards-compatible alias (your old endpoint name)
    @router.post("/trades/{trade_id}/mark_confirmed")
    async def admin_dex_mark_confirmed_alias(trade_id: int, req: Request):
        """Deprecated alias for /settle."""
        return await admin_dex_settle_trade(trade_id, req)

    return router


