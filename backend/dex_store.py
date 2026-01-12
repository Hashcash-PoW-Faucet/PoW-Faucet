# dex_store.py
import sqlite3
from typing import Any, Dict, List, Optional


def fetch_orders(
    con: sqlite3.Connection,
    status: str = "OPEN",
    currency: Optional[str] = None,
    side: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    status = (status or "OPEN").strip().upper()
    currency = (currency or "").strip().upper() or None
    side = (side or "").strip().upper() or None

    limit = int(limit)
    offset = int(offset)
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    q = """
    SELECT id, created_at, maker_account_id, side, currency, credits_amount,
           price_sat_per_credit, pay_to_address, status
    FROM dex_orders
    WHERE status = ?
    """
    params: List[Any] = [status]

    if currency:
        q += " AND currency = ?"
        params.append(currency)
    if side:
        q += " AND side = ?"
        params.append(side)

    q += " ORDER BY price_sat_per_credit ASC, created_at ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = con.execute(q, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            dict(
                order_id=int(r[0]),
                created_at=int(r[1]),
                maker_account_id=str(r[2]),
                side=str(r[3]),
                currency=str(r[4]),
                credits_amount=int(r[5]),
                price_sat_per_credit=int(r[6]),
                pay_to_address=str(r[7] or ""),
                status=str(r[8]),
            )
        )
    return out


def fetch_orders_by_maker(
    con: sqlite3.Connection,
    maker_account_id: str,
    status: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    maker_account_id = str(maker_account_id)
    status = (status or "").strip().upper() or None

    limit = int(limit)
    offset = int(offset)
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    q = """
    SELECT id, created_at, maker_account_id, side, currency, credits_amount,
           price_sat_per_credit, pay_to_address, status
    FROM dex_orders
    WHERE maker_account_id = ?
    """
    params: List[Any] = [maker_account_id]
    if status:
        q += " AND status = ?"
        params.append(status)

    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = con.execute(q, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            dict(
                order_id=int(r[0]),
                created_at=int(r[1]),
                maker_account_id=str(r[2]),
                side=str(r[3]),
                currency=str(r[4]),
                credits_amount=int(r[5]),
                price_sat_per_credit=int(r[6]),
                pay_to_address=str(r[7] or ""),
                status=str(r[8]),
            )
        )
    return out


def fetch_trades_for_account(
    con: sqlite3.Connection,
    account_id: str,
    state: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    account_id = str(account_id)
    state = (state or "").strip().upper() or None

    limit = int(limit)
    offset = int(offset)
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    if offset < 0:
        offset = 0

    q = """
    SELECT id, order_id, created_at, maker_account_id, taker_account_id, side,
           currency, credits_amount, pay_to_address, expected_sats, txid, confs,
           expires_at, state
    FROM dex_trades
    WHERE (maker_account_id = ? OR taker_account_id = ?)
    """
    params: List[Any] = [account_id, account_id]
    if state:
        q += " AND state = ?"
        params.append(state)

    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = con.execute(q, tuple(params)).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append(
            dict(
                trade_id=int(r[0]),
                order_id=int(r[1]),
                created_at=int(r[2]),
                maker_account_id=str(r[3]),
                taker_account_id=str(r[4]),
                side=str(r[5]),
                currency=str(r[6]),
                credits_amount=int(r[7]),
                pay_to_address=str(r[8] or ""),
                expected_sats=int(r[9]),
                txid=str(r[10]) if r[10] is not None else None,
                confs=int(r[11]),
                expires_at=int(r[12]),
                state=str(r[13]),
            )
        )
    return out