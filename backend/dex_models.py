# dex_models.py
from pydantic import BaseModel
from typing import Optional


# Input models
class DexOrderCreateIn(BaseModel):
    side: str = "SELL_CREDITS"     # SELL_CREDITS or BUY_CREDITS
    currency: str
    credits_amount: int
    price_sat_per_credit: int
    pay_to_address: Optional[str] = None


class DexOrderTakeIn(BaseModel):
    # For BUY_CREDITS orders, taker provides where maker should pay on-chain
    taker_pay_to_address: Optional[str] = None


# Output models
class DexOrderOut(BaseModel):
    order_id: int
    created_at: int
    maker_account_id: str
    side: str
    currency: str
    credits_amount: int
    price_sat_per_credit: int
    pay_to_address: str
    status: str


class DexOrderCancelOut(BaseModel):
    ok: bool
    order_id: int
    status: str


class DexTradeOut(BaseModel):
    trade_id: int
    order_id: int
    created_at: int
    maker_account_id: str
    taker_account_id: str
    side: str
    currency: str
    credits_amount: int
    pay_to_address: str
    expected_sats: int
    txid: Optional[str]
    confs: int
    expires_at: int
    state: str