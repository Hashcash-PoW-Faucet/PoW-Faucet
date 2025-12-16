# pow_utils.py
import hashlib
import time
from typing import Tuple


def leading_zero_bits(digest: bytes) -> int:
    """Count leading zero bits in a hash digest."""
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
        else:
            for i in range(7, -1, -1):
                if (byte >> i) & 1 == 0:
                    bits += 1
                else:
                    return bits
            return bits
    return bits


def pow_hash(message: str, nonce: str) -> bytes:
    """Compute SHA256(message + '|' + nonce)."""
    return hashlib.sha256((message + "|" + nonce).encode()).digest()


def pow_ok(message: str, nonce: str, bits: int) -> bool:
    """Verify that SHA256(message|'|'|nonce) has >= bits leading zero bits."""
    digest = pow_hash(message, nonce)
    return leading_zero_bits(digest) >= bits


def solve_pow(
    message: str,
    bits: int,
    nonce_start: int = 0,
    report_every: int = 250_000,
    verbose: bool = True,
) -> Tuple[str, int]:
    """
    Find nonce (as decimal string) such that SHA256(message + '|' + nonce)
    has >= bits leading zero bits. Returns (nonce_str, tries).
    """
    msg_prefix = (message + "|").encode()
    nonce = nonce_start
    tries = 0
    t0 = time.time()

    while True:
        n_str = str(nonce).encode()
        digest = hashlib.sha256(msg_prefix + n_str).digest()
        tries += 1

        if leading_zero_bits(digest) >= bits:
            if verbose:
                dt = time.time() - t0
                rate = tries / dt if dt > 0 else 0
                print(
                    f"[pow] solved bits={bits} nonce={nonce} "
                    f"tries={tries} time={dt:.2f}s rate={rate:,.0f}/s"
                )
            return str(nonce), tries

        nonce += 1
        if verbose and report_every and (tries % report_every == 0):
            dt = time.time() - t0
            rate = tries / dt if dt > 0 else 0
            print(f"[pow] tries={tries} rate={rate:,.0f}/s (bits={bits})")