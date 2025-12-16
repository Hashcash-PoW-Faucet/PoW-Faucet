# Hashcash PoW Faucet

A small **Hashcash-style Proof-of-Work faucet demo** inspired by early cypherpunk ideas.  
Users create anonymous accounts, solve PoW challenges in their browser (or via a CLI miner),  
earn non-monetary “credits” and can optionally burn credits to request *discretionary* crypto tips.

> ⚠️ **Important:** Credits in this project are **play points only**.  
> They have no monetary value, no fixed or implied exchange rate, and no payout guarantee.

---

## High-level overview

- **Hashcash-style PoW**  
  Every signup and claim uses a stateless PoW challenge (similar in spirit to Adam Back’s Hashcash).

- **Anonymous “crypto-inspired” accounts**  
  The client generates a random secret token (“private key” in the UI).  
  This is stored **only in the browser** and sent as a bearer token to the backend.  
  The server derives an address from this secret and stores **only** the address and balances, not the secret itself.

- **Credits instead of coins**  
  Users solve PoW challenges to earn **credits**.  
  Credits:
  - live in a simple SQLite database (`faucet.db`),
  - can be transferred to other addresses (no fees),
  - are rate-limited by a daily earn cap and cooldown.

- **Optional redeem / tip mechanism**  
  Users may burn credits to request a potential crypto tip to an external wallet address.  
  The backend:
  - validates addresses via coin-specific RPC,
  - logs the request,
  - optionally sends a small on-chain tip from the faucet’s own funds (if configured).  
  There is **no promise** of payout, minimum or maximum amount, or fixed odds.

- **Public redeem log**  
  A JSONL-based audit log can be exposed as a “recent redeems” list, similar to classic faucets.

- **Retro browser UI**  
  A single-page `index.html` + `styles.css` frontend with a Windows-9x-ish look, PoW status, hashrate display, cooldown countdown, and account tools.

- **Optional CLI miner**  
  A separate Go-based CLI miner can talk to the same HTTP API and run multi-threaded PoW on a server or desktop (see `README_miner.md`).

---

## Repository layout (suggested)

```text
PoW-Faucet/
  backend/
    app.py
    pow_utils.py
    coins.json
    requirements.txt
    .env.example
  frontend/
    index.html
    styles.css
    AB.png          
  README.md         
```

You can also keep `index.html`, `styles.css` and `app.py` in a single folder for local testing.  
In production it’s cleaner to separate **backend** and **frontend** and use a reverse proxy.

---

## Backend

### Requirements

- Python 3.8+
- Recommended packages (see `requirements.txt` in the repo):
  - `fastapi`
  - `uvicorn[standard]`
  - `gunicorn`
  - `httpx`
  - `python-dotenv` (optional but convenient)
  - `uvicorn` is used as the ASGI server, optionally via `gunicorn`.

### Environment configuration (`.env`)

Create a `.env` file next to `app.py` (or in `backend/`) with at least:

```env
# Random secrets (use long random strings; do NOT reuse anywhere else)
STAMP_HMAC_KEY=replace_with_long_random_hex_or_base64
IPTAG_HMAC_KEY=replace_with_long_random_hex_or_base64

# PoW difficulty (bits)
CLAIM_BITS=24
SIGNUP_BITS=26

# Stamp TTL and cooldown
STAMP_TTL_SEC=7200        # how long a challenge stamp is valid (seconds)
COOLDOWN_SEC=120          # cooldown after each successful claim

# Daily earning limits
DAILY_EARN_CAP=50         # max credits per address per day

# Redeem settings
MIN_REDEEM_CREDITS=50     # minimum balance required before you can redeem
REDEEM_COST_CREDITS=10    # credits burned per redeem request

# Signup caps per IP (demo anti-abuse rule)
SIGNUP_CAP_PER_IP=2

# Paths
FAUCET_DB=faucet.db
COINS_JSON=coins.json
REDEEM_QUEUE_PATH=redeem_queue.jsonl
```

Adjust values as you like. The backend reads these variables at startup.

### Coin configuration (`coins.json`)

Example `coins.json`:

```json
{
  "BTC": {
    "name": "Bitcoin",
    "short": "BTC",
    "homepage": "https://bitcoin.org",
    "rpc_url": "http://192.168.178.1:8332/",
    "rpc_user": "BTC_user",
    "rpc_password": "BTC_pw",
    "address_validate_method": "validateaddress",
    "min_tip": "0",
    "max_tip": "0.000001"
  },
  "LTC": {
    "name": "Litecoin",
    "short": "LTC",
    "homepage": "https://vecocoin.com/",
    "rpc_url": "http://192.168.178.3:9332/",
    "rpc_user": "LTC_user",
    "rpc_password": "LTC_pw",
    "address_validate_method": "validateaddress",
    "min_tip": "0.00001",
    "max_tip": "0.0001"
  }
}
```

- `min_tip` / `max_tip` are string amounts in the coin’s native units.  
- The backend randomly chooses a tip size in that range (if funds and RPC conditions allow).  
- If a coin has no valid RPC config or funds, a redeem request still burns credits and is logged,
  but **no tip** is sent.

The backend exposes coin meta-data to the frontend through the `/config` endpoint, so the UI  
can show the list of supported coins automatically.

---

## Running locally (development)

1. **Create and activate a virtualenv**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. **Create `.env` and `coins.json`**

Copy `.env.example` to `.env` and edit, or create your own as described above.  
Create `coins.json` if you want the redeem mechanism to talk to actual coin daemons.

3. **Start the backend with uvicorn**

```bash
uvicorn app:app --reload
```

This serves the API at `http://127.0.0.1:8000`.

4. **Serve the frontend**

The simplest way is to serve `frontend/` as static files:

```bash
cd frontend
python3 -m http.server 8080
```

Now open `http://127.0.0.1:8080` in your browser.

Inside `index.html` you may need to switch the API base:

```js
// const BASE_URL = "http://127.0.0.1:8000"; // backend FastAPI URL
const BASE_URL = "/api"; // production behind reverse proxy
```

For local dev, uncomment the `http://127.0.0.1:8000` line and comment out `/api`.

---

## Running in production

A typical production setup:

1. **Backend via gunicorn + uvicorn worker**

From the `backend/` directory:

```bash
source venv/bin/activate
gunicorn \
  -k uvicorn.workers.UvicornWorker \
  -w 1 \
  -b 127.0.0.1:8000 \
  app:app
```

You can wrap this in a systemd unit, e.g.:

```ini
[Unit]
Description=PoW Faucet FastAPI (Gunicorn)
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/pow_faucet/backend
Environment="PATH=/opt/pow_faucet/backend/venv/bin"
ExecStart=/opt/pow_faucet/backend/venv/bin/gunicorn \
    -k uvicorn.workers.UvicornWorker \
    -w 1 \
    -b 127.0.0.1:8000 \
    app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

2. **Reverse proxy + TLS (example: Caddy)**

Example `Caddyfile`:

```caddyfile
hashcash-pow-faucet.example.net {
    root * /var/www/pow_faucet/frontend
    file_server

    handle_path /api/* {
        reverse_proxy 127.0.0.1:8000
    }
}
```

Caddy automatically obtains a Let’s Encrypt certificate and serves HTTPS.  
The frontend then uses `BASE_URL = "/api"` so all API calls go through the proxy.

(You can use Nginx or any other reverse proxy instead; the idea is the same.)

---

## API overview (simplified)

All authenticated endpoints expect:

```http
Authorization: Bearer <private_key>
```

**Main endpoints:**

- `GET /config`  
  Returns difficulty, TTL, cooldown, daily caps and supported coins.

- `GET /signup_status`  
  Returns whether a new signup is allowed from this IP today and how many remain.

- `POST /signup_pow`  
  Verifies a signup PoW solution and, if successful and allowed, creates a new account.  
  Returns a new private key (for the client) and derived address (on the server).

- `GET /me`  
  Returns account state for the current private key:
  - `account_id` (address),
  - `credits`,
  - `earned_today`,
  - `daily_earn_cap`,
  - `cooldown_until`,
  - `server_time`, etc.

- `POST /challenge`  
  Returns a PoW challenge `{ stamp, bits, sig }` for a specific action, e.g. `earn_credit`.

- `POST /submit_pow`  
  Accepts `{ stamp, sig, nonce }` and, if valid and not expired and not exceeding limits,
  awards 1 credit and sets a cooldown.

- `POST /transfer`  
  Simple internal credit transfer between addresses.

- `POST /redeem_request`  
  Burns credits and records a redeem request.  
  Optionally attempts to send an on-chain tip via coin RPC immediately, and returns any `tip_amount` + `txid`.

- `GET /redeem_log`  
  Returns the last N redeem events, either globally (public faucet log) or per-account.

---

## Privacy & legal notes (non-lawyer summary)

- No email, username or personal data is collected.  
  The server only sees:
  - a random secret (bearer token) and its derived address,
  - IP hashes for signup caps,
  - credits and redeem logs.
- Credits are **not a currency**, not a stablecoin, not a token on a public chain.
- Redeem requests **do not** create any contractual right to receive cryptocurrency.  
  Any tip is discretionary, best-effort and can be changed or stopped at any time.
- There is **no advertised probability**, minimum or maximum payout.

If you adapt this project, make sure to:
- add your own clear disclaimer text,
- comply with your local regulations,
- and review the redeem / payout mechanism carefully.

---

## Companion CLI miner

There is an optional [Go-based CLI miner](https://github.com/Hashcash-PoW-Faucet/faucet-cpu-miner). It uses the same public HTTP API to claim credits but can  
run on a server with multiple worker threads.
