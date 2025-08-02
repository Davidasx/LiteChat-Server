# LiteChat Server

LiteChat is an open-source, end-to-end encrypted chatroom service using OpenPGP for key management and message authentication. This repository contains the server-side implementation built with FastAPI.

## Features

* 🔑 Public-key registration and unique usernames
* 🔐 Challenge-response authentication without ever transmitting private keys
* 📦 JWT-secured API endpoints
* ✉️ Message storage in encrypted form only; signatures prevent spoofing
* 💡 Simple SQLite storage by default (configurable via `DATABASE_URL`)

## Quickstart

```bash
# Install dependencies (preferably inside a virtualenv)
pip install -r requirements.txt

# Run the API
uvicorn litechat_server.main:app --reload
```

API documentation will be available at `http://localhost:8000/docs`.

## Security Notice

* The server never stores or receives private keys.
* All authentication is done via OpenPGP signatures.
* Messages are end-to-end encrypted on the client and remain opaque to the server.

## License

MIT 