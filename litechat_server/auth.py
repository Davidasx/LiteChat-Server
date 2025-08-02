import os
import secrets
from base64 import b64decode
from datetime import datetime, timedelta
from typing import Dict

import jwt
from fastapi import HTTPException, status
from pgpy import PGPKey, PGPMessage, PGPSignature
from sqlalchemy.orm import Session

from .models import User

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 60

# In-memory map of username → issued challenge (expires after single use)
_challenges: Dict[str, str] = {}


def create_challenge(username: str) -> str:
    """Generate and remember a random challenge string for the given username."""
    challenge = secrets.token_hex(32)
    _challenges[username] = challenge
    return challenge


def _pop_challenge(username: str) -> str | None:
    """Pop and return the stored challenge for a user, if any."""
    return _challenges.pop(username, None)


def _load_pubkey(armored_key: str) -> PGPKey:
    key, _ = PGPKey.from_blob(armored_key)
    return key


def verify_challenge_signature(username: str, signature_b64: str, db: Session) -> bool:
    """Verify that *signature_b64* is a valid signature of the issued challenge for *username*."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    challenge = _pop_challenge(username)
    if not challenge:
        return False  # No outstanding challenge or already used

    try:
        pubkey = _load_pubkey(user.public_key)
        signature_bytes = b64decode(signature_b64)
        signature = PGPSignature.from_blob(signature_bytes)
        # Verify detached signature over the raw challenge string (not wrapped in PGPMessage)
        return pubkey.verify(challenge, signature)
    except Exception:
        return False


def verify_message_signature(pub_key_str: str, ciphertext: str, signature_b64: str) -> bool:
    """Validate that *signature_b64* is a valid detached signature over *ciphertext* given *pub_key_str*."""
    try:
        pubkey = _load_pubkey(pub_key_str)
        signature = PGPSignature.from_blob(b64decode(signature_b64))
        return pubkey.verify(ciphertext, signature)
    except Exception:
        return False


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 