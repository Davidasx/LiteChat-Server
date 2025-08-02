from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(..., description="Unique username chosen by the user")
    public_key: str = Field(..., description="Armored ASCII PGP public key")


class RegisterResponse(BaseModel):
    message: str


class ChallengeRequest(BaseModel):
    username: str


class ChallengeResponse(BaseModel):
    challenge: str


class VerifyRequest(BaseModel):
    username: str
    signature: str  # base64-encoded signature of the issued challenge


class TokenResponse(BaseModel):
    token: str


class SendMessageRequest(BaseModel):
    recipient: str  # recipient username
    encrypted_message: str  # PGP-encrypted ciphertext (armored)
    signature: str  # base64-encoded signature over encrypted_message by sender


class MessageResponse(BaseModel):
    id: int
    sender: str
    encrypted_message: str
    timestamp: datetime


class InboxResponse(BaseModel):
    messages: List[MessageResponse] 