from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from . import auth, database, models, schemas, utils

# Create database tables on startup
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="LiteChat API", version="0.1.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/verify")


# --------------------------- Health Check ---------------------------


@app.get("/health")
def health_check():
    """Simple health check endpoint for connectivity testing."""
    return {"status": "healthy", "service": "LiteChat API"}


# Dependency that extracts the current user from the Authorization header

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db),
) -> models.User:
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# --------------------------- User registration ---------------------------


@app.post("/users/register", response_model=schemas.RegisterResponse)
def register_user(req: schemas.RegisterRequest, db: Session = Depends(database.get_db)):
    if db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    fingerprint = utils.get_fingerprint(req.public_key)
    if db.query(models.User).filter(models.User.fingerprint == fingerprint).first():
        raise HTTPException(status_code=400, detail="Public key already registered")

    user = models.User(username=req.username, public_key=req.public_key, fingerprint=fingerprint)
    db.add(user)
    db.commit()
    return {"message": "Registered successfully"}


# --------------------------- Authentication ---------------------------


@app.post("/auth/challenge", response_model=schemas.ChallengeResponse)
def get_challenge(req: schemas.ChallengeRequest, db: Session = Depends(database.get_db)):
    if not db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=404, detail="User not found")
    challenge = auth.create_challenge(req.username)
    return {"challenge": challenge}


@app.post("/auth/verify", response_model=schemas.TokenResponse)
def verify_signature(req: schemas.VerifyRequest, db: Session = Depends(database.get_db)):
    if not auth.verify_challenge_signature(req.username, req.signature, db):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signature verification failed")
    token = auth.create_access_token({"sub": req.username})
    return {"token": token}


# --------------------------- Messaging ---------------------------


@app.post("/messages/send", status_code=201)
def send_message(
    req: schemas.SendMessageRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    recipient = db.query(models.User).filter(models.User.username == req.recipient).first()
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient not found")

    # Anti-spoofing: verify that the sender holds the private key by validating signature over ciphertext
    if not auth.verify_message_signature(current_user.public_key, req.encrypted_message, req.signature):
        raise HTTPException(status_code=401, detail="Invalid message signature")

    message = models.Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        encrypted_message=req.encrypted_message,
        signature=req.signature,
    )
    db.add(message)
    db.commit()
    return {"message": "Message stored"}


@app.get("/messages/inbox", response_model=schemas.InboxResponse)
def read_inbox(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    messages = (
        db.query(models.Message)
        .filter(models.Message.recipient_id == current_user.id)
        .order_by(models.Message.timestamp.desc())
        .all()
    )

    def _build(msg: models.Message) -> schemas.MessageResponse:
        sender_username = (
            db.query(models.User).filter(models.User.id == msg.sender_id).first().username
        )
        return schemas.MessageResponse(
            id=msg.id,
            sender=sender_username,
            encrypted_message=msg.encrypted_message,
            timestamp=msg.timestamp,
        )

    return {"messages": [_build(m) for m in messages]}


# --------------------------- User lookup ---------------------------


@app.get("/users/search")
def search_user(
    username: Optional[str] = None,
    fingerprint: Optional[str] = None,
    db: Session = Depends(database.get_db),
):
    if not username and not fingerprint:
        raise HTTPException(status_code=400, detail="username or fingerprint query parameter required")

    query = db.query(models.User)
    if username:
        user = query.filter(models.User.username == username).first()
    else:
        user = query.filter(models.User.fingerprint == fingerprint).first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user.username,
        "fingerprint": user.fingerprint,
        "public_key": user.public_key,
    } 