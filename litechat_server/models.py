from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String, unique=True, nullable=False, index=True)

    messages_sent = relationship(
        "Message",
        back_populates="sender",
        foreign_keys="Message.sender_id",
        cascade="all, delete-orphan",
    )
    messages_received = relationship(
        "Message",
        back_populates="recipient",
        foreign_keys="Message.recipient_id",
        cascade="all, delete-orphan",
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    encrypted_message = Column(Text, nullable=False)
    signature = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    sender = relationship("User", back_populates="messages_sent", foreign_keys=[sender_id])
    recipient = relationship("User", back_populates="messages_received", foreign_keys=[recipient_id]) 