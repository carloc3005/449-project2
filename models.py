from sqlalchemy import Column, Integer, String
from db import Base
from beanie import Document
from pydantic import Field
from typing import Optional
import uuid

# SQLAlchemy User model (MySQL)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)  # "user" or "admin"

# Beanie InventoryItem model (MongoDB)
class InventoryItem(Document):
    item_id: str = Field(default_factory=lambda: str(uuid.uuid4()), unique=True)
    item_name: str
    description: Optional[str] = None
    quantity: int = Field(..., ge=0)
    price: float = Field(..., ge=0.0)
    owner_username: str

    class Settings:
        name = "inventory_items"
        indexes = ["item_id", "owner_username"]