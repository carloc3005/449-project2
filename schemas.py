from pydantic import BaseModel, EmailStr, Field
from typing import Optional

# User schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str

    class Config:
        orm_mode = True

# Inventory schemas
class InventoryItemBase(BaseModel):
    item_name: str
    description: Optional[str] = None
    quantity: int = Field(..., gt=0,)
    price: float = Field(..., ge=0.0)

class InventoryItemCreate(InventoryItemBase):
    pass

class InventoryItemUpdate(BaseModel):
    item_name: Optional[str] = None
    description: Optional[str] = None
    quantity: Optional[int] = Field(None, gt=0)
    price: Optional[float] = Field(None, ge=0.0)

class InventoryItemOut(InventoryItemBase):
    item_id: str
    owner_username: str

class SQLInventoryItemOut(InventoryItemBase):
    item_id: int
    owner_username: str
    
    class Config:
        orm_mode = True