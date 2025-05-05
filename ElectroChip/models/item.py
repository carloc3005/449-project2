from pydantic import BaseModel, Field
from typing import Optional
from bson import ObjectId

# Helper class for MongoDB ObjectId handling in Pydantic
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")

# Pydantic model for creating an inventory item (request body)
class ItemCreate(BaseModel):
    item_name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    quantity: int = Field(..., ge=0) # Quantity cannot be negative
    price: float = Field(..., gt=0) # Price must be positive

# Pydantic model for updating an inventory item (request body - all fields optional)
class ItemUpdate(BaseModel):
    item_name: Optional[str] = Field(None, min_length=1)
    description: Optional[str] = Field(None, min_length=1)
    quantity: Optional[int] = Field(None, ge=0)
    price: Optional[float] = Field(None, gt=0)

# Pydantic model for representing an inventory item in responses
class ItemOut(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id") # Map MongoDB's _id
    item_name: str
    description: str
    quantity: int
    price: float
    owner_username: str # To track which user owns the item

    class Config:
        populate_by_name = True # Allow using alias '_id'
        arbitrary_types_allowed = True # Allow ObjectId
        json_encoders = {ObjectId: str} # Serialize ObjectId to string
