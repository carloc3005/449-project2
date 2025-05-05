from sqlalchemy.orm import Session
from .. import models, security

# --- User CRUD Operations (MySQL) ---

def get_user(db: Session, user_id: int):
    return db.query(models.user.User).filter(models.user.User.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.user.User).filter(models.user.User.email == email).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.user.User).filter(models.user.User.username == username).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.user.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: models.user.UserCreate):
    hashed_password = security.auth.get_password_hash(user.password)
    db_user = models.user.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# --- Inventory CRUD Operations (MongoDB) ---
from .database import inventory_collection
from ..models.item import ItemCreate, ItemUpdate, ItemOut, PyObjectId
from bson import ObjectId
from typing import List, Optional

async def create_inventory_item(item_data: ItemCreate, owner_username: str) -> ItemOut:
    """Creates a new inventory item in MongoDB."""
    item_dict = item_data.model_dump()
    item_dict["owner_username"] = owner_username # Add owner information
    result = await inventory_collection.insert_one(item_dict)
    created_item = await inventory_collection.find_one({"_id": result.inserted_id})
    if created_item:
        return ItemOut(**created_item)
    raise Exception("Failed to create item") # Should not happen if insert succeeded

async def get_inventory_items_by_owner(owner_username: str) -> List[ItemOut]:
    """Retrieves all inventory items for a specific owner."""
    items = []
    cursor = inventory_collection.find({"owner_username": owner_username})
    async for item in cursor:
        items.append(ItemOut(**item))
    return items

async def get_all_inventory_items() -> List[ItemOut]:
    """Retrieves all inventory items (for admin)."""
    items = []
    cursor = inventory_collection.find({})
    async for item in cursor:
        items.append(ItemOut(**item))
    return items

async def get_inventory_item_by_id(item_id: str) -> Optional[ItemOut]:
    """Retrieves a single inventory item by its MongoDB ObjectId."""
    try:
        object_id = ObjectId(item_id)
        item = await inventory_collection.find_one({"_id": object_id})
        if item:
            return ItemOut(**item)
        return None
    except Exception: # Handles invalid ObjectId format
        return None

async def update_inventory_item(item_id: str, item_update: ItemUpdate) -> Optional[ItemOut]:
    """Updates an existing inventory item."""
    try:
        object_id = ObjectId(item_id)
        # Create update dict excluding unset fields
        update_data = {k: v for k, v in item_update.model_dump().items() if v is not None}

        if not update_data:
            # If no fields to update, just return the existing item
            return await get_inventory_item_by_id(item_id)

        result = await inventory_collection.update_one(
            {"_id": object_id},
            {"$set": update_data}
        )
        if result.modified_count == 1:
            updated_item = await inventory_collection.find_one({"_id": object_id})
            if updated_item:
                return ItemOut(**updated_item)
        # Handle case where item exists but wasn't modified (e.g., data is the same)
        # or item doesn't exist (find_one will return None)
        existing_item = await inventory_collection.find_one({"_id": object_id})
        if existing_item:
             return ItemOut(**existing_item) # Return existing if no change or update failed unexpectedly
        return None # Item not found
    except Exception:
        return None


async def delete_inventory_item(item_id: str) -> bool:
    """Deletes an inventory item by its ID."""
    try:
        object_id = ObjectId(item_id)
        result = await inventory_collection.delete_one({"_id": object_id})
        return result.deleted_count == 1
    except Exception:
        return False
