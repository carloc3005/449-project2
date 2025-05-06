from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Cookie
from sqlalchemy.orm import Session
from db import get_mysql_db, init_mongo, Base, init_mysql # Import init_mysql and Base
from models import User, InventoryItem, SQLInventoryItem
from schemas import (
    UserCreate, UserLogin, UserOut,
    InventoryItemCreate, InventoryItemUpdate, InventoryItemOut, SQLInventoryItemOut
)
from auth import (
    get_password_hash, verify_password,
    set_session, clear_session, get_session_data, SESSION_COOKIE_NAME
)
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from typing import List, Optional
import os
from pydantic import BaseSettings

app = FastAPI()

# JWT config
class Settings(BaseSettings):
    authjwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "supersecret")

@AuthJWT.load_config
def get_config():
    return Settings()

@app.on_event("startup")
async def on_startup():
    mysql_engine = init_mysql() # Initialize MySQL connection here and get the engine
    await init_mongo()
    Base.metadata.create_all(bind=mysql_engine) # Use the returned engine

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc: AuthJWTException):
    raise HTTPException(status_code=exc.status_code, detail=exc.message)

# ------------------- User Registration & Login (Session/Cookie) -------------------

@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_mysql_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login(user: UserLogin, response: Response, db: Session = Depends(get_mysql_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # Set session cookie
    set_session(response, {"username": db_user.username, "role": db_user.role})
    return {"message": "Login successful"}

@app.post("/logout")
def logout(response: Response):
    clear_session(response)
    return {"message": "Logged out"}

# Dependency to get current user from session cookie
def get_current_user(request: Request, db: Session = Depends(get_mysql_db)):
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session_data = get_session_data(cookie)
    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    user = db.query(User).filter(User.username == session_data["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ------------------- Admin JWT Login -------------------

@app.post("/admin/login")
def admin_login(user: UserLogin, response: Response, Authorize: AuthJWT = Depends(), db: Session = Depends(get_mysql_db)):
    db_user = db.query(User).filter(User.username == user.username, User.role == "admin").first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    access_token = Authorize.create_access_token(subject=db_user.username)
    
    response.set_cookie(
        key='admin_token',
        value=access_token,
        httponly=True,
        secure=False,
        samesite='lax'
    )
    return {"message": 'Login successful'}

# Dependency for admin JWT
def get_admin_user(Authorize: AuthJWT = Depends(), db: Session = Depends(get_mysql_db), request: Request = None):
    token = request.cookies.get('admin_token')
    if not token: 
        raise HTTPException(401, detail='Admin token missing')
    try:
        Authorize._token = token
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(401, detail='Invalid token')
    username = Authorize.get_jwt_subject()
    user = db.query(User).filter(User.username == username, User.role == "admin").first()
    if not user:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

# ------------------- Inventory CRUD (MongoDB, per-user) -------------------

@app.post("/inventory", response_model=InventoryItemOut)
async def create_inventory(
    item: InventoryItemCreate,
    current_user: User = Depends(get_current_user)
):
    new_item = InventoryItem(
        **item.dict(),
        owner_username=current_user.username
    )
    await new_item.insert()
    return new_item

@app.get("/inventory", response_model=List[InventoryItemOut])
async def get_inventory(current_user: User = Depends(get_current_user)):
    items = await InventoryItem.find(InventoryItem.owner_username == current_user.username).to_list()
    return items

@app.get("/inventory/{item_id}", response_model=InventoryItemOut)
async def get_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    return item

@app.patch("/inventory/{item_id}", response_model=InventoryItemOut)
async def update_inventory_item(
    item_id: str,
    item_update: InventoryItemUpdate,
    current_user: User = Depends(get_current_user)
):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    update_data = item_update.dict(exclude_unset=True)
    await item.update({"$set": update_data})
    updated_item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    return updated_item

@app.delete("/inventory/{item_id}")
async def delete_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    await item.delete()
    return {"message": "Item deleted"}

# ------------------- Admin Inventory CRUD (JWT) -------------------

@app.get("/admin/inventory", response_model=List[InventoryItemOut])
async def admin_get_inventory(admin: User = Depends(get_admin_user)):
    items = await InventoryItem.find(InventoryItem.owner_username == admin.username).to_list()
    return items

@app.post("/admin/inventory", response_model=InventoryItemOut)
async def admin_create_inventory(
    item: InventoryItemCreate,
    admin: User = Depends(get_admin_user)
):
    new_item = InventoryItem(
        **item.dict(),
        owner_username=admin.username
    )
    await new_item.insert()
    return new_item

@app.patch("/admin/inventory/{item_id}", response_model=InventoryItemOut)
async def admin_update_inventory_item(
    item_id: str,
    item_update: InventoryItemUpdate,
    admin: User = Depends(get_admin_user)
):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item or item.owner_username != admin.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized for admin")
    update_data = item_update.dict(exclude_unset=True)
    await item.update({"$set": update_data})
    updated_item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    return updated_item

@app.delete("/admin/inventory/{item_id}")
async def admin_delete_inventory_item(item_id: str, admin: User = Depends(get_admin_user)):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item or item.owner_username != admin.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized for admin")
    await item.delete()
    return {"message": "Admin item deleted"}

# (You can add more admin-only endpoints as needed)

@app.get("/sql/inventory", response_model=List[SQLInventoryItemOut])
async def sql_get_inventory (current_user: User = Depends(get_current_user),db: Session = Depends(get_mysql_db)):
    user_items = db.query(SQLInventoryItem).filter(SQLInventoryItem.owner_username == current_user.username).all()
    if not user_items:
        return []
    return user_items

@app.get("/sql/inventory/{item_id}", response_model=SQLInventoryItemOut)
async def sql_get_item_by_id (item_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id, SQLInventoryItem.owner_username == current_user.username).first()
    if not item:
        raise HTTPException(404, detail='Item not found')
    return item

@app.post("/sql/inventory", response_model=SQLInventoryItemOut)
async def insert_new_item (item: InventoryItemCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    new_item = SQLInventoryItem(
        item_name=item.item_name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
        owner_username=current_user.username
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item

@app.delete("/sql/inventory/{item_id}")
async def sql_delete_items(item_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id, SQLInventoryItem.owner_username == current_user.username).first()
    if not item:
        raise HTTPException(404, detail='Record not found')
    db.delete(item)
    db.commit()
    return {"message": "Record deleted successfully"}

@app.patch("/sql/inventory/{item_id}", response_model=SQLInventoryItemOut)
async def sql_update_item(
    item_id: int,
    item_update: InventoryItemUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_mysql_db)
):
    # Fetch the item from the database
    item = db.query(SQLInventoryItem).filter(
        SQLInventoryItem.item_id == item_id,
        SQLInventoryItem.owner_username == current_user.username
    ).first()

    # If the item does not exist or does not belong to the current user, raise an error
    if not item:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")

    # Update the fields of the item with the provided data
    update_data = item_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(item, key, value)

    # Commit the changes to the database
    db.commit()
    db.refresh(item)

    # Return the updated item
    return item

# ------------------- Admin SQL Inventory CRUD (JWT) -------------------

@app.get('/admin/sql/inventory', response_model=List[SQLInventoryItemOut])
async def admin_sql_get_inventory(db: Session = Depends(get_mysql_db), admin: User = Depends(get_admin_user)):
    """Lists all SQL inventory items belonging to the authenticated admin."""
    items = db.query(SQLInventoryItem).filter(SQLInventoryItem.owner_username == admin.username).all()
    return items

@app.post('/admin/sql/inventory', response_model=SQLInventoryItemOut)
async def admin_sql_create_item(item: InventoryItemCreate, db: Session = Depends(get_mysql_db), admin: User = Depends(get_admin_user)):
    """Creates a new SQL inventory item for the authenticated admin."""
    new_item = SQLInventoryItem(
        **item.dict(),
        owner_username=admin.username
    )
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item

@app.get('/admin/sql/inventory/{item_id}', response_model=SQLInventoryItemOut)
async def admin_sql_get_item(item_id: int, db: Session = Depends(get_mysql_db), admin: User = Depends(get_admin_user)):
    """Gets a specific SQL inventory item by ID, belonging to the authenticated admin."""
    item = db.query(SQLInventoryItem).filter(
        SQLInventoryItem.item_id == item_id,
        SQLInventoryItem.owner_username == admin.username
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Admin SQL item not found or not authorized")
    return item

@app.patch('/admin/sql/inventory/{item_id}', response_model=SQLInventoryItemOut)
async def admin_sql_update_item(
    item_id: int,
    item_update: InventoryItemUpdate,
    db: Session = Depends(get_mysql_db),
    admin: User = Depends(get_admin_user)
):
    """Updates a specific SQL inventory item by ID, belonging to the authenticated admin."""
    item = db.query(SQLInventoryItem).filter(
        SQLInventoryItem.item_id == item_id,
        SQLInventoryItem.owner_username == admin.username
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Admin SQL item not found or not authorized")

    update_data = item_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(item, key, value)

    db.commit()
    db.refresh(item)
    return item

@app.delete('/admin/sql/inventory/{item_id}')
async def admin_sql_delete_item(item_id: int, db: Session = Depends(get_mysql_db), admin: User = Depends(get_admin_user)):
    """Deletes a specific SQL inventory item by ID, belonging to the authenticated admin."""
    item = db.query(SQLInventoryItem).filter(
        SQLInventoryItem.item_id == item_id,
        SQLInventoryItem.owner_username == admin.username
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Admin SQL item not found or not authorized")

    db.delete(item)
    db.commit()
    return {"message": "Admin SQL item deleted successfully"}
