# Import FastAPI components for building the web application
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Cookie
# Import SQLAlchemy components for database operations
from sqlalchemy.orm import Session
# Import database connection functions
from db import get_mysql_db, init_mongo
# Import data models for User and Inventory items
from models import User, InventoryItem, SQLInventoryItem
# Import Pydantic schemas for data validation and serialization
from schemas import (
    UserCreate, UserLogin, UserOut,
    InventoryItemCreate, InventoryItemUpdate, InventoryItemOut, SQLInventoryItemOut
)
# Import authentication related functions
from auth import (
    get_password_hash, verify_password,
    set_session, clear_session, get_session_data, SESSION_COOKIE_NAME
)
# Import JWT authentication components
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
# Import type hints
from typing import List, Optional
# Import OS for environment variables
import os
# Import Pydantic settings for configuration
from pydantic import BaseSettings

# Create FastAPI application instance
app = FastAPI()

# Define JWT configuration settings
class Settings(BaseSettings):
    # Get JWT secret key from environment variable or use default
    authjwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "supersecret")

# Configure JWT settings
@AuthJWT.load_config
def get_config():
    return Settings()

# Initialize application on startup
@app.on_event("startup")
async def on_startup():
    # Initialize MongoDB connection
    await init_mongo()
    # Import and create SQL database tables
    from db import Base, engine
    Base.metadata.create_all(bind=engine)

# Handle JWT authentication exceptions
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc: AuthJWTException):
    raise HTTPException(status_code=exc.status_code, detail=exc.message)

# ------------------- User Registration & Login (Session/Cookie) -------------------

# Register new user endpoint
@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_mysql_db)):
    # Check if username already exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    # Check if email already exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    # Hash the user's password
    hashed_password = get_password_hash(user.password)
    # Create new user instance
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )
    # Add user to database and commit changes
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# User login endpoint
@app.post("/login")
def login(user: UserLogin, response: Response, db: Session = Depends(get_mysql_db)):
    # Find user by username
    db_user = db.query(User).filter(User.username == user.username).first()
    # Verify password
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    # Set session cookie with user data
    set_session(response, {"username": db_user.username, "role": db_user.role})
    return {"message": "Login successful"}

# User logout endpoint
@app.post("/logout")
def logout(response: Response):
    # Clear session cookie
    clear_session(response)
    return {"message": "Logged out"}

# Dependency to get current user from session cookie
def get_current_user(request: Request, db: Session = Depends(get_mysql_db)):
    # Get session cookie
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Get session data from cookie
    session_data = get_session_data(cookie)
    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    # Find user in database
    user = db.query(User).filter(User.username == session_data["username"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ------------------- Admin JWT Login -------------------

# Admin login endpoint using JWT
@app.post("/admin/login")
def admin_login(user: UserLogin, response: Response, Authorize: AuthJWT = Depends(), db: Session = Depends(get_mysql_db)):
    # Find admin user
    db_user = db.query(User).filter(User.username == user.username, User.role == "admin").first()
    # Verify admin credentials
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    # Create JWT access token
    access_token = Authorize.create_access_token(subject=db_user.username)
    
    # Set admin token cookie
    response.set_cookie(
        key='admin_token',
        value=access_token,
        httponly=True,
        secure=False,
        samesite='lax'
    )
    return {"message": 'Login successful'}

# Dependency to get admin user from JWT token
def get_admin_user(Authorize: AuthJWT = Depends(), db: Session = Depends(get_mysql_db), request: Request = None):
    # Get admin token from cookie
    token = request.cookies.get('admin_token')
    if not token: 
        raise HTTPException(401, detail='Admin token missing')
    try:
        # Verify JWT token
        Authorize._token = token
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(401, detail='Invalid token')
    # Get username from token
    username = Authorize.get_jwt_subject()
    # Find admin user in database
    user = db.query(User).filter(User.username == username, User.role == "admin").first()
    if not user:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

# ------------------- Inventory CRUD (MongoDB, per-user) -------------------

# Create inventory item endpoint
@app.post("/inventory", response_model=InventoryItemOut)
async def create_inventory(
    item: InventoryItemCreate,
    current_user: User = Depends(get_current_user)
):
    # Create new inventory item with owner
    new_item = InventoryItem(
        **item.dict(),
        owner_username=current_user.username
    )
    # Insert into MongoDB
    await new_item.insert()
    return new_item

# Get all inventory items for current user
@app.get("/inventory", response_model=List[InventoryItemOut])
async def get_inventory(current_user: User = Depends(get_current_user)):
    # Find all items owned by current user
    items = await InventoryItem.find(InventoryItem.owner_username == current_user.username).to_list()
    return items

# Get specific inventory item
@app.get("/inventory/{item_id}", response_model=InventoryItemOut)
async def get_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    # Find item by ID
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    # Check ownership
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    return item

# Update inventory item
@app.patch("/inventory/{item_id}", response_model=InventoryItemOut)
async def update_inventory_item(
    item_id: str,
    item_update: InventoryItemUpdate,
    current_user: User = Depends(get_current_user)
):
    # Find item by ID
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    # Check ownership
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    # Update item with new data
    update_data = item_update.dict(exclude_unset=True)
    await item.update({"$set": update_data})
    # Get updated item
    updated_item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    return updated_item

# Delete inventory item
@app.delete("/inventory/{item_id}")
async def delete_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    # Find item by ID
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    # Check ownership
    if not item or item.owner_username != current_user.username:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")
    # Delete item
    await item.delete()
    return {"message": "Item deleted"}

# ------------------- Admin Inventory CRUD (JWT) -------------------

# Get all inventory items (admin)
@app.get("/admin/inventory", response_model=List[InventoryItemOut])
async def admin_get_inventory(admin: User = Depends(get_admin_user)):
    # Get all items owned by admin
    items = await InventoryItem.find(InventoryItem.owner_username == admin.username).to_list()
    return items

# Create inventory item (admin)
@app.post("/admin/inventory", response_model=InventoryItemOut)
async def admin_create_inventory(
    item: InventoryItemCreate,
    admin: User = Depends(get_admin_user)
):
    # Create new item owned by admin
    new_item = InventoryItem(
        **item.dict(),
        owner_username=admin.username
    )
    await new_item.insert()
    return new_item

# ------------------- SQL Inventory CRUD -------------------

# Get all SQL inventory items for current user
@app.get("/sql/inventory", response_model=List[SQLInventoryItemOut])
async def sql_get_inventory (current_user: User = Depends(get_current_user),db: Session = Depends(get_mysql_db)):
    # Get all items owned by current user from SQL database
    user_items = db.query(SQLInventoryItem).filter(SQLInventoryItem.owner_username == current_user.username).all()
    if not user_items:
        return []
    return user_items

# Get specific SQL inventory item
@app.get("/sql/inventory/{item_id}", response_model=SQLInventoryItemOut)
async def sql_get_item_by_id (item_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    # Find item by ID and owner
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id, SQLInventoryItem.owner_username == current_user.username).first()
    if not item:
        raise HTTPException(404, detail='Item not found')
    return item

# Create new SQL inventory item
@app.post("/sql/inventory", response_model=SQLInventoryItemOut)
async def insert_new_item (item: InventoryItemCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    # Create new SQL inventory item
    new_item = SQLInventoryItem(
        item_name=item.item_name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
        owner_username=current_user.username
    )
    # Add to database and commit
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item

# Delete SQL inventory item
@app.delete("/sql/inventory/{item_id}")
async def sql_delete_items(item_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_mysql_db)):
    # Find item by ID and owner
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id, SQLInventoryItem.owner_username == current_user.username).first()
    if not item:
        raise HTTPException(404, detail='Record not found')
    # Delete item and commit
    db.delete(item)
    db.commit()
    return {"message": "Record deleted successfully"}

# Update SQL inventory item
@app.patch("/sql/inventory/{item_id}", response_model=SQLInventoryItemOut)
async def sql_update_item(
    item_id: int,
    item_update: InventoryItemUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_mysql_db)
):
    # Find item by ID and owner
    item = db.query(SQLInventoryItem).filter(
        SQLInventoryItem.item_id == item_id,
        SQLInventoryItem.owner_username == current_user.username
    ).first()

    # Check if item exists and belongs to user
    if not item:
        raise HTTPException(status_code=404, detail="Item not found or not authorized")

    # Update item fields
    update_data = item_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(item, key, value)

    # Commit changes
    db.commit()
    db.refresh(item)

    return item

# Get all SQL inventory items (admin)
@app.get("/sql/admin/inventory", response_model=List[SQLInventoryItemOut])
async def admin_get_all_items(
    page: int = 1,
    db: Session = Depends(get_mysql_db),
    admin: User = Depends(get_admin_user)
):
    # Pagination settings
    items_per_page = 50
    offset = (page - 1) * items_per_page

    # Get paginated items
    items = db.query(SQLInventoryItem).offset(offset).limit(items_per_page).all()

    return items

# Update SQL inventory item (admin)
@app.patch("/sql/admin/inventory/{item_id}", response_model=SQLInventoryItemOut)
async def admin_update_item(
    item_id: int,
    item_update: InventoryItemUpdate,
    db: Session = Depends(get_mysql_db),
    admin: User = Depends(get_admin_user)
):
    # Find item by ID
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id).first()

    # Check if item exists
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Update item fields
    update_data = item_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(item, key, value)

    # Commit changes
    db.commit()
    db.refresh(item)

    return item

# Delete SQL inventory item (admin)
@app.delete("/sql/admin/inventory/{item_id}")
async def admin_delete_item(
    item_id: int,
    db: Session = Depends(get_mysql_db),
    admin: User = Depends(get_admin_user)
):
    # Find item by ID
    item = db.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id).first()

    # Check if item exists
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Delete item and commit
    db.delete(item)
    db.commit()

    return {"message": "Item deleted successfully"}

# Create SQL inventory item (admin)
@app.post("/sql/admin/inventory", response_model=SQLInventoryItemOut)
async def sql_get_inventory (item: InventoryItemCreate, current_user: User = Depends(get_admin_user),db: Session = Depends(get_mysql_db)):
    # Create new SQL inventory item
    new_item = SQLInventoryItem(
        item_name=item.item_name,
        description=item.description,
        quantity=item.quantity,
        price=item.price,
    )
    # Add to database and commit
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item