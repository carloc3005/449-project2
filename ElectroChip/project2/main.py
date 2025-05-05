# ------------------- Imports -------------------
import os
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field, EmailStr # Removed BaseSettings import
# Removed SQLAlchemy imports, they are now in sql.py
from sqlalchemy.orm import Session # Keep Session for type hinting
from passlib.context import CryptContext
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie, Document, Link # Added Link
from dotenv import load_dotenv # Keep for MONGO/JWT
from typing import List, Optional
from pydantic import Field as PydanticField # Alias Pydantic Field to avoid conflict if needed later
import uuid # For generating item IDs

# Import from sql.py
from sql import SessionLocal, engine, Base, User, ElectronicComponent, create_db_tables, settings

# ------------------- Environment Variables & Settings -------------------
# load_dotenv() # Moved to sql.py
# Settings class is now imported from sql.py

# ------------------- FastAPI App Initialization -------------------
app = FastAPI()

# ------------------- Password Hashing Context -------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------- JWT Authentication Setup -------------------
@AuthJWT.load_config
def get_config():
    # Use the imported settings object
    return settings

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc: AuthJWTException):
    return HTTPException(status_code=exc.status_code, detail=exc.message)

# ------------------- SQLAlchemy (MySQL) Setup -------------------
# engine, SessionLocal, Base are now imported from sql.py

# Dependency function to get a MySQL DB session
def get_db(): # Renamed from get_mysql_db, removed the duplicate get_db
    # Use SessionLocal imported from sql.py
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------- Beanie (MongoDB) Setup -------------------
# Define Beanie Documents (MongoDB Models) Here (Example Placeholder)
# class MongoItem(Document):
#     name: str
#     description: Optional[str] = None
#     class Settings:
#         name = "items_collection" # MongoDB collection name

async def init_mongo_db():
    print(f"Attempting to connect to MongoDB at: {settings.MONGO_CONNECTION_STRING}")
    client = AsyncIOMotorClient(settings.MONGO_CONNECTION_STRING)
    db_instance = client[settings.MONGO_DATABASE_NAME]
    print(f"Connected to MongoDB database: {settings.MONGO_DATABASE_NAME}")
    # Pass all Document subclasses defined in this file or imported
    await init_beanie(database=db_instance, document_models=[
        InventoryItem, # Add the InventoryItem model here
        # Add other Beanie Document classes if you create more
    ])
    print("Beanie initialized successfully.")


@app.on_event("startup")
async def on_startup():
    # Initialize MongoDB connection when the app starts
    await init_mongo_db()
    # Create MySQL tables using the function from sql.py
    create_db_tables() # Call the function imported from sql.py

# ------------------- SQLAlchemy Models (MySQL Tables) -------------------
# User model is now imported from sql.py
# ElectronicComponent model is now imported from sql.py

# ------------------- Beanie Documents (MongoDB Collections) -------------------
class InventoryItem(Document):
    item_id: str = PydanticField(default_factory=lambda: str(uuid.uuid4()), unique=True)
    item_name: str
    description: Optional[str] = None
    quantity: int = Field(..., ge=0) # Quantity must be non-negative
    price: float = Field(..., ge=0.0) # Price must be non-negative
    owner_username: str = Field(..., index=True) # Link item to the user who owns it

    class Settings:
        name = "inventory_items" # MongoDB collection name
        # Add indexes if needed for frequent queries
        indexes = ["item_id", "owner_username"]

# ------------------- Pydantic Schemas -------------------

# Schema for User Creation (Registration)
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str = Field(min_length=8) # Add password validation later if needed
    role: str = 'user' # Default role is user, admin registration might need separate logic or manual DB entry

# Schema for User Login
class UserLogin(BaseModel):
    username: str
    password: str

# Schema for Token Response
class Token(BaseModel):
    access_token: str
    refresh_token: str

# Schema for displaying User Info (without password)
class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str # Include role in output

    class Config:
        orm_mode = True # For compatibility with SQLAlchemy objects

# --- Inventory Schemas ---
class InventoryItemBase(BaseModel):
    item_name: str
    description: Optional[str] = None
    quantity: int = Field(..., ge=0)
    price: float = Field(..., ge=0.0)

class InventoryItemCreate(InventoryItemBase):
    pass # Inherits all fields from Base

class InventoryItemUpdate(BaseModel): # Allow partial updates
    item_name: Optional[str] = None
    description: Optional[str] = None
    quantity: Optional[int] = Field(None, ge=0)
    price: Optional[float] = Field(None, ge=0.0)

class InventoryItemOut(InventoryItemBase):
    item_id: str
    owner_username: str

# ------------------- Helper Functions -------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Dependency to get current user from JWT and check roles
async def get_current_user(Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)) -> User: # Changed to use get_db
    Authorize.jwt_required()
    current_username = Authorize.get_jwt_subject()
    # Use the imported User model for querying
    user = db.query(User).filter(User.username == current_username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# Dependency for checking if user is admin
async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user

# ------------------- API Endpoints -------------------

# --- Authentication Endpoints (using MySQL for user storage) ---

@app.post('/register', response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: Session = Depends(get_db)): # Changed to use get_db
    # Check if username or email already exists using the imported User model
    db_user_by_username = db.query(User).filter(User.username == user.username).first()
    if db_user_by_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    db_user_by_email = db.query(User).filter(User.email == user.email).first()
    if db_user_by_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    if user.role not in ['user', 'admin']: # Basic role validation
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified. Must be 'user' or 'admin'.")

    # Hash the password
    hashed_password = get_password_hash(user.password)
    # Create new user instance using the imported User model
    # Use the correct column name 'password' from the model for the hashed value
    new_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password, # Assign hashed password to the 'password' field
        role=user.role # Assign role from input (defaults to 'user' in schema)
    )
    # Add to session and commit
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post('/login', response_model=Token)
def login_for_access_token(form_data: UserLogin, Authorize: AuthJWT = Depends(), db: Session = Depends(get_db)): # Changed to use get_db
    # Find user by username using the imported User model
    user = db.query(User).filter(User.username == form_data.username).first()
    # Check if user exists and password is correct
    # Use the 'password' field from the retrieved user object for verification
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Create tokens. Include role in access token claims for easier checking later?
    # user_claims = {"role": user.role} # Optional: Add role to token claims
    access_token = Authorize.create_access_token(
        subject=user.username,
        # user_claims=user_claims # Uncomment to add role claim
    )
    refresh_token = Authorize.create_refresh_token(subject=user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.post('/refresh', response_model=Token)
def refresh_token(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    # Keep the same refresh token or create a new one if needed
    # For simplicity, we'll just return the new access token and the old refresh token
    # You might want to implement refresh token rotation for better security
    refresh_token = Authorize.create_refresh_token(subject=current_user) # Or reuse existing if not rotating
    return {"access_token": new_access_token, "refresh_token": refresh_token}

@app.get("/users/me", response_model=UserOut)
async def read_users_me(current_user: User = Depends(get_current_user)):
    # The dependency already fetches and validates the user
    return current_user

# --- Inventory Endpoints (using MongoDB) ---

@app.post("/inventory", response_model=InventoryItemOut, status_code=status.HTTP_201_CREATED)
async def create_inventory_item(
    item: InventoryItemCreate,
    current_user: User = Depends(get_current_user) # Requires login
):
    new_item = InventoryItem(
        **item.dict(),
        owner_username=current_user.username # Set owner from logged-in user
    )
    await new_item.insert()
    return new_item

@app.get("/inventory", response_model=List[InventoryItemOut])
async def get_all_inventory_items(current_user: User = Depends(get_current_user)):
    if current_user.role == 'admin':
        # Admin gets all items
        items = await InventoryItem.find_all().to_list()
    else:
        # Regular user gets only their own items
        items = await InventoryItem.find(InventoryItem.owner_username == current_user.username).to_list()
    return items

@app.get("/inventory/{item_id}", response_model=InventoryItemOut)
async def get_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Check access: admin or owner
    if current_user.role != 'admin' and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this item")

    return item

@app.patch("/inventory/{item_id}", response_model=InventoryItemOut)
async def update_inventory_item(
    item_id: str,
    item_update: InventoryItemUpdate,
    current_user: User = Depends(get_current_user)
):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Check access: admin or owner
    if current_user.role != 'admin' and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this item")

    # Apply updates - exclude unset fields to allow partial updates
    update_data = item_update.dict(exclude_unset=True)
    if not update_data:
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided")

    await item.update({"$set": update_data})
    # Beanie doesn't automatically refresh the object in-place after update,
    # so we fetch it again to return the updated state.
    updated_item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    return updated_item

@app.delete("/inventory/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_inventory_item(item_id: str, current_user: User = Depends(get_current_user)):
    item = await InventoryItem.find_one(InventoryItem.item_id == item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Check access: admin or owner
    if current_user.role != 'admin' and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this item")

    await item.delete()
    return None # Return No Content on successful deletion

# ------------------- Main Execution (for running with uvicorn) -------------------
if __name__ == "__main__":
    import uvicorn
    # Note: Uvicorn should ideally be run from the command line:
    # uvicorn main:app --reload --host 0.0.0.0 --port 8000
    # This block is mainly for informational purposes or simple testing.
    print("Starting Uvicorn server...")
    print("Please ensure a .env file exists with DATABASE_URL, MONGO_CONNECTION_STRING, MONGO_DATABASE_NAME, and JWT_SECRET_KEY")
    uvicorn.run(app, host="0.0.0.0", port=8000)

