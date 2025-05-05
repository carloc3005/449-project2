# ------------------- Imports -------------------
import os # Added
from sqlalchemy import create_engine, Column, Integer, String, Float, MetaData, ForeignKey # Added ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from pydantic import BaseSettings # Added
from dotenv import load_dotenv # Added

# ------------------- Environment Variables & Settings -------------------
load_dotenv() # Load variables from .env file

class Settings(BaseSettings):
    # SQLAlchemy (MySQL) Settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "mysql+mysqlconnector://root:449project@localhost/electrochip_db") # Use env var

    # MongoDB Settings (Added)
    MONGO_CONNECTION_STRING: str = os.getenv("MONGO_CONNECTION_STRING", "mongodb://localhost:27017")
    MONGO_DATABASE_NAME: str = os.getenv("MONGO_DATABASE_NAME", "electrochip_inventory")

    # JWT Settings (Added)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your_super_secret_key_change_this") # CHANGE THIS IN .env!

    class Config:
        env_file = ".env"

settings = Settings()


# ------------------- SQLAlchemy Setup -------------------
# Use DATABASE_URL from settings
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine) # Define SessionLocal here
Base = declarative_base()

# ------------------- SQLALCHEMY MODELS -------------------
# These models define the structure of your database tables.
class User(Base): # Renamed from UserTable
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    # Ensure main.py uses 'hashed_password' when interacting with this model
    password = Column(String(255), nullable=False) # Store HASHED passwords! Increased length for bcrypt
    email = Column(String(100), unique=True, nullable=False, index=True)
    role = Column(String(50), default="user", nullable=False) # Increased length slightly

# Renamed table and adjusted fields for electronics
class ElectronicComponent(Base): # Renamed from ElectronicComponentTable
    __tablename__ = "components"
    id = Column(Integer, primary_key=True, index=True)
    part_number = Column(String(100), nullable=False, index=True)
    item_name = Column(String(100), nullable=False, index=True)
    description = Column(String(255))
    quantity = Column(Integer, nullable=False, default=0)
    price = Column(Float, nullable=False, default=0.0)
    manufacturer = Column(String(100))
    datasheet_url = Column(String(255), nullable=True)
    # Use ForeignKey to link to the User table's primary key
    owner_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False) # Changed to owner_id and added ForeignKey

# ------------------- Table Creation Function -------------------
def create_db_tables():
    """Creates all tables defined in the Base metadata."""
    print(f"Attempting to connect to database: {engine.url}")
    try:
        print("Creating database tables...")
        # Use the Base imported/defined in this file
        Base.metadata.create_all(bind=engine)
        print("Tables created successfully (if they didn't already exist).")
    except Exception as e:
        print(f"An error occurred during table creation: {e}")
        print("Please ensure the database server is running, the database exists,")
        print("and the connection details in DATABASE_URL (check .env file or default) are correct.")

# Removed the __main__ block, table creation will be triggered by the FastAPI app startup
