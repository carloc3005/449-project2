import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import logging # Optional: for logging errors

# Initialize SessionLocal as None, will be set by init_mysql
SessionLocal = None
Base = declarative_base()

def init_mysql():
    # Removed global engine declaration here
    DATABASE_URL = os.getenv("DATABASE_URL")
    if not DATABASE_URL:
        logging.error("DATABASE_URL environment variable not set.") # Log instead of raising here
        raise ValueError("DATABASE_URL environment variable not set or .env file not loaded correctly")

    try:
        engine = create_engine(DATABASE_URL) # Create engine locally
        global SessionLocal # Need to modify the global SessionLocal
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        # Optional: Test connection
        with engine.connect() as connection:
            logging.info("Successfully connected to MySQL database.")
        return engine # Return the created engine
    except Exception as e:
        logging.error(f"Failed to connect to MySQL database: {e}")
        raise

# Dependency for SQLAlchemy session
def get_mysql_db():
    if SessionLocal is None:
        # This should ideally not happen if init_mysql is called at startup
        raise RuntimeError("Database not initialized. Call init_mysql() first.")
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MongoDB/Beanie setup
async def init_mongo():
    MONGO_CONNECTION_STRING = os.getenv("MONGO_CONNECTION_STRING")
    MONGO_DATABASE_NAME = os.getenv("MONGO_DATABASE_NAME")
    if not MONGO_CONNECTION_STRING or not MONGO_DATABASE_NAME:
        raise ValueError("MONGO_CONNECTION_STRING or MONGO_DATABASE_NAME environment variable not set or .env file not loaded correctly")
    from models import InventoryItem  # Import here to avoid circular import
    client = AsyncIOMotorClient(MONGO_CONNECTION_STRING)
    db = client[MONGO_DATABASE_NAME]
    await init_beanie(database=db, document_models=[InventoryItem])
    logging.info("Successfully connected to MongoDB and initialized Beanie.") # Optional logging