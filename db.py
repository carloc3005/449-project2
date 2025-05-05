import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
MONGO_CONNECTION_STRING = os.getenv("MONGO_CONNECTION_STRING")
MONGO_DATABASE_NAME = os.getenv("MONGO_DATABASE_NAME")

# SQLAlchemy setup (MySQL)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency for SQLAlchemy session
def get_mysql_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MongoDB/Beanie setup
async def init_mongo():
    from models import InventoryItem  # Import here to avoid circular import
    client = AsyncIOMotorClient(MONGO_CONNECTION_STRING)
    db = client[MONGO_DATABASE_NAME]
    await init_beanie(database=db, document_models=[InventoryItem])