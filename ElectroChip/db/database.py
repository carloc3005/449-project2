# MySQL (SQLAlchemy) Setup
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from ..config.settings import settings

SQLALCHEMY_DATABASE_URL = settings.MYSQL_DSN

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# MongoDB (Motor) Setup
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_DETAILS = settings.MONGO_URI
client = AsyncIOMotorClient(MONGO_DETAILS)
database = client.get_database() # The database name is part of the MONGO_URI
inventory_collection = database.get_collection("inventory_items")

# Optional: Add indexing for MongoDB here if needed later
# Example:
# async def create_indexes():
#     await inventory_collection.create_index([("item_name", 1)], unique=False)
#     print("MongoDB indexes created.")
