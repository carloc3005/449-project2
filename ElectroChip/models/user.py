from sqlalchemy import Column, Integer, String, Enum as SQLAlchemyEnum
from sqlalchemy.orm import relationship
from pydantic import BaseModel, EmailStr, Field
import enum

from ..db.database import Base

# Enum for User Roles
class UserRole(str, enum.Enum):
    user = "user"
    admin = "admin"

# SQLAlchemy model for the User table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SQLAlchemyEnum(UserRole), default=UserRole.user, nullable=False)

# Pydantic model for creating a new user (request body)
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z][a-zA-Z0-9-_]{2,49}$")
    email: EmailStr
    password: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z][a-zA-Z0-9-_]{2,49}$")
    role: UserRole = UserRole.user # Default role is user

# Pydantic model for user registration (specifically for the endpoint)
class UserRegister(UserCreate):
    pass # Inherits validation from UserCreate

# Pydantic model for representing a user in responses (excluding password)
class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: UserRole

    class Config:
        from_attributes = True # Allows creating Pydantic model from ORM object
