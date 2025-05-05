from pydantic import BaseModel
from typing import Optional

# Pydantic model for the data encoded in the JWT token
class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# Pydantic model for the response when requesting a token (e.g., after login)
class Token(BaseModel):
    access_token: str
    token_type: str
