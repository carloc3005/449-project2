from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # MySQL
    MYSQL_USER: str
    MYSQL_PASSWORD: str
    MYSQL_HOST: str
    MYSQL_PORT: int = 3306
    MYSQL_DB: str

    # MongoDB
    MONGO_URI: str

    # JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Construct MySQL DSN
    @property
    def MYSQL_DSN(self) -> str:
        return f"mysql+mysqlconnector://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}"

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()
