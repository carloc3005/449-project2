# tests/conftest.py
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import AsyncMock, patch # Import mock tools

from main import app, get_mysql_db, get_admin_user, get_current_user # Import app and dependencies
from db import Base # Import Base for creating tables
from models import User, SQLInventoryItem, InventoryItem # Import models
from schemas import UserOut # Import schema for user creation helper

# Use an in-memory SQLite database for testing SQL parts
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}, # Needed for SQLite
    poolclass=StaticPool, # Use StaticPool for SQLite in-memory
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables in the in-memory database before tests run
Base.metadata.create_all(bind=engine)

# Dependency override for SQL database session
def override_get_mysql_db():
    database = None
    try:
        database = TestingSessionLocal()
        yield database
    finally:
        if database:
            database.close()

# Apply the override to the app
app.dependency_overrides[get_mysql_db] = override_get_mysql_db

# --- Mocking Beanie/MongoDB ---
# We'll patch the InventoryItem class directly where it's used (in main.py)

@pytest_asyncio.fixture(autouse=True) # Autouse ensures it runs for all tests
def mock_beanie_operations():
    """Mocks Beanie operations used in the main application."""
    # Patch where the model is used in the application code (main.py)
    with patch('main.InventoryItem.find', new_callable=AsyncMock) as mock_find, \
         patch('main.InventoryItem.find_one', new_callable=AsyncMock) as mock_find_one, \
         patch('main.InventoryItem.insert', new_callable=AsyncMock) as mock_insert, \
         patch('main.InventoryItem.update', new_callable=AsyncMock) as mock_update, \
         patch('main.InventoryItem.delete', new_callable=AsyncMock) as mock_delete:

        # Configure default return values or behaviors if needed, e.g.:
        # mock_find_one.return_value = None # Default to not found

        yield {
            "find": mock_find,
            "find_one": mock_find_one,
            "insert": mock_insert,
            "update": mock_update,
            "delete": mock_delete
        }
# --- End Mocking Beanie ---


@pytest_asyncio.fixture(scope="function")
async def client():
    """
    Pytest fixture to create an async test client for the app.
    Cleans up the in-memory database tables after each test function.
    """
    # Reset dependency overrides for each test function if necessary
    app.dependency_overrides[get_mysql_db] = override_get_mysql_db
    # Clear potential overrides from other tests if needed
    if get_current_user in app.dependency_overrides:
        del app.dependency_overrides[get_current_user]
    if get_admin_user in app.dependency_overrides:
        del app.dependency_overrides[get_admin_user]

    # Revert back to using keyword arguments
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

    # Clean up database tables after each test
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Pytest fixture to provide a direct database session for setup/assertions.
    """
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
    # Clean up database tables after each test
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


# --- Helper Fixtures for Authentication ---

@pytest_asyncio.fixture
async def registered_user(client: AsyncClient, db_session):
    """Registers a standard user and returns their details."""
    user_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    }
    response = await client.post("/register", json=user_data)
    assert response.status_code == 200
    # Return data including the ID from the response
    return UserOut(**response.json())


@pytest_asyncio.fixture
async def logged_in_client(client: AsyncClient, registered_user):
    """Provides a client that is already logged in as the registered_user."""
    login_data = {
        "username": registered_user.username,
        "password": "password123" # Use the password used in registered_user fixture
    }
    response = await client.post("/login", json=login_data)
    assert response.status_code == 200
    assert "session" in response.cookies
    return client # Return the client which now has the session cookie


@pytest_asyncio.fixture
async def registered_admin(client: AsyncClient, db_session):
    """Registers a user and promotes them to admin in the test DB."""
    user_data = {
        "username": "adminuser",
        "email": "admin@example.com",
        "password": "adminpass"
    }
    response = await client.post("/register", json=user_data)
    assert response.status_code == 200
    user_id = response.json()["id"]

    # Promote to admin in the test database
    db_user = db_session.query(User).filter(User.id == user_id).first()
    assert db_user is not None
    db_user.role = "admin"
    db_session.commit()
    db_session.refresh(db_user)
    assert db_user.role == "admin"
    return UserOut.from_orm(db_user)


@pytest_asyncio.fixture
async def admin_logged_in_client(client: AsyncClient, registered_admin):
    """Provides a client logged in as the admin user via JWT."""
    login_data = {
        "username": registered_admin.username,
        "password": "adminpass" # Use the password used in registered_admin fixture
    }
    response = await client.post("/admin/login", json=login_data)
    assert response.status_code == 200
    assert "admin_token" in response.cookies
    return client # Return the client which now has the admin_token cookie
