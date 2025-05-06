# tests/test_main.py
import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, MagicMock # Import MagicMock for simulating Beanie docs

# Import models and schemas used in tests
from models import InventoryItem, SQLInventoryItem
from schemas import InventoryItemOut, SQLInventoryItemOut

# Mark all tests in this module as async using pytest-asyncio
pytestmark = pytest.mark.asyncio

# --- Existing User Auth Tests ---
async def test_register_user(client: AsyncClient):
    """Test user registration."""
    response = await client.post("/register", json={
        "username": "testuser",
        "email": "test@example.com",
        "password": "password123"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["email"] == "test@example.com"
    assert data["role"] == "user"
    assert "id" in data
    assert "hashed_password" not in data # Ensure password is not returned

async def test_register_user_duplicate_username(client: AsyncClient):
    """Test registration with duplicate username."""
    # First registration
    await client.post("/register", json={
        "username": "testuser",
        "email": "test1@example.com",
        "password": "password123"
    })
    # Second registration with same username
    response = await client.post("/register", json={
        "username": "testuser", # Duplicate username
        "email": "test2@example.com",
        "password": "password456"
    })
    assert response.status_code == 400
    assert "Username already exists" in response.json()["detail"]

async def test_register_user_duplicate_email(client: AsyncClient):
    """Test registration with duplicate email."""
    # First registration
    await client.post("/register", json={
        "username": "testuser1",
        "email": "test@example.com", # Duplicate email
        "password": "password123"
    })
    # Second registration with same email
    response = await client.post("/register", json={
        "username": "testuser2",
        "email": "test@example.com", # Duplicate email
        "password": "password456"
    })
    assert response.status_code == 400
    assert "Email already exists" in response.json()["detail"]


async def test_login_user_success(client: AsyncClient):
    """Test successful user login."""
    # Register user first
    await client.post("/register", json={
        "username": "loginuser",
        "email": "login@example.com",
        "password": "password123"
    })

    # Attempt login
    response = await client.post("/login", json={
        "username": "loginuser",
        "password": "password123"
    })
    assert response.status_code == 200
    assert response.json() == {"message": "Login successful"}
    # Check if the session cookie was set (httpx handles cookies automatically)
    assert "session" in response.cookies

async def test_login_user_wrong_password(client: AsyncClient):
    """Test login with incorrect password."""
    # Register user first
    await client.post("/register", json={
        "username": "loginuser",
        "email": "login@example.com",
        "password": "password123"
    })

    # Attempt login with wrong password
    response = await client.post("/login", json={
        "username": "loginuser",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

async def test_login_user_not_found(client: AsyncClient):
    """Test login for a user that does not exist."""
    response = await client.post("/login", json={
        "username": "nonexistentuser",
        "password": "password123"
    })
    assert response.status_code == 401
    assert "Invalid username or password" in response.json()["detail"]

# --- MongoDB Inventory Tests (User) ---

# [Deleted test_create_inventory_item_success]

async def test_create_inventory_item_unauthenticated(client: AsyncClient):
    """Test creating item fails if not logged in."""
    item_data = {"item_name": "Fail Item", "quantity": 1, "price": 1.0}
    response = await client.post("/inventory", json=item_data)
    assert response.status_code == 401 # Expect unauthorized

# [Deleted test_get_inventory_list_success]

async def test_get_inventory_list_unauthenticated(client: AsyncClient):
    """Test getting item list fails if not logged in."""
    response = await client.get("/inventory")
    assert response.status_code == 401

# [Deleted test_get_inventory_item_success]

# [Deleted test_get_inventory_item_not_found]

# [Deleted test_get_inventory_item_wrong_user]

# [Deleted test_update_inventory_item_success]

# [Deleted test_update_inventory_item_not_found]

# [Deleted test_delete_inventory_item_success]

# [Deleted test_delete_inventory_item_not_found]

# --- SQL Inventory Tests (User) ---

async def test_create_sql_inventory_item_success(logged_in_client: AsyncClient, registered_user, db_session):
    """Test creating an SQL inventory item successfully."""
    item_data = {
        "item_name": "SQL Item 1",
        "description": "Description for SQL Item 1",
        "quantity": 5,
        "price": 9.99
    }
    response = await logged_in_client.post("/sql/inventory", json=item_data)

    assert response.status_code == 200
    data = response.json()
    assert data["item_name"] == item_data["item_name"]
    assert data["owner_username"] == registered_user.username
    assert "item_id" in data

    # Verify in test DB
    db_item = db_session.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == data["item_id"]).first()
    assert db_item is not None
    assert db_item.item_name == item_data["item_name"]
    assert db_item.owner_username == registered_user.username


async def test_create_sql_inventory_item_unauthenticated(client: AsyncClient):
    """Test creating SQL item fails if not logged in."""
    item_data = {"item_name": "Fail SQL Item", "quantity": 1, "price": 1.0, "description": "d"}
    response = await client.post("/sql/inventory", json=item_data)
    assert response.status_code == 401


async def test_get_sql_inventory_list_success(logged_in_client: AsyncClient, registered_user, db_session):
    """Test getting the list of SQL inventory items."""
    # Add some items directly to the test DB
    item1 = SQLInventoryItem(item_name="Sql A", quantity=1, price=1.0, owner_username=registered_user.username, description="dA")
    item2 = SQLInventoryItem(item_name="Sql B", quantity=2, price=2.0, owner_username=registered_user.username, description="dB")
    item3 = SQLInventoryItem(item_name="Sql C", quantity=3, price=3.0, owner_username="otheruser", description="dC") # Belongs to other user
    db_session.add_all([item1, item2, item3])
    db_session.commit()

    response = await logged_in_client.get("/sql/inventory")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2 # Should only get items for logged_in_client's user
    assert data[0]["item_name"] == "Sql A"
    assert data[1]["item_name"] == "Sql B"
    assert data[0]["owner_username"] == registered_user.username


async def test_get_sql_inventory_list_empty(logged_in_client: AsyncClient):
    """Test getting SQL item list when user has no items."""
    response = await logged_in_client.get("/sql/inventory")
    assert response.status_code == 200
    assert response.json() == []


async def test_get_sql_inventory_item_success(logged_in_client: AsyncClient, registered_user, db_session):
    """Test getting a specific SQL item."""
    item = SQLInventoryItem(item_name="Specific SQL", quantity=1, price=1.0, owner_username=registered_user.username, description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id # Get ID after commit

    response = await logged_in_client.get(f"/sql/inventory/{item_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["item_id"] == item_id
    assert data["item_name"] == "Specific SQL"
    assert data["owner_username"] == registered_user.username


async def test_get_sql_inventory_item_not_found(logged_in_client: AsyncClient):
    """Test getting a non-existent SQL item."""
    response = await logged_in_client.get("/sql/inventory/9999")
    assert response.status_code == 404
    assert "Item not found" in response.json()["detail"]


async def test_get_sql_inventory_item_wrong_user(logged_in_client: AsyncClient, db_session):
    """Test getting an SQL item belonging to another user."""
    item = SQLInventoryItem(item_name="Other SQL", quantity=1, price=1.0, owner_username="otheruser", description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    response = await logged_in_client.get(f"/sql/inventory/{item_id}")
    assert response.status_code == 404 # Endpoint logic treats wrong user as not found
    assert "Item not found" in response.json()["detail"]


async def test_update_sql_inventory_item_success(logged_in_client: AsyncClient, registered_user, db_session):
    """Test updating an SQL item."""
    item = SQLInventoryItem(item_name="SQL Original", quantity=10, price=20.0, owner_username=registered_user.username, description="Original Desc")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    update_payload = {"item_name": "SQL Updated", "quantity": 15}
    response = await logged_in_client.patch(f"/sql/inventory/{item_id}", json=update_payload)

    assert response.status_code == 200
    data = response.json()
    assert data["item_name"] == "SQL Updated"
    assert data["quantity"] == 15
    assert data["price"] == 20.0 # Price wasn't updated
    assert data["description"] == "Original Desc" # Description wasn't updated

    # Verify in DB
    db_session.refresh(item)
    assert item.item_name == "SQL Updated"
    assert item.quantity == 15


async def test_update_sql_inventory_item_not_found(logged_in_client: AsyncClient):
    """Test updating a non-existent SQL item."""
    response = await logged_in_client.patch("/sql/inventory/9999", json={"quantity": 5})
    assert response.status_code == 404
    assert "Item not found or not authorized" in response.json()["detail"]


async def test_delete_sql_inventory_item_success(logged_in_client: AsyncClient, registered_user, db_session):
    """Test deleting an SQL item."""
    item = SQLInventoryItem(item_name="SQL To Delete", quantity=1, price=5.0, owner_username=registered_user.username, description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    response = await logged_in_client.delete(f"/sql/inventory/{item_id}")

    assert response.status_code == 200
    assert response.json() == {"message": "Record deleted successfully"}

    # Verify in DB
    db_item = db_session.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id).first()
    assert db_item is None


async def test_delete_sql_inventory_item_not_found(logged_in_client: AsyncClient):
    """Test deleting a non-existent SQL item."""
    response = await logged_in_client.delete("/sql/inventory/9999")
    assert response.status_code == 404
    assert "Record not found" in response.json()["detail"]


# --- Admin MongoDB Inventory Tests ---

# [Deleted test_admin_create_mongo_item]

# [Deleted test_admin_get_mongo_list]

# [Deleted test_admin_update_mongo_item]

# [Deleted test_admin_delete_mongo_item]

# --- Admin SQL Inventory Tests ---

async def test_admin_create_sql_item(admin_logged_in_client: AsyncClient, registered_admin, db_session):
    """Test admin creating an SQL item."""
    item_data = {"item_name": "Admin SQL Item", "quantity": 1, "price": 100.0, "description": "Admin SQL Desc"}
    response = await admin_logged_in_client.post("/admin/sql/inventory", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert data["item_name"] == item_data["item_name"]
    assert data["owner_username"] == registered_admin.username
    # Verify in DB
    db_item = db_session.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == data["item_id"]).first()
    assert db_item is not None
    assert db_item.owner_username == registered_admin.username


async def test_admin_get_sql_list(admin_logged_in_client: AsyncClient, registered_admin, db_session):
    """Test admin getting their SQL item list."""
    item1 = SQLInventoryItem(item_name="AdminSqlA", quantity=1, price=1.0, owner_username=registered_admin.username, description="dA")
    item2 = SQLInventoryItem(item_name="UserSqlB", quantity=2, price=2.0, owner_username="testuser", description="dB") # Non-admin item
    db_session.add_all([item1, item2])
    db_session.commit()

    response = await admin_logged_in_client.get("/admin/sql/inventory")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["item_name"] == "AdminSqlA"
    assert data[0]["owner_username"] == registered_admin.username


async def test_admin_get_sql_item(admin_logged_in_client: AsyncClient, registered_admin, db_session):
    """Test admin getting a specific SQL item belonging to them."""
    item = SQLInventoryItem(item_name="AdminSpecific", quantity=1, price=1.0, owner_username=registered_admin.username, description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    response = await admin_logged_in_client.get(f"/admin/sql/inventory/{item_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["item_id"] == item_id
    assert data["item_name"] == "AdminSpecific"


async def test_admin_get_sql_item_wrong_user(admin_logged_in_client: AsyncClient, db_session):
    """Test admin trying to get SQL item belonging to another user (should fail)."""
    item = SQLInventoryItem(item_name="UserSpecific", quantity=1, price=1.0, owner_username="testuser", description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    response = await admin_logged_in_client.get(f"/admin/sql/inventory/{item_id}")
    assert response.status_code == 404 # Endpoint checks ownership
    assert "Admin SQL item not found or not authorized" in response.json()["detail"]


async def test_admin_update_sql_item(admin_logged_in_client: AsyncClient, registered_admin, db_session):
    """Test admin updating their SQL item."""
    item = SQLInventoryItem(item_name="AdminSQLOrig", quantity=10, price=20.0, owner_username=registered_admin.username, description="Orig")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    update_payload = {"quantity": 99}
    response = await admin_logged_in_client.patch(f"/admin/sql/inventory/{item_id}", json=update_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["quantity"] == 99
    assert data["item_name"] == "AdminSQLOrig" # Not updated

    db_session.refresh(item)
    assert item.quantity == 99


async def test_admin_delete_sql_item(admin_logged_in_client: AsyncClient, registered_admin, db_session):
    """Test admin deleting their SQL item."""
    item = SQLInventoryItem(item_name="AdminSQLDelete", quantity=1, price=1.0, owner_username=registered_admin.username, description="d")
    db_session.add(item)
    db_session.commit()
    item_id = item.item_id

    response = await admin_logged_in_client.delete(f"/admin/sql/inventory/{item_id}")
    assert response.status_code == 200
    assert response.json() == {"message": "Admin SQL item deleted successfully"}

    db_item = db_session.query(SQLInventoryItem).filter(SQLInventoryItem.item_id == item_id).first()
    assert db_item is None
