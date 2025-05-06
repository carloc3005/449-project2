# Inventory Management API

This project is a FastAPI-based API for managing inventory items. It supports user registration, login, and separate inventory management for regular users and administrators, utilizing both MySQL and MongoDB databases.

## Features

*   **User Authentication:**
    *   User registration (MySQL)
    *   Session-based login for regular users (MySQL)
    *   JWT-based login for administrators (MySQL)
*   **Inventory Management (User - MongoDB):**
    *   Create, Read, Update, Delete (CRUD) personal inventory items stored in MongoDB.
    *   Users can only access their own inventory items.
*   **Inventory Management (User - SQL):**
    *   Create, Read, Update, Delete (CRUD) personal inventory items stored in MySQL.
    *   Users can only access their own inventory items.
*   **Admin Inventory Management (MongoDB & SQL):**
    *   Admins can view all inventory items (MongoDB & SQL).
    *   Admins can CRUD items associated with their own admin account (MongoDB & SQL).
    *   Separate endpoints for admin operations.
*   **Dual Database Support:** Demonstrates using both relational (MySQL) and NoSQL (MongoDB) databases within the same application.

## Technologies Used

*   **Backend:** Python, FastAPI
*   **Databases:**
    *   MySQL (with SQLAlchemy ORM & mysql-connector-python)
    *   MongoDB (with Beanie ODM & Motor driver)
*   **Authentication:**
    *   Passlib (for password hashing)
    *   python-itsdangerous (for session signing)
    *   fastapi-jwt-auth (for JWT)
*   **Data Validation:** Pydantic
*   **Environment Variables:** python-dotenv
*   **ASGI Server:** Uvicorn
*   **Testing:** Pytest, httpx, pytest-asyncio, respx

## Prerequisites

*   Python 3.8+
*   MySQL Server
*   MongoDB Server
*   pip (Python package installer)

## Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd inventory-management
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up databases:**
    *   Ensure your MySQL and MongoDB servers are running.
    *   Create a database in MySQL (e.g., `Electronics` as suggested in the `.env` example).
    *   Note your database connection details.

5.  **Configure environment variables:**
    *   Rename the `.env.example` file to `.env`.
    *   Update the `.env` file with your actual database credentials and desired secret keys:
        ```dotenv
        DATABASE_URL=mysql+mysqlconnector://YOUR_MYSQL_USER:YOUR_MYSQL_PASSWORD@YOUR_MYSQL_HOST:YOUR_MYSQL_PORT/YOUR_MYSQL_DB_NAME
        MONGO_CONNECTION_STRING=mongodb://YOUR_MONGO_HOST:YOUR_MONGO_PORT
        MONGO_DATABASE_NAME=YOUR_MONGO_DB_NAME
        JWT_SECRET_KEY=generate_a_strong_random_secret_key
        SESSION_SECRET_KEY=generate_another_strong_random_secret_key
        ```

## Running the Application

Start the FastAPI application using Uvicorn:

```bash
uvicorn main:app --reload
