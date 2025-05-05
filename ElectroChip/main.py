from fastapi import FastAPI, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os

# Import database models and engine
from .db import database, models as db_models # Renamed import

# Import routers
from .routers import users, inventory

# Create database tables if they don't exist
# This should ideally be handled by migrations (e.g., Alembic) in production
try:
    db_models.user.Base.metadata.create_all(bind=database.engine)
    print("Database tables checked/created successfully.")
except Exception as e:
    print(f"Error creating database tables: {e}")
    # Depending on the error, you might want to exit or handle differently

# Create FastAPI app instance
app = FastAPI(
    title="ElectroChip Inventory Management",
    description="API for managing electronic component inventory.",
    version="1.0.0"
)

# Determine base directory and mount static files (images)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "images")

# Check if static directory exists before mounting
if os.path.exists(STATIC_DIR):
    app.mount("/images", StaticFiles(directory=STATIC_DIR), name="images")
    print(f"Mounted static directory: {STATIC_DIR}")
else:
    print(f"Warning: Static directory not found at {STATIC_DIR}")

# Include routers
app.include_router(users.router)
app.include_router(inventory.router)

# Root redirect to login page
@app.get("/", include_in_schema=False)
async def root(request: Request):
    # Check if user is already logged in via cookie
    if request.cookies.get("access_token"):
        # If logged in, redirect to dashboard
        return RedirectResponse(url=request.url_for("get_dashboard"))
    else:
        # If not logged in, redirect to login page
        return RedirectResponse(url=request.url_for("login_page"))

# Optional: Add event handlers for database connection pool if needed
# @app.on_event("startup")
# async def startup_db_client():
#     # If using async database connections that need explicit start/stop
#     pass

# @app.on_event("shutdown")
# async def shutdown_db_client():
#     # Clean up connections
#     pass

# Add a simple health check endpoint (good practice)
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok"}
