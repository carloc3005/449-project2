from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Annotated, Optional, List # Added List
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import os # Import os module
from ..models.user import UserRole # Import UserRole

from .. import models, security, db
from ..db import crud, database
from ..security import auth

# Determine the base directory of the ElectroChip package
# This assumes main.py is in the ElectroChip directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "pages")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

router = APIRouter(
    tags=["Authentication", "Pages"], # Added Pages tag
)

# --- HTML Endpoints --- (Serving signup/login pages)

@router.get("/signup/user", response_class=HTMLResponse, name="signup_user_page")
async def get_signup_user_page(request: Request):
    return templates.TemplateResponse("signup_user.html", {"request": request})

@router.get("/signup/admin", response_class=HTMLResponse, name="signup_admin_page")
async def get_signup_admin_page(request: Request):
    # Optional: Add logic here to restrict admin signup if needed
    return templates.TemplateResponse("signup_admin.html", {"request": request})

@router.get("/login", response_class=HTMLResponse, name="login_page")
async def get_login_page(request: Request):
    # Check if user is already logged in (via cookie)
    try:
        # Attempt to get current user without raising exception on failure
        token = request.cookies.get("access_token")
        if token:
            token_data = auth.decode_access_token(token)
            if token_data and token_data.username:
                 # If valid token exists, redirect to dashboard
                 # Note: This doesn't fully validate the user against DB here for performance,
                 # relies on the dashboard route's own auth check.
                return RedirectResponse(url=router.url_path_for("get_dashboard"), status_code=status.HTTP_302_FOUND)
    except Exception:
        pass # Ignore errors, just show login page
    return templates.TemplateResponse("login.html", {"request": request})

# --- API Endpoints --- (Handling form submissions and JSON requests)

@router.post("/register/user", response_model=models.user.UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_in: models.user.UserRegister,
    db: Session = Depends(database.get_db)
):
    """Registers a new regular user."""
    db_user = crud.get_user_by_username(db, username=user_in.username)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    db_user_email = crud.get_user_by_email(db, email=user_in.email)
    if db_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Ensure role is 'user'
    user_in.role = models.user.UserRole.user
    created_user = crud.create_user(db=db, user=user_in)
    return created_user

@router.post("/register/admin", response_model=models.user.UserOut, status_code=status.HTTP_201_CREATED)
async def register_admin(
    user_in: models.user.UserRegister,
    db: Session = Depends(database.get_db)
    # Optional: Add dependency to require admin privileges to create another admin
    # current_admin: models.user.User = Depends(auth.require_admin)
):
    """Registers a new admin user."""
    db_user = crud.get_user_by_username(db, username=user_in.username)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    db_user_email = crud.get_user_by_email(db, email=user_in.email)
    if db_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Ensure role is 'admin'
    user_in.role = models.user.UserRole.admin
    created_user = crud.create_user(db=db, user=user_in)
    return created_user

@router.post("/token", response_model=models.token.Token)
async def login_for_access_token_json(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(database.get_db)
):
    """Handles login via JSON request (e.g., Postman) using OAuth2PasswordRequestForm."""
    user = crud.get_user_by_username(db, username=form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(
        data={"username": user.username, "role": user.role.value} # Ensure role is passed as string
    )
    auth.set_auth_cookie(response, access_token)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login", name="login_form") # Separate endpoint for form submission
async def login_for_access_token_form(
    response: Response,
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(database.get_db)
):
    """Handles login via HTML form submission."""
    user = crud.get_user_by_username(db, username=username)
    if not user or not auth.verify_password(password, user.hashed_password):
        # Render login page again with error
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    access_token = auth.create_access_token(
        data={"username": user.username, "role": user.role.value}
    )
    # Set cookie and redirect to dashboard
    # Use RedirectResponse with status_code 302 Found
    redirect_response = RedirectResponse(url=router.url_path_for("get_dashboard"), status_code=status.HTTP_302_FOUND)
    auth.set_auth_cookie(redirect_response, access_token)
    return redirect_response

@router.post("/logout", name="logout")
async def logout(response: Response, request: Request):
    """Logs the user out by unsetting the cookie and redirecting to login."""
    # Check if request accepts HTML
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header:
        # Redirect to login page for browser requests
        redirect_response = RedirectResponse(url=router.url_path_for("login_page"), status_code=status.HTTP_302_FOUND)
        auth.unset_auth_cookie(redirect_response)
        return redirect_response
    else:
        # Return JSON response for API requests
        auth.unset_auth_cookie(response)
        return {"message": "Successfully logged out"}

# --- Dashboard Route --- (Now fetches inventory data)

@router.get("/dashboard", response_class=HTMLResponse, name="get_dashboard")
async def get_dashboard(
    request: Request,
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Displays the dashboard with inventory items based on user role."""
    items: List[models.item.ItemOut] = []
    if current_user.role == UserRole.admin:
        items = await crud.get_all_inventory_items()
    else:
        items = await crud.get_inventory_items_by_owner(owner_username=current_user.username)

    # Convert ItemOut objects to dicts suitable for Jinja2, handling ObjectId
    items_dict = [item.model_dump(by_alias=True) for item in items]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "username": current_user.username,
            "items": items_dict,
            "is_admin": current_user.role == UserRole.admin # Pass admin status to template
        }
    )
