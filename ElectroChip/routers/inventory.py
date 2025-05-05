from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from typing import List, Optional
from fastapi.responses import RedirectResponse, HTMLResponse, Response # 
from fastapi.templating import Jinja2Templates
import os

from .. import models, security, db
from ..db import crud
from ..security import auth
from ..models.user import UserRole # Import UserRole

# Template setup (assuming templates are in ElectroChip/pages)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "pages")
templates = Jinja2Templates(directory=TEMPLATE_DIR)

router = APIRouter(
    prefix="/inventory",
    tags=["Inventory"],
    dependencies=[Depends(auth.get_current_active_user)] # Protect all routes in this router
)

# --- API Endpoints --- (JSON based)

@router.post("/", response_model=models.item.ItemOut, status_code=status.HTTP_201_CREATED)
async def create_item(
    item: models.item.ItemCreate,
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Creates a new inventory item for the current user."""
    created_item = await crud.create_inventory_item(item_data=item, owner_username=current_user.username)
    return created_item

@router.get("/", response_model=List[models.item.ItemOut])
async def read_items(
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Lists inventory items. Admins see all, users see their own."""
    if current_user.role == UserRole.admin:
        items = await crud.get_all_inventory_items()
    else:
        items = await crud.get_inventory_items_by_owner(owner_username=current_user.username)
    return items

@router.get("/{item_id}", response_model=models.item.ItemOut)
async def read_item(
    item_id: str,
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Gets a specific inventory item by ID."""
    item = await crud.get_inventory_item_by_id(item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Authorization check: Admin or Owner
    if current_user.role != UserRole.admin and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this item")

    return item

@router.patch("/{item_id}", response_model=models.item.ItemOut)
async def update_item(
    item_id: str,
    item_update: models.item.ItemUpdate,
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Updates an inventory item."""
    item = await crud.get_inventory_item_by_id(item_id) # Check existence first
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Authorization check: Admin or Owner
    if current_user.role != UserRole.admin and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this item")

    updated_item = await crud.update_inventory_item(item_id=item_id, item_update=item_update)
    if updated_item is None: # Should not happen if checks above pass, but good practice
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found after update attempt")
    return updated_item

@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(
    item_id: str,
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Deletes an inventory item."""
    item = await crud.get_inventory_item_by_id(item_id) # Check existence first
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    # Authorization check: Admin or Owner
    if current_user.role != UserRole.admin and item.owner_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this item")

    deleted = await crud.delete_inventory_item(item_id=item_id)
    if not deleted:
        # This might happen if the item was deleted between the check and the delete operation
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found or already deleted")
    # No content response on successful deletion
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Form Handling Endpoint for Dashboard --- (Example)
# This handles the form submission from the dashboard to add an item

@router.post("/add_item_form", name="add_item_form", include_in_schema=False) # Hide from API docs
async def add_item_via_form(
    request: Request,
    item_name: str = Form(...),
    description: str = Form(...),
    quantity: int = Form(...),
    price: float = Form(...),
    current_user: models.user.User = Depends(auth.get_current_active_user)
):
    """Handles adding an item via the dashboard form."""
    item_data = models.item.ItemCreate(item_name=item_name, description=description, quantity=quantity, price=price)
    try:
        await crud.create_inventory_item(item_data=item_data, owner_username=current_user.username)
        # Redirect back to dashboard on success
        # Need to get the URL for the dashboard route from the users router
        # This is a bit tricky, ideally routers know about each other or use app.url_path_for
        # For now, hardcoding or using a known name
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    except Exception as e:
        # Basic error handling: Redirect back to dashboard with an error message
        # A more robust solution would use flash messages or query parameters
        print(f"Error adding item via form: {e}") # Log the error
        # Fetch items again to render the dashboard with the error
        if current_user.role == UserRole.admin:
            items = await crud.get_all_inventory_items()
        else:
            items = await crud.get_inventory_items_by_owner(owner_username=current_user.username)
        # Convert ItemOut objects to dicts for template rendering if needed
        items_dict = [item.model_dump(by_alias=True) for item in items]
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "username": current_user.username,
                "items": items_dict,
                "error": "Failed to add item. Please check inputs.",
                "is_admin": current_user.role == UserRole.admin
            },
            status_code=status.HTTP_400_BAD_REQUEST
        )
