import uuid
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import re

# Configure Flask to use custom folders:
app = Flask(
    __name__,
    template_folder='pages',    # HTML pages are in the 'pages' folder
    static_folder='images',     # Static files (e.g., images) are in the 'images' folder
    static_url_path='/images'   # Access static files via /images URL
)
app.secret_key = 'server_secret_key'

# In-memory storage for user credentials and inventory items.
users = {}       # Format: { username: {"password": ..., "email": ..., "role": ...} }
inventory = {}     # Format: { username: { item_id: item_data } }

# -----------------------------------
# Helper Functions for Verification
# -----------------------------------
def verifyJWT():
    if not session.get('username'):
        raise ValueError("Unauthorized")

def verifyVarFromSession(varName: str, varType: type):
    if request.json and varName in request.json and isinstance(request.json[varName], varType):
        return request.json[varName]
    raise ValueError(f"Invalid or missing {varName}")

def verifyIsJsonResponse():
    if not request.json:
        raise ValueError("Missing JSON payload")

# -----------------------------------
# Registration Endpoints (API + HTML)
# -----------------------------------

# JSON-based registration (for Postman or API testing)
@app.route('/register', methods=['POST'])
def register():
    try:
        verifyIsJsonResponse()
        username = verifyVarFromSession('username', str)
        password = verifyVarFromSession('password', str)
        email = verifyVarFromSession('email', str)
    except ValueError as e:
        return jsonify({"error": f"{str(e)}. JSON must include username, password, and email."}), 400

    role = request.json.get('role', 'user')   # Default to 'user' if not provided.
    if role not in ['user', 'admin']:
        return jsonify({"error": "Role must be either 'user' or 'admin'"}), 400

    # Validate username and password with regex.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
        return jsonify({"error": "Username must only consist of letters, numbers, and '-'."}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
        return jsonify({"error": "Password must only consist of letters, numbers, and '-'."}), 400

    users[username] = {"password": password, "email": email, "role": role}
    return jsonify("User registered successfully."), 201

# HTML-based registration for regular users.
@app.route('/signup_user', methods=['GET', 'POST'])
def signup_user():
    if request.method == 'GET':
        return render_template("signup_user.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = "user"  # Force the role to 'user'
        if not username or not password or not email:
            return render_template("signup_user.html", error="All fields are required.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
            return render_template("signup_user.html", error="Invalid username format.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
            return render_template("signup_user.html", error="Invalid password format.")
        if username in users:
            return render_template("signup_user.html", error="Username already exists.")
        users[username] = {"password": password, "email": email, "role": role}
        return redirect(url_for('login'))

# HTML-based registration for admin accounts.
@app.route('/signup_admin', methods=['GET', 'POST'])
def signup_admin():
    if request.method == 'GET':
        return render_template("signup_admin.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = "admin"  # Force the role to 'admin'
        if not username or not password or not email:
            return render_template("signup_admin.html", error="All fields are required.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", username):
            return render_template("signup_admin.html", error="Invalid username format.")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-_]{3,32}$", password):
            return render_template("signup_admin.html", error="Invalid password format.")
        if username in users:
            return render_template("signup_admin.html", error="Username already exists.")
        users[username] = {"password": password, "email": email, "role": role}
        return redirect(url_for('login'))

# -----------------------------------
# Login and Logout Endpoints
# -----------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    else:
        if request.is_json:
            try:
                verifyIsJsonResponse()
                username = verifyVarFromSession('username', str)
                password = verifyVarFromSession('password', str)
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
        else:
            username = request.form.get("username")
            password = request.form.get("password")
            if not username or not password:
                return render_template("login.html", error="Missing username or password")
        if username not in users or users[username]["password"] != password:
            if request.is_json:
                return jsonify({"error": "Invalid credentials"}), 401
            else:
                return render_template("login.html", error="Invalid credentials")
        session['username'] = username
        session['role'] = users[username]['role']
        if request.is_json:
            return jsonify("Logged in.")
        else:
            return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    if request.is_json:
        return jsonify("Logged out.")
    else:
        return redirect(url_for('login'))

# -----------------------------------
# Inventory CRUD Endpoints
# -----------------------------------
def get_item_by_id(item_id):
    """
    Returns the item with the given ID from any user's inventory.

    Note: Does NOT check if the current user has access.
    Returns None if the item is not found.
    """
    for user_items in inventory.values():
        if item_id in user_items:
            return user_items[item_id]
    return None

def can_access(item_id):
    # Admins can access any item; others only their own.
    if session.get('role') == 'admin':
        return True
    return item_id in inventory.get(session['username'], {})

@app.route('/inventory', methods=['POST'])
def createInventory():
    try:
        verifyJWT()
        
        # Handle both form data and JSON requests
        if request.is_json:
            data = request.json
        else:
            data = request.form
            
        required_fields = ['item_name', 'description', 'quantity', 'price']
        for field in required_fields:
            if field not in data:
                if request.is_json:
                    return jsonify({"error": f"Missing required field: {field}"}), 400
                else:
                    return render_template("dashboard.html", error=f"Missing required field: {field}")
                    
        # Convert form data to appropriate types
        try:
            quantity = int(data['quantity'])
            price = float(data['price'])
        except ValueError:
            if request.is_json:
                return jsonify({"error": "Invalid quantity or price format"}), 400
            else:
                return render_template("dashboard.html", error="Invalid quantity or price format")

        username = session['username']

        # Initialize storage if this is user's first item
        if username not in inventory:
            inventory[username] = {}

        item_id = str(uuid.uuid4())
        new_item = {
            'id': item_id,
            'item_name': data['item_name'],
            'description': data['description'],
            'quantity': quantity,
            'price': price,
        }
        inventory[username][item_id] = new_item

        if request.is_json:
            return jsonify(new_item), 201
        else:
            return redirect(url_for('dashboard'))

    except ValueError:
        if request.is_json:
            return jsonify({"error": "Unauthorized"}), 401
        else:
            return redirect(url_for('login'))

@app.route('/inventory', methods=['GET'])
def getAllInventory():
    try:
        verifyJWT()
        if session.get('role') == 'admin':
            all_items = []
            for user_items in inventory.values():
                all_items.extend(user_items.values())
            return jsonify(all_items)
        else:
            username = session['username']
            return jsonify(list(inventory.get(username, {}).values()))
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/inventory/<item_id>', methods=['GET'])
def getInventoryItem(item_id):
    try:
        verifyJWT()
        item = get_item_by_id(item_id)
        if not item:
            return jsonify({"error": "Item not found"}), 404
        if not can_access(item_id):
            return jsonify({"error": "Forbidden"}), 403
        return jsonify(item)
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/inventory/<item_id>', methods=['PATCH'])
def updateInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    item = get_item_by_id(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404

    if not can_access(item_id):
        return jsonify({"error": "Forbidden"}), 403

    if not request.json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    if 'item_name' in request.json:
        if not isinstance(request.json['item_name'], str):
            return jsonify({"error": "item_name must be a string"}), 400
        item['item_name'] = request.json['item_name']
    if 'description' in request.json:
        if not isinstance(request.json['description'], str):
            return jsonify({"error": "description must be a string"}), 400
        item['description'] = request.json['description']
    if 'quantity' in request.json:
        if not isinstance(request.json['quantity'], int):
            return jsonify({"error": "quantity must be an integer"}), 400
        item['quantity'] = request.json['quantity']
    if 'price' in request.json:
        if not isinstance(request.json['price'], (int, float)):
            return jsonify({"error": "price must be a number"}), 400
        item['price'] = request.json['price']

    return jsonify(item), 200

@app.route('/inventory/<item_id>', methods=['DELETE'])
def deleteInventory(item_id):
    try:
        verifyJWT()
    except ValueError:
        return jsonify({"error": "Unauthorized"}), 401

    item = get_item_by_id(item_id)
    if not item:
        return jsonify({"error": "Item not found"}), 404

    if not can_access(item_id):
        return jsonify({"error": "Forbidden"}), 403

    owner = session['username']
    if session.get('role') == 'admin':
        for username, items in inventory.items():
            if item_id in items:
                owner = username
                break

    deleted_item = inventory[owner].pop(item_id)
    return jsonify({
        "message": "Item deleted successfully",
        "item": deleted_item
    }), 200

# -----------------------------------
# Dashboard (HTML Interface)
# -----------------------------------
@app.route('/dashboard')
def dashboard():
    try:
        verifyJWT()
        if session.get('role') == 'admin':
            items = []
            for username, user_items in inventory.items():
                for item in user_items.values():
                    item_with_owner = item.copy()
                    item_with_owner['owner'] = username
                    items.append(item_with_owner)
        else:
            items = list(inventory.get(session['username'], {}).values())
        return render_template("dashboard.html", items=items, username=session.get('username'))
    except ValueError:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
