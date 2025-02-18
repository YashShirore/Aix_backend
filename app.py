import os
import re
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from shutil import rmtree
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import bcrypt  
import stat

# Load environment variables from .env file
load_dotenv()

# Flask app setup
app = Flask(__name__)
CORS(app)

# Database Configuration (using environment variables)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# User Model with Role
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='User')  # Added role

# Hash password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def check_password(stored_hash, password):
    # Ensure the stored hash is in bytes format, in case it's a string
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    
    # Compare the hashed password with the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

def make_writable(file_path):
    os.chmod(file_path, stat.S_IWRITE)

# Initialize database
with app.app_context():
    db.create_all()

# ** Vendor platform mapping **
VENDOR_PLATFORM = {
    "paloalto": ["panos"],
    "cisco": ["asa", "ios"],
    "fortinet": ["fortios"]
}



def identify_vendor(file_path):
    vendor_patterns = {
        "cisco": [r"^interface\\s", r"ip route", r"access-list", r"line vty", r"crypto ikev2"],
        "fortinet": [r"^config\\s", r"^edit\\s", r"^next$", r"^set\\s", r"^end$"],
        "paloalto": [r"<config>", r"<devices>", r"<entry>", r"set deviceconfig", r"<phash>"]
    }

    try:
        with open(file_path, "r") as file:
            content = file.readlines()

        for line in content:
            for vendor, patterns in vendor_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        return vendor
        return "unknown"

    except Exception as e:
        return f"Error: {str(e)}"


# Extract ZIP file to temporary directory
def extract_zip(zip_path, extract_dir):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)



# Run firewall analyzer for a single file
def analyze_file(file_path, vendor, output_dir):
    platform = VENDOR_PLATFORM.get(vendor, ["unknown"])[0]
    if platform == "unknown":
        return f"Error: No platform available for vendor '{vendor}'." 

    # Generate unique output filename using the input file name and timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    input_filename = Path(file_path).stem
    output_file = output_dir
    command = [
        "python", "main.py",
        "--input", file_path,
        "--platform", f"{vendor}.{platform}",
        "--report", "excel",
        "--output", output_file
    ]

    try:
        subprocess.run(command, check=True)
        return f"Success: Report saved as {output_file}"
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global variable for user-specific output directory
user_output_dir = None

# Utility function to create a zip file from a directory
def create_zip(zip_name, files=None, files_dir=None):
    """
    Create a zip file from a list of files or all files in a directory.

    Args:
        zip_name (str): Name of the output zip file.
        files (list): List of specific files to include (optional, not used in this case).
        files_dir (str): Directory containing files to zip.

    Returns:
        str: Path to the created zip file.
    """
    if not files_dir:
        raise ValueError("The 'files_dir' argument must be provided.")

    # Ensure the full path for the zip file
    zip_path = os.path.join(user_output_dir, zip_name)

    with zipfile.ZipFile(zip_path, 'w') as zipf:
        # Iterate over the top-level files in the directory
        for item in os.listdir(files_dir):
            item_path = os.path.join(files_dir, item)

            # Ensure the item is a file and not a directory, also skip .zip files
            if os.path.isfile(item_path) and not item.endswith('.zip'):
                zipf.write(item_path, arcname=item)  # Add the file with its name
    
    return zip_path

def get_user_output_dir(username):
    """
    Retrieve the user's output directory path based on the username.
    """
    if not username:
        return None, "Username not provided."

    # Create a directory specific to the user
    output_dir = os.path.join(report_output_dir, username)
    os.makedirs(output_dir, exist_ok=True)
    return output_dir, None


 

def extract_vendor_from_file(file_content):
    """
    Dummy function to determine vendor from file content.
    Replace with your actual logic.
    """
    if b'cisco' in file_content.lower():
        return 'Cisco'
    elif b'fortinet' in file_content.lower():
        return 'Fortinet'
    else:
        return 'Unknown'

@app.route('/analyze', methods=['POST'])
def analyze_files():
    global user_output_dir
    if 'file' not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400

    # Get username from the request headers
    username = request.headers.get('username')
    if not username:
        return jsonify({"error": "Username not provided in headers."}), 400

    # Update the global user_output_dir for the current request
    user_output_dir, error = get_user_output_dir(username)
    if error:
        return jsonify({"error": error}), 400

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    temp_dir = os.path.join(UPLOAD_FOLDER, "temp_extracted")
    is_zip_input = file_path.endswith(".zip")
    input_files = []

    # Handle ZIP files
    if is_zip_input:
        rmtree(temp_dir, ignore_errors=True)
        os.makedirs(temp_dir, exist_ok=True)
        extract_zip(file_path, temp_dir)
        input_files = [os.path.join(temp_dir, f) for f in os.listdir(temp_dir)]
        input_file_count = len(input_files)  # Track the number of files in the ZIP
        output_dir = report_output_dir
    else:
        input_files = [file_path]
        input_file_count = 1  # Only one file in the input
        output_dir = user_output_dir  # For individual files

    def process_file(file_path):
        vendor = identify_vendor(file_path)
        if vendor == "unknown":
            return {"file": Path(file_path).name, "status": "error", "message": "Unable to identify vendor", "vendor": "unknown"}

        analysis_result = analyze_file(file_path, vendor, output_dir)
        return {"file": Path(file_path).name, "status": "success", "vendor": vendor, "result": analysis_result}

    results = []
    output_files = []  # Collect output files
    vendors = []  # Collect vendor names
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_file, f): f for f in input_files}
        for future in futures:
            result = future.result()
            results.append(result)
            vendors.append(result["vendor"])  # Add the vendor name to the vendors list
            if result["status"] == "success" and "result" in result:
                match = re.search(r"Report saved as (.+)", result["result"])
                if match:
                    output_files.append(match.group(1))

    if os.path.exists(temp_dir):
        rmtree(temp_dir)

    # If the input was a ZIP file, create a single ZIP file for the output reports
    if is_zip_input:
        if len(output_files) == input_file_count:
            zip_name = f"analysis_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            zip_path = create_zip(zip_name, files_dir=report_output_dir)
            # Move the ZIP file to the {username} folder
            final_zip_path = os.path.join(user_output_dir, os.path.basename(zip_path))
            os.rename(zip_path, final_zip_path)
            
            # Verify ZIP creation before deleting files
            if os.path.exists(zip_path):
                for file_name in os.listdir(report_output_dir):
                    file_path = os.path.join(report_output_dir, file_name)
                    if os.path.isfile(file_path):  # Ensure it's a file, not a directory
                        try:
                            os.remove(file_path)
                        except Exception as e:
                            print(f"Error deleting file {file_path}: {e}")

            return jsonify({
                "status": "success",
                "message": "Analysis completed. Reports are available for download.",
                "zip_file": os.path.basename(final_zip_path),
                "vendors": vendors  # Include the list of vendor names in the response
            }), 200
        else:
            return jsonify({"error": "Mismatch in the number of processed files. Some files may have failed."}), 400

    return jsonify({
        "status": "success",
        "message": "Analysis completed.",
        "results": results,
        "vendors": vendors  # Include the vendor names for individual files
    }), 200


@app.route('/signup', methods=['POST'])
def sign_up():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'User')

    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    new_user = User(username=username, email=email, password=hash_password(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Account created successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')  # Get email from the request
    password = data.get('password')  # Get password from the request

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Check if the email exists in the database
    user = User.query.filter_by(email=email).first()

    if user and check_password(user.password, password):  # Check if the hashed password matches
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 400


@app.route('/get-user', methods=['POST'])
def get_user():
    data = request.json
    email = data.get('email')

    # Check if the email exists in the database
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"username": user.username}), 200  # Return the username
    else:
        return jsonify({"error": "User not found"}), 404  # Handle case where user does not exist


@app.route('/get-role', methods=['POST'])
def get_role():
    data = request.json
    email = data.get('email')

    # Check if the email exists in the database
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"role": user.role}), 200  # Return the role of the user
    else:
        return jsonify({"error": "User not found"}), 404  # Handle case where user does not exist


@app.route('/get-users', methods=['GET'])
def get_users():
    users = User.query.filter_by(role="User").all()
    if users:
        users_data = [{"id": user.id, "username": user.username, "email": user.email, "role": user.role} for user in users]
        return jsonify({"status": "success", "users": users_data}), 200
    else:
        return jsonify({"status": "error", "message": "No users found"}), 404

root_dir = os.path.dirname(os.path.abspath(__file__))
report_output_dir = os.path.join(root_dir, 'report_output')

@app.route('/api/files', methods=['GET'])
def list_files():
    # Get username from request headers
    username = request.headers.get('username')
    
    if not username:
        return jsonify({"error": "Username header is required"}), 400
        
    # Create user-specific directory path
    user_dir = os.path.join(report_output_dir, username)
    
    # Create directory if it doesn't exist
    os.makedirs(user_dir, exist_ok=True)
    
    try:
        # List files in user's directory and sort by modification time (newest first)
        files = [
            {"file": f, "modified": os.path.getmtime(os.path.join(user_dir, f))}
            for f in os.listdir(user_dir)
            if os.path.isfile(os.path.join(user_dir, f))
        ]
        
        # Sort files by the modification time (latest first)
        files.sort(key=lambda x: x["modified"], reverse=True)
        
        # Extract only the file names for the response
        files = [file_info["file"] for file_info in files]
        
        return jsonify({"files": files}), 200
    except Exception as e:
        return jsonify({"error": f"Error listing files: {str(e)}"}), 500

# Update the download endpoint to use user-specific directory
@app.route('/api/download/<filename>', methods=['GET'])
def download_report(filename):
    username = request.headers.get('username')
    
    if not username:
        return jsonify({"error": "Username header is required"}), 400
        
    user_dir = os.path.join(report_output_dir, username)
    file_path = os.path.join(user_dir, filename)
    
    if not os.path.isfile(file_path):
        return jsonify({"error": f"File not found: {filename}"}), 404

    return send_file(file_path, as_attachment=True)

# Update the latest file endpoint to use user-specific directory
@app.route('/api/latest-file', methods=['GET'])
def get_latest_file():
    username = request.headers.get('username')
    
    if not username:
        return jsonify({"error": "Username header is required"}), 400
        
    user_dir = os.path.join(report_output_dir, username)
    
    # Create directory if it doesn't exist
    os.makedirs(user_dir, exist_ok=True)
    
    try:
        files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
        if files:
            latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(user_dir, f)))
            return jsonify({"latest_file": latest_file}), 200
        else:
            return jsonify({"error": "No files found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error getting latest file: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, threaded=True, use_reloader=False, host='0.0.0.0', port=5000)
