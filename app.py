from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import hashlib
import datetime
import os
import random

app = Flask(__name__)
CORS(app)

# Simulated user database
users = {"admin": hashlib.sha256("password123".encode()).hexdigest()}
user_roles = {"admin": "admin"}
sessions = {}
auth_codes = {}

# Log file
LOG_FILE = "system_call_logs.txt"

# System calls
SYSTEM_CALLS = ["get_system_info", "list_processes", "check_disk_space", "create_file", "delete_file", "network_status"]
USER_ALLOWED_CALLS = ["get_system_info", "list_processes", "check_disk_space"]

def log_action(entry):
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

@app.route('/')
def index():
    return render_template_string(html_template, system_calls=SYSTEM_CALLS)

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username or not password:
        return jsonify({"error": "Please enter both username and password"}), 400

    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if username in users and users[username] == hashed_password:
        auth_codes[username] = random.randint(1000, 9999)
        return jsonify({"message": f"Enter this 2FA code: {auth_codes[username]}", "status": "success"})
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    username = request.json.get('username')
    code = request.json.get('code')
    if not username or not code or not code.isdigit():
        return jsonify({"error": "Invalid 2FA code"}), 400

    if int(code) == auth_codes.get(username):
        sessions[username] = {"role": user_roles.get(username, "user"), "start": datetime.datetime.now()}
        del auth_codes[username]
        return jsonify({"status": "success", "role": sessions[username]["role"]})
    return jsonify({"error": "Invalid 2FA code"}), 401

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    confirm = request.json.get('confirm')
    role = request.json.get('role').lower()

    if not username or not password or not confirm or not role:
        return jsonify({"error": "All fields are required"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    if role not in ["admin", "user"]:
        return jsonify({"error": "Role must be 'admin' or 'user'"}), 400
    if username in users:
        return jsonify({"error": "Username already exists"}), 400

    users[username] = hashlib.sha256(password.encode()).hexdigest()
    user_roles[username] = role
    return jsonify({"message": "User registered successfully", "status": "success"})

@app.route('/execute', methods=['POST'])
def execute_system_call():
    if not request.json.get('username'):
        return jsonify({"error": "Please login first"}), 401
    username = request.json.get('username')
    selected_call = request.json.get('call')
    session = sessions.get(username)

    if not session or session.get('role') != "admin" and selected_call not in USER_ALLOWED_CALLS:
        log_entry = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {username} | IP: 192.168.{random.randint(1, 255)}.{random.randint(1, 255)} | Session: {(datetime.datetime.now() - session['start']).total_seconds():.1f}s | System Call: {selected_call} | Status: Failed | Error: Access denied for non-admin user"
        log_action(log_entry)
        return jsonify({"error": "Access denied. Admin privileges required"}), 403

    try:
        result = ""
        if selected_call == "get_system_info":
            result = "System info: Simulated OS details retrieved."
        elif selected_call == "list_processes":
            result = "Processes: Simulated process list retrieved."
        elif selected_call == "check_disk_space":
            result = "Disk Space: Simulated 50% usage reported."
        elif selected_call == "create_file":
            result = "File created: Simulated file 'test.txt' created."
        elif selected_call == "delete_file":
            result = "File deleted: Simulated file 'test.txt' deleted."
        elif selected_call == "network_status":
            result = "Network Status: Simulated connection active."

        log_entry = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {username} | IP: 192.168.{random.randint(1, 255)}.{random.randint(1, 255)} | Session: {(datetime.datetime.now() - session['start']).total_seconds():.1f}s | System Call: {selected_call} | Status: Success"
        log_action(log_entry)
        return jsonify({"message": result, "status": "success"})
    except Exception as e:
        log_entry = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {username} | IP: 192.168.{random.randint(1, 255)}.{random.randint(1, 255)} | Session: {(datetime.datetime.now() - session['start']).total_seconds():.1f}s | System Call: {selected_call} | Status: Failed | Error: {str(e)}"
        log_action(log_entry)
        return jsonify({"error": f"Failed to execute {selected_call}: {str(e)}"}), 500

@app.route('/view_logs', methods=['GET'])
def view_logs():
    if not request.args.get('username'):
        return jsonify({"error": "Please login first"}), 401
    username = request.args.get('username')
    if user_roles.get(username) != "admin":
        return jsonify({"error": "Only admins can view logs"}), 403
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            return jsonify({"logs": f.read()})
    return jsonify({"logs": "No logs available"})

@app.route('/logout', methods=['POST'])
def logout():
    username = request.json.get('username')
    if username in sessions and sessions[username]:
        session_duration = (datetime.datetime.now() - sessions[username]['start']).total_seconds()
        log_entry = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {username} | Session Ended | Duration: {session_duration:.1f}s"
        log_action(log_entry)
        del sessions[username]
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
