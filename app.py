from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
import subprocess
import datetime

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your_secret_key"
jwt = JWTManager(app)

# Users with roles
users = {
    "admin": {"password": "password123", "role": "admin"},
    "user": {"password": "userpass", "role": "user"}
}

# Logs for system call tracking
logs = []

# Pre-approved commands for regular users
allowed_commands = ["ls", "whoami", "pwd"]

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data.get("username"), data.get("password")
    if username in users and users[username]["password"] == password:
        token = create_access_token(identity={"username": username, "role": users[username]["role"]})
        return jsonify(token=token, role=users[username]["role"]), 200
    return jsonify({"msg": "Invalid credentials"}), 401

@app.route("/execute", methods=["POST"])
@jwt_required()
def execute_command():
    data = request.json
    command = data.get("command")
    user_info = get_jwt_identity()
    role = user_info["role"]

    # Regular users can only execute pre-approved commands
    if role == "user" and command.split()[0] not in allowed_commands:
        logs.append(f"{datetime.datetime.now()} - {user_info['username']} tried unauthorized command: {command}")
        return jsonify({"error": "Permission denied"}), 403

    try:
        output = subprocess.check_output(command, shell=True, text=True)
        logs.append(f"{datetime.datetime.now()} - {user_info['username']} executed: {command} -> SUCCESS")
        return jsonify({"output": output}), 200
    except subprocess.CalledProcessError:
        logs.append(f"{datetime.datetime.now()} - {user_info['username']} executed: {command} -> FAILED")
        return jsonify({"error": "Command execution failed"}), 400

@app.route("/logs", methods=["GET"])
@jwt_required()
def get_logs():
    user_info = get_jwt_identity()
    if user_info["role"] != "admin":
        return jsonify({"error": "Permission denied"}), 403
    return jsonify({"logs": logs}), 200

if __name__ == "__main__":
    app.run(debug=True)
