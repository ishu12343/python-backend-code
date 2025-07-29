from flask import Blueprint, request, jsonify
from flask_cors import CORS
from db import get_db_connection
import bcrypt
import jwt
import datetime
import re
import logging

SECRET_KEY = "your_secret_key"

# Configure logging
logging.basicConfig(level=logging.INFO)

patient_bp = Blueprint("patient", __name__)

# ---------------------------
# Register API
# ---------------------------
@patient_bp.route("/api/patient/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        full_name = data.get("fullName")
        email = data.get("email", "").lower()
        password = data.get("password")
        mobile = data.get("mobile")
        date_of_birth = data.get("dateOfBirth")
        gender = data.get("gender")
        blood_group = data.get("bloodGroup")
        address = data.get("address")
        emergency_contact = data.get("emergencyContact")
        role = data.get("role", "PATIENT")

        # Validate required fields
        if not all([full_name, email, password, mobile]):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate email format
        email_regex = r"[^@]+@[^@]+\.[^@]+"
        if not re.match(email_regex, email):
            return jsonify({"error": "Invalid email format"}), 400

        # Validate password length
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        # Validate date format
        if date_of_birth:
            try:
                datetime.datetime.strptime(date_of_birth, "%Y-%m-%d")
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        # Validate role
        if role not in ["PATIENT", "DOCTOR"]:
            return jsonify({"error": "Invalid role"}), 400

        # Validate gender
        if gender and gender.upper() not in ["MALE", "FEMALE", "OTHER"]:
            return jsonify({"error": "Invalid gender"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for duplicate email
        cursor.execute("SELECT id FROM patient WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already registered"}), 409

        # Insert patient
        cursor.execute("""
            INSERT INTO patient (
                full_name, email, password, mobile, date_of_birth, gender,
                blood_group, address, emergency_contact, role, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            full_name, email, hashed_password, mobile, date_of_birth, gender,
            blood_group, address, emergency_contact, role
        ))
        conn.commit()

        # Fetch inserted patient ID
        cursor.execute("SELECT id FROM patient WHERE email = %s", (email,))
        patient = cursor.fetchone()
        conn.close()

        payload = {
            "patient_id": patient[0],
            "email": email,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "message": "✅ Registered successfully",
            "token": token
        }), 200

    except Exception as e:
        logging.exception("Register Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Login API
# ---------------------------
@patient_bp.route("/api/patient/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        email = data.get("email", "").lower()
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM patient WHERE email = %s", (email,))
        patient = cursor.fetchone()
        conn.close()

        if patient and bcrypt.checkpw(password.encode('utf-8'), patient['password'].encode('utf-8')):
            payload = {
                "patient_id": patient["id"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            return jsonify({
                "token": token,
                "patient": {
                    "id": patient["id"],
                    "name": patient["full_name"],
                    "email": patient["email"],
                    "role": patient["role"]
                }
            }), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        logging.exception("Login Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Profile API
# ---------------------------
@patient_bp.route("/api/patient/profile", methods=["GET"])
def get_profile():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing token"}), 401

    try:
        # Optional: If you’re sending "Bearer <token>"
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header

        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        doctor_id = decoded.get("doctor_id")  # must match token payload

        if not doctor_id:
            return jsonify({"error": "doctor_id not found in token"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, email, mobile FROM doctors WHERE id = %s", (doctor_id,))
        doctor = cursor.fetchone()
        conn.close()

        if doctor:
            return jsonify(doctor), 200
        else:
            return jsonify({"error": "Doctor not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
