from flask import Blueprint, request, jsonify
from db import get_db_connection
import bcrypt
import jwt
import datetime
import os

SECRET_KEY = os.environ.get("SECRET_KEY", "default_dev_secret")

doctor_bp = Blueprint("doctor", __name__, url_prefix="/api/doctor")

# ===========================
# POST /api/doctor/register
# ===========================
@doctor_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        full_name = data.get("fullName")
        email = data.get("email")
        password = data.get("password")
        mobile = data.get("mobile")
        location = data.get("location")
        registration_number = data.get("registrationNumber")
        council = data.get("council")
        degree = data.get("degree")
        specialty = data.get("specialty")
        experience = data.get("experience")
        clinic_name = data.get("clinicName")
        clinic_address = data.get("clinicAddress")
        role = data.get("role", "DOCTOR")

        # Required fields validation
        if not all([full_name, email, password, mobile]):
            return jsonify({"error": "Missing required fields: fullName, email, password, mobile"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if email already exists
        cursor.execute("SELECT id FROM doctors WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Email already registered"}), 409

        # Insert new doctor
        cursor.execute("""
            INSERT INTO doctors (
                full_name, email, password, mobile, location,
                registration_number, council, degree, specialty, experience,
                clinic_name, clinic_address, role, approved, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, NOW(), NOW())
        """, (
            full_name, email, hashed_password, mobile, location,
            registration_number, council, degree, specialty, experience,
            clinic_name, clinic_address, role
        ))
        conn.commit()

        # Get inserted doctor ID
        cursor.execute("SELECT id FROM doctors WHERE email = %s", (email,))
        doctor = cursor.fetchone()
        conn.close()

        if not doctor:
            return jsonify({"error": "Doctor registration failed, try again"}), 500

        payload = {
            "doctor_id": doctor[0],
            "email": email,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "message": "✅ Doctor registered successfully",
            "token": token
        }), 201

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# =======================
# POST /api/doctor/login
# =======================
@doctor_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM doctors WHERE email = %s", (email,))
        doctor = cursor.fetchone()
        conn.close()

        if not doctor:
            return jsonify({"error": "Doctor with this email does not exist"}), 404

        if not bcrypt.checkpw(password.encode('utf-8'), doctor["password"].encode('utf-8')):
            return jsonify({"error": "Invalid email or password"}), 401

        payload = {
            "doctor_id": doctor["id"],
            "email": doctor["email"],
            "role": doctor["role"],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "message": "✅ Login successful",
            "token": token,
            "doctor": {
                "id": doctor["id"],
                "name": doctor["full_name"],
                "email": doctor["email"],
                "role": doctor["role"]
            }
        }), 200

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# =========================
# GET /api/doctor/profile
# =========================
@doctor_bp.route("/profile", methods=["GET"])
def get_profile():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "Missing Authorization header"}), 401

    if token.startswith("Bearer "):
        token = token.split(" ")[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        doctor_id = decoded["doctor_id"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, full_name, email, mobile, location, council, specialty, experience,
                   clinic_name, clinic_address, registration_number, approved, role
            FROM doctors WHERE id = %s
        """, (doctor_id,))
        doctor = cursor.fetchone()
        conn.close()

        if doctor:
            return jsonify(doctor), 200
        else:
            return jsonify({"error": "Doctor not found"}), 404

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve profile: {str(e)}"}), 500
