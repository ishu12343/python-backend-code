import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, get_jwt
)
from db import get_db_connection
import bcrypt
import datetime

doctor_bp = Blueprint("doctor", __name__, url_prefix="/api/doctor")

# ---------------------------
# Register API
# ---------------------------
@doctor_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        full_name = data.get("fullName")
        email = data.get("email", "").lower()
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

        if not all([full_name, email, password, mobile]):
            return jsonify({"error": "Missing required fields"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM doctors WHERE email = %s", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "Email already registered"}), 409

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

        cursor.execute("SELECT id FROM doctors WHERE email = %s", (email,))
        doctor = cursor.fetchone()
        conn.close()

        if not doctor:
            return jsonify({"error": "Registration failed"}), 500

        access_token = create_access_token(
            identity=str(doctor[0]),
            additional_claims={"email": email, "role": role}
        )

        return jsonify({
            "message": "✅ Doctor registered successfully",
            "token": access_token
        }), 201

    except Exception as e:
        logging.exception("Register Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Login API
# ---------------------------
@doctor_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400

        email = data.get("email", "").lower()
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM doctors WHERE email = %s", (email,))
        doctor = cursor.fetchone()
        conn.close()

        if not doctor or not bcrypt.checkpw(password.encode('utf-8'), doctor["password"].encode('utf-8')):
            return jsonify({"error": "Invalid email or password"}), 401

        access_token = create_access_token(
            identity=str(doctor["id"]),
            additional_claims={
                "email": doctor["email"],
                "role": doctor["role"]
            }
        )

        return jsonify({
            "message": "✅ Login successful",
            "token": access_token,
            "doctor": {
                "id": doctor["id"],
                "name": doctor["full_name"],
                "email": doctor["email"],
                "role": doctor["role"]
            }
        }), 200

    except Exception as e:
        logging.exception("Login Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Profile API
# ---------------------------
@doctor_bp.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        doctor_id = get_jwt_identity()
        claims = get_jwt()
        email = claims.get("email")
        role = claims.get("role")

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
            return jsonify({
                "doctor": doctor,
                "email": email,
                "role": role
            }), 200
        else:
            return jsonify({"error": "Doctor not found"}), 404

    except Exception as e:
        logging.exception("Profile Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Logout API
# ---------------------------
@doctor_bp.route("/logout", methods=["POST"])
@jwt_required()
def doctor_logout():
    try:
        jti = get_jwt()["jti"]
        from app import blacklist
        blacklist.add(jti)
        return jsonify(message="✅ Doctor logged out successfully. Token revoked."), 200
    except Exception as e:
        logging.exception("Logout Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500
