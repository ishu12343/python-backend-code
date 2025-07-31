from flask import Blueprint, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, jwt_required, get_jwt
)
from db import get_db_connection
import bcrypt
import datetime
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

patient_bp = Blueprint("patient", __name__)
CORS(patient_bp)

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

        if not all([full_name, email, password, mobile]):
            return jsonify({"error": "Missing required fields"}), 400

        email_regex = r"[^@]+@[^@]+\.[^@]+"
        if not re.match(email_regex, email):
            return jsonify({"error": "Invalid email format"}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        if date_of_birth:
            try:
                datetime.datetime.strptime(date_of_birth, "%Y-%m-%d")
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        if role not in ["PATIENT", "DOCTOR"]:
            return jsonify({"error": "Invalid role"}), 400

        if gender and gender.upper() not in ["MALE", "FEMALE", "OTHER"]:
            return jsonify({"error": "Invalid gender"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM patient WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already registered"}), 409

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

        cursor.execute("SELECT id FROM patient WHERE email = %s", (email,))
        patient = cursor.fetchone()
        conn.close()

        access_token = create_access_token(
            identity=str(patient[0]),
            additional_claims={"email": email, "role": role}
        )

        return jsonify({
            "message": "✅ Registered successfully",
            "token": access_token
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
            access_token = create_access_token(
                identity=str(patient["id"]),
                additional_claims={
                    "email": patient["email"],
                    "role": patient["role"]
                }
            )

            return jsonify({
                "message": "✅ Login successful",
                "token": access_token,
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
@jwt_required()
def get_profile():
    try:
        patient_id = get_jwt_identity()
        claims = get_jwt()
        email = claims.get("email")
        role = claims.get("role")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, full_name, email, mobile FROM patient WHERE id = %s", (patient_id,))
        patient = cursor.fetchone()
        conn.close()

        if patient:
            return jsonify({
                "patient": patient,
                "email": email,
                "role": role
            }), 200
        else:
            return jsonify({"error": "Patient not found"}), 404

    except Exception as e:
        logging.exception("Profile Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500


# ---------------------------
# Logout API
# ---------------------------
@patient_bp.route("/api/patient/logout", methods=["POST"])
@jwt_required()
def patient_logout():
    try:
        jti = get_jwt()["jti"]
        from app import blacklist
        blacklist.add(jti)
        return jsonify(message="✅ Patient logged out successfully. Token revoked."), 200
    except Exception as e:
        logging.exception("Logout Error")
        return jsonify({"error": "Something went wrong. Please try again later."}), 500
