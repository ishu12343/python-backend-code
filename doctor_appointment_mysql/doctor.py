from flask import Blueprint, request, jsonify
from db import get_db_connection
import bcrypt
import datetime
import os
import traceback
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt, unset_jwt_cookies
)

SECRET_KEY = os.environ.get("SECRET_KEY", "your_dev_secret")

doctor_bp = Blueprint("doctor", __name__, url_prefix="/api/doctor")


# REGISTER
@doctor_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        hashed_password = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())

        query = """
            INSERT INTO doctors (
                full_name, email, password, mobile, gender, location, registration_number,
                council, degree, specialty, experience, clinic_name, clinic_address,
                profile_photo, role, dob, blood_group, available_days,
                available_from, available_to, city, state, zip_code,
                languages, status, documents, created_at, updated_at
            ) VALUES (
                %(full_name)s, %(email)s, %(password)s, %(mobile)s, %(gender)s, %(location)s,
                %(registration_number)s, %(council)s, %(degree)s, %(specialty)s, %(experience)s,
                %(clinic_name)s, %(clinic_address)s, %(profile_photo)s, %(role)s,
                %(dob)s, %(blood_group)s, %(available_days)s, %(available_from)s,
                %(available_to)s, %(city)s, %(state)s, %(zip_code)s, %(languages)s,
                %(status)s, %(documents)s, NOW(), NOW()
            )
        """
        doctor_data = {
            "full_name": data["full_name"],
            "email": data["email"],
            "password": hashed_password.decode("utf-8"),
            "mobile": data["mobile"],
            "gender": data["gender"],
            "location": data["location"],
            "registration_number": data["registration_number"],
            "council": data["council"],
            "degree": data["degree"],
            "specialty": data["specialty"],
            "experience": data["experience"],
            "clinic_name": data["clinic_name"],
            "clinic_address": data["clinic_address"],
            "profile_photo": data.get("profile_photo", ""),
            "role": data.get("role", "DOCTOR"),
            "dob": data.get("dob"),
            "blood_group": data.get("blood_group"),
            "available_days": data.get("available_days"),
            "available_from": data.get("available_from"),
            "available_to": data.get("available_to"),
            "city": data.get("city"),
            "state": data.get("state"),
            "zip_code": data.get("zip_code"),
            "languages": data.get("languages"),
            "status": data.get("status", "ACTIVE"),
            "documents": data.get("documents", "")
        }

        cursor.execute(query, doctor_data)
        doctor_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()

        access_token = create_access_token(
            identity=str(doctor_id),
            additional_claims={"role": "DOCTOR"},
            expires_delta=datetime.timedelta(days=1)
        )

        return jsonify({
            "token": access_token,
            "doctor": {
                "id": doctor_id,
                "full_name": data["full_name"],
                "email": data["email"],
                "mobile": data["mobile"],
                "role": "DOCTOR"
            }
        }), 201

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Registration failed", "details": str(e)}), 400


# LOGIN
@doctor_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM doctors WHERE email = %s", (data["email"],))
        doctor = cursor.fetchone()

        if doctor and bcrypt.checkpw(data["password"].encode("utf-8"), doctor["password"].encode("utf-8")):
            access_token = create_access_token(
                identity=str(doctor["id"]),
                additional_claims={"role": "DOCTOR"},
                expires_delta=datetime.timedelta(days=1)
            )

            cursor.close()
            conn.close()

            return jsonify({
                "token": access_token,
                "doctor": {
                    "id": doctor["id"],
                    "full_name": doctor["full_name"],
                    "email": doctor["email"],
                    "mobile": doctor["mobile"],
                    "role": doctor["role"]
                }
            }), 200

        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Login failed", "details": str(e)}), 400


# LOGOUT
@doctor_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    response = jsonify({"message": "Doctor logged out successfully"})
    unset_jwt_cookies(response)
    return response, 200


# PROFILE
@doctor_bp.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        doctor_id = int(get_jwt_identity())

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM doctors WHERE id = %s", (doctor_id,))
        doctor = cursor.fetchone()
        cursor.close()
        conn.close()

        if not doctor:
            return jsonify({"error": "Doctor not found"}), 404

        # Remove password
        doctor.pop("password", None)

        # Convert timedelta fields to "HH:MM"
        for key in ["available_from", "available_to", "experience"]:
            if isinstance(doctor.get(key), datetime.timedelta):
                total_seconds = int(doctor[key].total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                doctor[key] = f"{hours:02d}:{minutes:02d}"

        return jsonify(doctor), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch profile", "details": str(e)}), 500
