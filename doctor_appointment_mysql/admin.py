from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
from doctor_appointment_mysql.patient import patient_bp

admin_bp = Blueprint("admin", __name__)

# --- Admin Signup (No Token Required) ---
@admin_bp.route("/admin/create", methods=["POST"])
def admin_signup():
    data = request.get_json()
    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "ADMIN")  # Default role is ADMIN

    if not full_name or not email or not password:
        return jsonify(error="Missing required fields"), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Check if email already exists
    cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
    existing_admin = cur.fetchone()
    if existing_admin:
        conn.close()
        return jsonify(error="Admin with this email already exists"), 409

    try:
        cur.execute(
            "INSERT INTO admin (full_name, email, password, role, is_active) VALUES (%s, %s, %s, %s, TRUE)",
            (full_name, email, hashed_password, role),
        )
        conn.commit()

        # Get the newly created admin
        cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
        admin = cur.fetchone()

        token = create_access_token(identity=str(admin["id"]))

        return jsonify(
            message="Admin created successfully",
            token=token,
            admin={
                "id": admin["id"],
                "name": admin["full_name"],
                "email": admin["email"],
                "role": admin["role"]
            }
        ), 201

    except Exception as e:
        conn.rollback()
        return jsonify(error=str(e)), 500
    finally:
        conn.close()


# --- Admin Login (Returns JWT Token) ---
@admin_bp.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    email = data.get("email")
    pwd = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
    user = cur.fetchone()
    conn.close()

    if user and user["is_active"] and check_password_hash(user["password"], pwd):
        token = create_access_token(identity=str(user["id"]))
        return jsonify(
            token=token,
            admin={
                "id": user["id"],
                "name": user["full_name"],
                "email": user["email"],
                "role": user["role"]
            }
        ), 200
    return jsonify(error="Invalid credentials or inactive account"), 401


# --- List Doctors ---
@admin_bp.route("/admin/doctors", methods=["GET"])
@jwt_required()
def list_doctors():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, approved, suspended, documents_verified FROM doctors")
    doctors = cur.fetchall()
    conn.close()
    return jsonify(doctors), 200


# --- View Doctors Details---
@admin_bp.route("/admin/doctors/view", methods=["GET"])
@jwt_required()
def view_doctors():
    try:
        doctor_id = request.args.get("id")  # Get ?id= from URL
        if not doctor_id:
            return jsonify(success=False, error="Doctor ID is required"), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, full_name, email, mobile, location,
                   registration_number, council, degree, specialty,
                   experience, clinic_name, clinic_address, role,
                   approved, suspended, documents_verified
            FROM doctors
            WHERE id = %s
        """, (doctor_id,))
        doctor = cur.fetchone()
        conn.close()

        if not doctor:
            return jsonify(success=False, error="Doctor not found"), 404

        return jsonify(success=True, data=doctor), 200

    except Exception as e:
        return jsonify(success=False, error="Failed to fetch doctor", details=str(e)), 500


# --- View Patient Details ---
@admin_bp.route("/admin/patient/view", methods=["GET"])
@jwt_required()
def view_patient():
    try:
        patient_id = request.args.get("id")  # Get ?id= from URL
        if not patient_id:
            return jsonify(success=False, error="Patient ID is required"), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, full_name, email, mobile, date_of_birth, gender, blood_group,
             address, emergency_contact, role
            FROM patient
            WHERE id = %s
        """, (patient_id,))
        patient = cur.fetchone()
        conn.close()
        if not patient:
            return jsonify(success=False, error="Patient not found"), 404

        return jsonify(success=True, data=patient), 200

    except Exception as e:
        return jsonify(success=False, error="Failed to fetch doctor", details=str(e)), 500


# --- Approve Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/approve", methods=["PUT"])
@jwt_required()
def approve_doctor(doc_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE doctors SET approved=1 WHERE id=%s", (doc_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Doctor approved"), 200


# --- Reject Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/reject", methods=["PUT"])
@jwt_required()
def reject_doctor(doc_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE doctors SET approved=0 WHERE id=%s", (doc_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Doctor rejected"), 200


# --- List Patients ---
@admin_bp.route("/admin/patients", methods=["GET"])
@jwt_required()
def list_patients():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, mobile, is_active FROM patient")
    patients = cur.fetchall()
    conn.close()
    return jsonify(patients), 200


# --- Deactivate Patient ---
@admin_bp.route("/admin/patients/<int:pat_id>/deactivate", methods=["PUT"])
@jwt_required()
def deactivate_patient(pat_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE patient SET is_active=FALSE WHERE id=%s", (pat_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Patient deactivated"), 200

@admin_bp.route("/admin/patients/<int:pat_id>/activate", methods=["PUT"])
@jwt_required()
def activate_patient(pat_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE patient SET is_active=TRUE WHERE id=%s", (pat_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Patient activated"), 200
