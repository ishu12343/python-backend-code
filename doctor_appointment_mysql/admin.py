from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection
import random
import datetime
import re
import traceback

admin_bp = Blueprint("admin", __name__)

# ===== FORGOT PASSWORD ENDPOINTS =====

@admin_bp.route("/admin/forgot-password/send-otp", methods=["POST"])
def send_otp():
    """Send OTP for password reset - Works with registered admin email or mobile"""
    print("Admin forgot password send OTP endpoint called")
    data = request.get_json()
    identifier = data.get("identifier", "").strip()
    print(f"Identifier received: {identifier}")
    
    if not identifier:
        return jsonify({"success": False, "error": "Email or mobile number is required"}), 400
    
    try:
        print("Attempting database connection...")
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        print("Database connection successful")
        
        # Determine if identifier is email or mobile
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        mobile_pattern = r'^[0-9]{10}$'
        
        admin = None
        identifier_type = None
        
        if re.match(email_pattern, identifier):
            identifier_type = "email"
            cursor.execute("SELECT id, email, mobile, full_name FROM admin WHERE email = %s AND is_active = 1", (identifier,))
            admin = cursor.fetchone()
        elif re.match(mobile_pattern, identifier):
            identifier_type = "mobile"
            cursor.execute("SELECT id, email, mobile, full_name FROM admin WHERE mobile = %s AND is_active = 1", (identifier,))
            admin = cursor.fetchone()
            cursor.fetchall()  # Consume any remaining results
        else:
            return jsonify({"success": False, "error": "Please enter a valid email address or 10-digit mobile number"}), 400
        
        if not admin:
            error_msg = f"No admin account found with this {identifier_type}. Please use a registered {identifier_type}."
            return jsonify({"success": False, "error": error_msg}), 404
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=10)
        
        # Store OTP in database (replace any existing OTP)
        cursor.execute(
            "UPDATE admin SET reset_otp = %s, otp_expires_at = %s WHERE id = %s",
            (otp, expiry_time, admin['id'])
        )
        conn.commit()
        
        # In production, send OTP via Email/SMS service
        # For now, we'll just return success (OTP will be visible in logs for testing)
        print(f"OTP for admin {admin['full_name']}: {otp}")  # Remove in production
        
        cursor.close()
        conn.close()
        
        message = f"OTP sent to your registered {identifier_type}"
        if identifier_type == "mobile":
            message = "OTP sent to your registered mobile"
        else:
            message = "OTP sent to your registered email address"
        
        return jsonify({
            "success": True,
            "message": message,
            "identifier_type": identifier_type,
            "otp": otp  # Remove this in production
        }), 200
        
    except Exception as e:
        print(f"Send OTP error: {str(e)}")
        print(f"Error details: {traceback.format_exc()}")
        return jsonify({"success": False, "error": f"Failed to send OTP: {str(e)}"}), 500


@admin_bp.route("/admin/forgot-password/reset", methods=["POST"])
def reset_password():
    """Reset password using OTP"""
    data = request.get_json()
    identifier = data.get("identifier", "").strip()
    otp = data.get("otp", "").strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")
    
    if not all([identifier, otp, new_password, confirm_password]):
        return jsonify({"success": False, "error": "All fields are required"}), 400
    
    if new_password != confirm_password:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400
    
    if len(new_password) < 6:
        return jsonify({"success": False, "error": "Password must be at least 6 characters long"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Find admin by email or mobile and get stored OTP
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        mobile_pattern = r'^[0-9]{10}$'
        
        if re.match(email_pattern, identifier):
            cursor.execute(
                "SELECT id, email, mobile, full_name, reset_otp, otp_expires_at FROM admin WHERE email = %s AND is_active = 1", 
                (identifier,)
            )
        elif re.match(mobile_pattern, identifier):
            cursor.execute(
                "SELECT id, email, mobile, full_name, reset_otp, otp_expires_at FROM admin WHERE mobile = %s AND is_active = 1", 
                (identifier,)
            )
            cursor.fetchall()  # Consume any remaining results
        else:
            return jsonify({"success": False, "error": "Please enter a valid email address or 10-digit mobile number"}), 400
        
        admin = cursor.fetchone()
        
        if not admin:
            return jsonify({"success": False, "error": "No admin account found with this identifier"}), 404
        
        # Verify OTP exists and not expired
        if not admin['reset_otp'] or not admin['otp_expires_at']:
            return jsonify({"success": False, "error": "No OTP found. Please request a new OTP."}), 400
        
        if datetime.datetime.now() > admin['otp_expires_at']:
            # Clear expired OTP
            cursor.execute(
                "UPDATE admin SET reset_otp = NULL, otp_expires_at = NULL WHERE id = %s",
                (admin['id'],)
            )
            conn.commit()
            return jsonify({"success": False, "error": "OTP has expired. Please request a new one."}), 400
        
        if admin['reset_otp'] != otp:
            return jsonify({"success": False, "error": "Invalid OTP. Please check and try again."}), 400
        
        # Hash new password
        hashed_password = generate_password_hash(new_password)
        
        # Update password and clear OTP
        cursor.execute(
            "UPDATE admin SET password = %s, reset_otp = NULL, otp_expires_at = NULL WHERE id = %s",
            (hashed_password, admin['id'])
        )
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Password reset successfully. You can now login with your new password."
        }), 200
        
    except Exception as e:
        print(f"Reset password error: {str(e)}")
        print(f"Error details: {traceback.format_exc()}")
        return jsonify({"success": False, "error": "Failed to reset password"}), 500


# --- Admin Signup (No Token Required) ---
@admin_bp.route("/admin/create", methods=["POST"])
def admin_signup():
    data = request.get_json()
    full_name = data.get("full_name")
    email = data.get("email")
    mobile = data.get("mobile")
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
            "INSERT INTO admin (full_name, email, mobile, password, role, is_active, created_at) VALUES (%s, %s, %s, %s, %s, TRUE, NOW())",
            (full_name, email, mobile, hashed_password, role),
        )
        conn.commit()

        # Get the newly created admin
        cur.execute("""
            SELECT id, full_name, email, mobile, role, profile_photo, created_at 
            FROM admin 
            WHERE email = %s
        """, (email,))
        admin = cur.fetchone()

        token = create_access_token(identity=str(admin["id"]))

        return jsonify(
            message="Admin created successfully",
            token=token,
            admin={
                "id": admin["id"],
                "full_name": admin["full_name"],
                "username": admin["full_name"],
                "email": admin["email"],
                "mobile": admin["mobile"],
                "role": admin["role"],
                "profile_photo": admin["profile_photo"]
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
    identifier = data.get("email") or data.get("identifier")  # Support both email field and identifier field
    pwd = data.get("password")

    if not identifier or not pwd:
        return jsonify(error="Email/mobile and password are required"), 400

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    # Determine if identifier is email or mobile
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    mobile_pattern = r'^[0-9]{10}$'
    
    if re.match(email_pattern, identifier):
        cur.execute("""
            SELECT id, full_name, email, mobile, password, role, profile_photo, is_active 
            FROM admin 
            WHERE email = %s
        """, (identifier,))
    elif re.match(mobile_pattern, identifier):
        cur.execute("""
            SELECT id, full_name, email, mobile, password, role, profile_photo, is_active 
            FROM admin 
            WHERE mobile = %s
        """, (identifier,))
    else:
        conn.close()
        return jsonify(error="Please enter a valid email address or 10-digit mobile number"), 400
        
    user = cur.fetchone()
    
    if user and user["is_active"] and check_password_hash(user["password"], pwd):
        # Update last_login timestamp
        cur.execute("UPDATE admin SET last_login = NOW() WHERE id = %s", (user["id"],))
        conn.commit()
        conn.close()
        
        token = create_access_token(identity=str(user["id"]))
        return jsonify(
            token=token,
            admin={
                "id": user["id"],
                "full_name": user["full_name"],
                "username": user["full_name"],  # For header compatibility
                "email": user["email"],
                "mobile": user["mobile"],
                "role": user["role"],
                "profile_photo": user["profile_photo"]
            }
        ), 200
    
    conn.close()
    return jsonify(error="Invalid credentials or inactive account"), 401


# --- List Doctors ---
@admin_bp.route("/admin/doctors", methods=["GET"])
@jwt_required()
def list_doctors():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, approved, suspended, specialty, documents_verified FROM doctors")
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
             address, emergency_contact, role, is_active
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
    # Approve the doctor and update status to ACTIVE
    cur.execute("UPDATE doctors SET approved=1, suspended=0, status='ACTIVE' WHERE id=%s", (doc_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Doctor approved"), 200


# --- Reject Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/reject", methods=["PUT"])
@jwt_required()
def reject_doctor(doc_id):
    conn = get_db_connection()
    cur = conn.cursor()
    # Reject the doctor and update status to INACTIVE
    cur.execute("UPDATE doctors SET approved=0, suspended=0, status='INACTIVE' WHERE id=%s", (doc_id,))
    conn.commit()
    conn.close()
    return jsonify(message="Doctor rejected"), 200


# --- Suspend Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/suspend", methods=["PUT"])
@jwt_required()
def suspend_doctor(doc_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Suspend the doctor and update status to SUSPENDED
        cur.execute("UPDATE doctors SET suspended=1, status='SUSPENDED' WHERE id=%s", (doc_id,))
        
        if cur.rowcount == 0:
            conn.close()
            return jsonify(error="Doctor not found"), 404
        
        conn.commit()
        conn.close()
        return jsonify(message="Doctor suspended successfully"), 200
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify(error="Failed to suspend doctor", details=str(e)), 500


# --- Unsuspend Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/unsuspend", methods=["PUT"])
@jwt_required()
def unsuspend_doctor(doc_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Unsuspend the doctor and restore to ACTIVE status if approved
        cur.execute("""
            UPDATE doctors 
            SET suspended=0, 
                status=CASE 
                    WHEN approved=1 THEN 'ACTIVE' 
                    ELSE 'INACTIVE' 
                END 
            WHERE id=%s
        """, (doc_id,))
        
        if cur.rowcount == 0:
            conn.close()
            return jsonify(error="Doctor not found"), 404
        
        conn.commit()
        conn.close()
        return jsonify(message="Doctor unsuspended successfully"), 200
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify(error="Failed to unsuspend doctor", details=str(e)), 500


# --- List Patients ---
@admin_bp.route("/admin/patients", methods=["GET"])
@jwt_required()
def list_patients():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, mobile, role, gender, is_active FROM patient")
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


# --- Delete Doctor ---
@admin_bp.route("/admin/doctors/<int:doc_id>/delete", methods=["DELETE"])
@jwt_required()
def delete_doctor(doc_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if doctor exists
        cur.execute("SELECT id FROM doctors WHERE id = %s", (doc_id,))
        doctor = cur.fetchone()
        
        if not doctor:
            conn.close()
            return jsonify(error="Doctor not found"), 404
        
        # Delete the doctor (this will cascade to related records if foreign keys are set up)
        cur.execute("DELETE FROM doctors WHERE id = %s", (doc_id,))
        
        if cur.rowcount == 0:
            conn.close()
            return jsonify(error="Failed to delete doctor"), 500
        
        conn.commit()
        conn.close()
        return jsonify(message="Doctor deleted successfully"), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify(error="Failed to delete doctor", details=str(e)), 500


# --- Delete Patient ---
@admin_bp.route("/admin/patients/<int:pat_id>/delete", methods=["DELETE"])
@jwt_required()
def delete_patient(pat_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if patient exists
        cur.execute("SELECT id FROM patient WHERE id = %s", (pat_id,))
        patient = cur.fetchone()
        
        if not patient:
            conn.close()
            return jsonify(error="Patient not found"), 404
        
        # Delete the patient (this will cascade to related records if foreign keys are set up)
        cur.execute("DELETE FROM patient WHERE id = %s", (pat_id,))
        
        if cur.rowcount == 0:
            conn.close()
            return jsonify(error="Failed to delete patient"), 500
        
        conn.commit()
        conn.close()
        return jsonify(message="Patient deleted successfully"), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify(error="Failed to delete patient", details=str(e)), 500


# --- Admin Profile ---
@admin_bp.route("/admin/profile", methods=["GET"])
@jwt_required()
def get_admin_profile():
    try:
        admin_id = get_jwt_identity()
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, full_name, email, mobile, role, profile_photo, 
                   created_at, last_login
            FROM admin 
            WHERE id = %s AND is_active = TRUE
        """, (admin_id,))
        admin = cur.fetchone()
        conn.close()
        
        if not admin:
            return jsonify(error="Admin not found"), 404
            
        return jsonify(admin), 200
    except Exception as e:
        return jsonify(error="Failed to fetch admin profile", details=str(e)), 500

# --- Update Admin Profile ---
@admin_bp.route("/admin/profile/update", methods=["PUT"])
@jwt_required()
def update_admin_profile():
    try:
        admin_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify(error="No data provided"), 400
        
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        
        # Define updatable fields
        updatable_fields = ["full_name", "email", "mobile", "profile_photo"]
        
        update_fields = []
        update_values = []
        
        for field in updatable_fields:
            if field in data and data[field] is not None:
                update_fields.append(f"{field} = %s")
                update_values.append(data[field])
            elif field in data and data[field] is None and field == "profile_photo":
                # Handle explicit removal of profile photo
                update_fields.append(f"{field} = %s")
                update_values.append(None)
                update_fields.append(f"{field} = %s")
                update_values.append(data[field])
        
        if not update_fields:
            conn.close()
            return jsonify(error="No valid fields to update"), 400
        
        # Add admin_id to values for WHERE clause
        update_values.append(admin_id)
        
        # Build and execute update query
        query = f"UPDATE admin SET {', '.join(update_fields)} WHERE id = %s AND is_active = TRUE"
        cur.execute(query, update_values)
        
        if cur.rowcount == 0:
            conn.close()
            return jsonify(error="Admin not found or no changes made"), 404
        
        conn.commit()
        
        # Fetch updated admin data
        cur.execute("""
            SELECT id, full_name, email, mobile, role, profile_photo, created_at, last_login
            FROM admin 
            WHERE id = %s AND is_active = TRUE
        """, (admin_id,))
        updated_admin = cur.fetchone()
        conn.close()
        
        if not updated_admin:
            return jsonify(error="Failed to fetch updated admin data"), 500
        
        return jsonify(
            message="Admin profile updated successfully",
            admin=updated_admin
        ), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return jsonify(error="Failed to update admin profile", details=str(e)), 500

@admin_bp.route("/api/admin/logout", methods=["POST"])
@jwt_required()
def admin_logout():
    jti = get_jwt()["jti"]
    from app import blacklist
    blacklist.add(jti)
    return jsonify(message="Admin logged out successfully. Token revoked."), 200
