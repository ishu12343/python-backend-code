from flask import Blueprint, request, jsonify
from db import get_db_connection
import bcrypt
import datetime
import os
import traceback
import random
import re
from flask_jwt_extended import (
    jwt_required, create_access_token,
    get_jwt_identity, unset_jwt_cookies
)

SECRET_KEY = os.environ.get("SECRET_KEY", "your_dev_secret")

doctor_bp = Blueprint("doctor", __name__, url_prefix="/api/doctor")


# ===== FORGOT PASSWORD ENDPOINTS =====

@doctor_bp.route("/forgot-password/send-otp", methods=["POST"])
def send_otp():
    """Send OTP for password reset - Only works with registered doctor emails/mobiles"""
    print("Doctor forgot password send OTP endpoint called")
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
        
        # Check if it's email or mobile
        is_email = "@" in identifier
        
        if is_email:
            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, identifier):
                return jsonify({"success": False, "error": "Invalid email format"}), 400
            
            # Check if doctor exists with this email (approved doctors only)
            cursor.execute(
                "SELECT id, email, full_name, approved, suspended FROM doctors WHERE email = %s", 
                (identifier,)
            )
            identifier_type = "email"
        else:
            # Validate mobile format (assuming 10 digits)
            mobile_pattern = r'^[+]?[0-9]{10,15}$'
            if not re.match(mobile_pattern, identifier.replace("-", "").replace(" ", "")):
                return jsonify({"success": False, "error": "Invalid mobile number format"}), 400
            
            # Check if doctor exists with this mobile (approved doctors only)
            cursor.execute(
                "SELECT id, mobile, full_name, approved, suspended FROM doctors WHERE mobile = %s", 
                (identifier,)
            )
            identifier_type = "mobile"
        
        doctor = cursor.fetchone()
        
        # Consume any remaining results to avoid "Unread result found" error
        try:
            cursor.fetchall()
        except Exception:
            pass
        
        if not doctor:
            return jsonify({"success": False, "error": f"No doctor account found with this {identifier_type}. Please use a registered {identifier_type} address."}), 404
        
        # Check if doctor is approved and not suspended
        if not doctor.get('approved'):
            return jsonify({"success": False, "error": "Your doctor account is pending approval. Please contact admin."}), 403
        
        if doctor.get('suspended'):
            return jsonify({"success": False, "error": "Your doctor account is suspended. Please contact admin."}), 403
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=10)
        
        # Store OTP in database (replace any existing OTP)
        cursor.execute(
            "UPDATE doctors SET reset_otp = %s, otp_expires_at = %s WHERE id = %s",
            (otp, expiry_time, doctor['id'])
        )
        conn.commit()
        
        # In production, send OTP via SMS/Email service
        # For now, we'll just return success (OTP will be visible in logs for testing)
        print(f"OTP for doctor {doctor['full_name']}: {otp}")  # Remove in production
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"OTP sent to your registered {identifier_type}",
            "identifier_type": identifier_type,
            "otp": otp  # Remove this in production
        }), 200
        
    except Exception as e:
        print(f"Send OTP error: {str(e)}")
        print(f"Error details: {traceback.format_exc()}")
        return jsonify({"success": False, "error": f"Failed to send OTP: {str(e)}"}), 500


@doctor_bp.route("/forgot-password/reset", methods=["POST"])
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
        
        # Find doctor by identifier and get stored OTP
        is_email = "@" in identifier
        
        if is_email:
            cursor.execute(
                "SELECT id, email, full_name, reset_otp, otp_expires_at, approved, suspended FROM doctors WHERE email = %s", 
                (identifier,)
            )
        else:
            cursor.execute(
                "SELECT id, mobile, full_name, reset_otp, otp_expires_at, approved, suspended FROM doctors WHERE mobile = %s", 
                (identifier,)
            )
        
        doctor = cursor.fetchone()
        
        if not doctor:
            return jsonify({"success": False, "error": "Doctor not found"}), 404
        
        # Check if doctor is approved and not suspended
        if not doctor.get('approved'):
            return jsonify({"success": False, "error": "Your doctor account is pending approval. Please contact admin."}), 403
        
        if doctor.get('suspended'):
            return jsonify({"success": False, "error": "Your doctor account is suspended. Please contact admin."}), 403
        
        # Verify OTP exists and not expired
        if not doctor['reset_otp'] or not doctor['otp_expires_at']:
            return jsonify({"success": False, "error": "No OTP found. Please request a new OTP."}), 400
        
        if datetime.datetime.now() > doctor['otp_expires_at']:
            # Clear expired OTP
            cursor.execute(
                "UPDATE doctors SET reset_otp = NULL, otp_expires_at = NULL WHERE id = %s",
                (doctor['id'],)
            )
            conn.commit()
            return jsonify({"success": False, "error": "OTP has expired. Please request a new one."}), 400
        
        if doctor['reset_otp'] != otp:
            return jsonify({"success": False, "error": "Invalid OTP. Please check and try again."}), 400
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
        
        # Update password and clear OTP
        cursor.execute(
            "UPDATE doctors SET password = %s, reset_otp = NULL, otp_expires_at = NULL, updated_at = NOW() WHERE id = %s",
            (hashed_password.decode("utf-8"), doctor['id'])
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
            "license_number": data["license_number"],
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
            # Check if doctor is approved and not suspended
            if not doctor.get("approved"):
                cursor.close()
                conn.close()
                return jsonify({"error": "Your account is pending approval by the admin. Please wait for approval."}), 403
            
            if doctor.get("suspended"):
                cursor.close()
                conn.close()
                return jsonify({"error": "Your account has been suspended by the admin. Please contact support."}), 403

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
                    "role": doctor["role"],
                    "approved": doctor["approved"],
                    "suspended": doctor["suspended"]
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
        
        if not doctor:
            cursor.close()
            conn.close()
            return jsonify({"error": "Doctor not found"}), 404

        # Sync the status field based on approval and suspension status
        new_status = 'INACTIVE'  # default
        if doctor.get('suspended'):
            new_status = 'SUSPENDED'
        elif doctor.get('approved'):
            new_status = 'ACTIVE'
        else:
            new_status = 'PENDING'
        
        # Update the status if it's different
        if doctor.get('status') != new_status:
            cursor.execute("UPDATE doctors SET status=%s WHERE id=%s", (new_status, doctor_id))
            conn.commit()
            doctor['status'] = new_status

        cursor.close()
        conn.close()

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

@doctor_bp.route("/profile/update", methods=["PUT"])
@jwt_required()
def update_profile():
    try:
        doctor_id = int(get_jwt_identity())
        data = request.get_json()
        
        print(f"Updating profile for doctor_id: {doctor_id}")
        print(f"Received data keys: {list(data.keys())}")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        fields = [
            "full_name", "email", "mobile", "gender", "location", "registration_number", 
            "council", "degree", "specialty", "experience", "clinic_name", "clinic_address",
            "profile_photo", "dob", "blood_group", "available_days", "available_from",
            "available_to", "city", "state", "zip_code", "languages", "status", "documents", "license_number"
        ]

        updates = []
        values = []

        for field in fields:
            if field in data and data[field] is not None:
                updates.append(f"{field} = %s")
                values.append(data[field])
                if field == "profile_photo" and data[field]:
                    print(f"Profile photo data length: {len(str(data[field]))}")

        if not updates:
            return jsonify({"error": "No fields to update"}), 400

        values.append(doctor_id)

        query = f"""
            UPDATE doctors SET {', '.join(updates)}, updated_at = NOW()
            WHERE id = %s
        """
        
        print(f"Executing query with {len(updates)} updates")
        cursor.execute(query, tuple(values))
        conn.commit()
        
        print(f"Profile updated successfully for doctor_id: {doctor_id}")
        
        cursor.close()
        conn.close()

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        print(f"Error in update_profile: {str(e)}")
        traceback.print_exc()
        return jsonify({"error": "Profile update failed", "details": str(e)}), 500


# APPOINTMENT MANAGEMENT ENDPOINTS

@doctor_bp.route("/appointments", methods=["GET"])
@jwt_required()
def get_appointments():
    """Get all appointments for the logged-in doctor"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT 
                a.id,
                a.appointment_datetime,
                a.reason,
                a.status,
                a.created_at,
                p.full_name as patient_name,
                p.email as patient_email,
                p.mobile as patient_phone,
                p.blood_group as patient_blood_group,
                p.gender as patient_gender
            FROM appointments a
            JOIN patient p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_datetime DESC
        """
        
        cursor.execute(query, (doctor_id,))
        appointments = cursor.fetchall()
        
        # Convert datetime objects to strings
        for appointment in appointments:
            if appointment['appointment_datetime']:
                appointment['appointment_datetime'] = appointment['appointment_datetime'].strftime('%Y-%m-%d %H:%M:%S')
            if appointment['created_at']:
                appointment['created_at'] = appointment['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "appointments": appointments
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch appointments",
            "details": str(e)
        }), 500


@doctor_bp.route("/appointments/<int:appointment_id>/approve", methods=["POST"])
@jwt_required()
def approve_appointment(appointment_id):
    """Approve a pending appointment"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this doctor
        verify_query = """
            SELECT id, status FROM appointments 
            WHERE id = %s AND doctor_id = %s
        """
        cursor.execute(verify_query, (appointment_id, doctor_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] != 'PENDING':
            return jsonify({
                "success": False,
                "error": "Only pending appointments can be approved"
            }), 400

        # Update appointment status to CONFIRMED
        update_query = """
            UPDATE appointments 
            SET status = 'CONFIRMED'
            WHERE id = %s
        """
        cursor.execute(update_query, (appointment_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment approved successfully"
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to approve appointment",
            "details": str(e)
        }), 500


@doctor_bp.route("/appointments/<int:appointment_id>/reject", methods=["POST"])
@jwt_required()
def reject_appointment(appointment_id):
    """Reject/Cancel a pending appointment"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this doctor
        verify_query = """
            SELECT id, status FROM appointments 
            WHERE id = %s AND doctor_id = %s
        """
        cursor.execute(verify_query, (appointment_id, doctor_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] not in ['PENDING', 'CONFIRMED']:
            return jsonify({
                "success": False,
                "error": "Only pending or confirmed appointments can be rejected"
            }), 400

        # Update appointment status to CANCELLED
        update_query = """
            UPDATE appointments 
            SET status = 'CANCELLED'
            WHERE id = %s
        """
        cursor.execute(update_query, (appointment_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment rejected successfully"
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to reject appointment",
            "details": str(e)
        }), 500


@doctor_bp.route("/appointments/<int:appointment_id>/complete", methods=["POST"])
@jwt_required()
def complete_appointment(appointment_id):
    """Mark a confirmed appointment as completed"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this doctor
        verify_query = """
            SELECT id, status FROM appointments 
            WHERE id = %s AND doctor_id = %s
        """
        cursor.execute(verify_query, (appointment_id, doctor_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] != 'CONFIRMED':
            return jsonify({
                "success": False,
                "error": "Only confirmed appointments can be marked as completed"
            }), 400

        # Update appointment status to COMPLETED
        update_query = """
            UPDATE appointments 
            SET status = 'COMPLETED'
            WHERE id = %s
        """
        cursor.execute(update_query, (appointment_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment marked as completed"
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to complete appointment",
            "details": str(e)
        }), 500


@doctor_bp.route("/appointments/<int:appointment_id>/reschedule", methods=["POST"])
@jwt_required()
def reschedule_appointment(appointment_id):
    """Reschedule an appointment to a new date and time"""
    try:
        doctor_id = get_jwt_identity()
        data = request.get_json()
        
        print(f"Reschedule request for appointment {appointment_id} by doctor {doctor_id}")
        print(f"Request data: {data}")
        
        # Validate required fields
        if not data or not data.get('new_date') or not data.get('new_time'):
            return jsonify({
                "success": False,
                "error": "New date and time are required"
            }), 400
        
        # Validate date and time format
        try:
            from datetime import datetime
            new_date = data['new_date']
            new_time = data['new_time']
            
            # Validate date format (YYYY-MM-DD)
            datetime.strptime(new_date, '%Y-%m-%d')
            
            # Validate time format (HH:MM)
            datetime.strptime(new_time, '%H:%M')
            
            # Check if the new datetime is in the future
            new_datetime_str = f"{new_date} {new_time}:00"
            new_datetime = datetime.strptime(new_datetime_str, '%Y-%m-%d %H:%M:%S')
            
            if new_datetime <= datetime.now():
                return jsonify({
                    "success": False,
                    "error": "New appointment time must be in the future"
                }), 400
                
        except ValueError as e:
            return jsonify({
                "success": False,
                "error": f"Invalid date or time format: {str(e)}"
            }), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this doctor
        verify_query = """
            SELECT id, status, appointment_datetime FROM appointments 
            WHERE id = %s AND doctor_id = %s
        """
        cursor.execute(verify_query, (appointment_id, doctor_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] not in ['PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED']:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Appointment cannot be rescheduled"
            }), 400

        # Combine new date and time
        new_datetime_final = f"{data['new_date']} {data['new_time']}:00"
        
        # Update appointment with new datetime
        update_query = """
            UPDATE appointments 
            SET appointment_datetime = %s, 
                status = 'CONFIRMED'
            WHERE id = %s
        """
        cursor.execute(update_query, (new_datetime_final, appointment_id))
        conn.commit()
        
        print(f"Appointment {appointment_id} rescheduled to {new_datetime_final}")
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment rescheduled successfully",
            "new_datetime": new_datetime_final,
            "appointment_id": appointment_id
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to reschedule appointment",
            "details": str(e)
        }), 500


@doctor_bp.route("/appointments/stats", methods=["GET"])
@jwt_required()
def get_appointment_stats():
    """Get appointment statistics for the doctor"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get overall stats
        stats_query = """
            SELECT 
                COUNT(*) as total_appointments,
                SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending_appointments,
                SUM(CASE WHEN status = 'CONFIRMED' THEN 1 ELSE 0 END) as confirmed_appointments,
                SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed_appointments,
                SUM(CASE WHEN status = 'CANCELLED' THEN 1 ELSE 0 END) as cancelled_appointments,
                SUM(CASE WHEN DATE(appointment_datetime) = CURDATE() AND status = 'CONFIRMED' THEN 1 ELSE 0 END) as today_appointments
            FROM appointments 
            WHERE doctor_id = %s
        """
        
        cursor.execute(stats_query, (doctor_id,))
        stats = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "stats": stats
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch appointment stats",
            "details": str(e)
        }), 500


@doctor_bp.route("/patients", methods=["GET"])
@jwt_required()
def get_patients():
    """Get all patient appointments with patient details for the logged-in doctor"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all appointments with patient details - each appointment creates a separate patient entry
        patients_query = """
            SELECT 
                a.id as appointment_id,
                a.appointment_datetime,
                a.reason,
                a.status as appointment_status,
                a.created_at as appointment_created_at,
                p.id as patient_id,
                p.full_name,
                p.email,
                p.mobile,
                p.gender,
                p.date_of_birth,
                p.blood_group,
                p.address,
                p.city,
                p.state,
                p.zip,
                p.country,
                p.allergies,
                p.conditions,
                p.medications,
                p.surgeries,
                p.emergency_contact_name,
                p.emergency_contact_number,
                p.is_active,
                p.created_at as patient_created_at,
                -- Get total counts for this patient across all appointments
                (SELECT COUNT(*) FROM appointments a2 WHERE a2.patient_id = p.id AND a2.doctor_id = %s AND a2.status = 'PENDING') as total_pending,
                (SELECT COUNT(*) FROM appointments a2 WHERE a2.patient_id = p.id AND a2.doctor_id = %s AND a2.status = 'CONFIRMED') as total_confirmed,
                (SELECT COUNT(*) FROM appointments a2 WHERE a2.patient_id = p.id AND a2.doctor_id = %s AND a2.status = 'COMPLETED') as total_completed,
                (SELECT COUNT(*) FROM appointments a2 WHERE a2.patient_id = p.id AND a2.doctor_id = %s AND a2.status = 'CANCELLED') as total_cancelled,
                (SELECT COUNT(*) FROM appointments a2 WHERE a2.patient_id = p.id AND a2.doctor_id = %s) as total_appointments
            FROM appointments a
            INNER JOIN patient p ON a.patient_id = p.id
            WHERE a.doctor_id = %s
            ORDER BY a.status ASC, a.appointment_datetime DESC, p.full_name ASC
        """
        
        cursor.execute(patients_query, (doctor_id, doctor_id, doctor_id, doctor_id, doctor_id, doctor_id))
        patient_appointments = cursor.fetchall()
        
        # Convert datetime objects to strings and format data
        for entry in patient_appointments:
            if entry.get('date_of_birth'):
                if isinstance(entry['date_of_birth'], datetime.date):
                    entry['date_of_birth'] = entry['date_of_birth'].isoformat()
            
            if entry.get('patient_created_at'):
                if hasattr(entry['patient_created_at'], 'isoformat'):
                    entry['patient_created_at'] = entry['patient_created_at'].isoformat()
                    
            if entry.get('appointment_created_at'):
                if hasattr(entry['appointment_created_at'], 'isoformat'):
                    entry['appointment_created_at'] = entry['appointment_created_at'].isoformat()
                    
            if entry.get('appointment_datetime'):
                if hasattr(entry['appointment_datetime'], 'isoformat'):
                    entry['appointment_datetime'] = entry['appointment_datetime'].isoformat()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "patients": patient_appointments,
            "count": len(patient_appointments)
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch patients",
            "details": str(e)
        }), 500

@doctor_bp.route("/recent-activities", methods=["GET"])
@jwt_required()
def get_recent_activities():
    """Get recent patient activities for the logged-in doctor"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get recent appointments (last 7 days) with patient details
        recent_appointments_query = """
            SELECT 
                a.id as activity_id,
                'appointment' as activity_type,
                a.status,
                a.appointment_datetime,
                a.reason,
                a.created_at,
                p.id as patient_id,
                p.full_name as patient_name,
                p.email as patient_email,
                p.mobile as patient_mobile,
                'appointment_status_change' as action_type
            FROM appointments a
            INNER JOIN patient p ON a.patient_id = p.id
            WHERE a.doctor_id = %s 
            AND a.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ORDER BY a.created_at DESC
            LIMIT 10
        """
        
        cursor.execute(recent_appointments_query, (doctor_id,))
        appointment_activities = cursor.fetchall()

        # Get recently registered patients who have appointments with this doctor
        recent_patients_query = """
            SELECT DISTINCT
                p.id as activity_id,
                'patient' as activity_type,
                'new_patient' as action_type,
                p.full_name as patient_name,
                p.email as patient_email,
                p.mobile as patient_mobile,
                p.created_at,
                '' as status,
                '' as reason,
                '' as appointment_datetime
            FROM patient p
            INNER JOIN appointments a ON p.id = a.patient_id
            WHERE a.doctor_id = %s 
            AND p.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ORDER BY p.created_at DESC
            LIMIT 5
        """
        
        cursor.execute(recent_patients_query, (doctor_id,))
        patient_activities = cursor.fetchall()

        # Combine and sort all activities
        all_activities = []
        
        # Process appointment activities
        for activity in appointment_activities:
            activity_time = activity.get('created_at')
            
            # Create dynamic title based on status
            status_titles = {
                'PENDING': 'New Appointment Request',
                'CONFIRMED': 'Appointment Confirmed', 
                'COMPLETED': 'Appointment Completed',
                'CANCELLED': 'Appointment Cancelled'
            }
            title = status_titles.get(activity['status'], 'Appointment Update')
            
            description = f"{activity['patient_name']} - {activity['reason'] or 'General consultation'}"
            
            all_activities.append({
                'id': f"appointment_{activity['activity_id']}",
                'appointment_id': activity['activity_id'],  # Real appointment ID for navigation
                'patient_id': activity['patient_id'],       # Real patient ID for navigation
                'type': 'appointment',
                'title': title,
                'description': description,
                'patient_name': activity['patient_name'],
                'patient_email': activity['patient_email'],
                'status': activity['status'],
                'time': activity_time,
                'appointment_datetime': activity.get('appointment_datetime'),
                'reason': activity.get('reason')
            })

        # Process patient activities
        for activity in patient_activities:
            all_activities.append({
                'id': f"patient_{activity['activity_id']}",
                'patient_id': activity['activity_id'],     # Real patient ID for navigation
                'type': 'patient',
                'title': 'New Patient Registered',
                'description': f"{activity['patient_name']} joined your practice",
                'patient_name': activity['patient_name'],
                'patient_email': activity['patient_email'],
                'status': 'new',
                'time': activity['created_at'],
                'appointment_datetime': None,
                'reason': None
            })

        # Sort by time (most recent first)
        all_activities.sort(key=lambda x: x['time'], reverse=True)
        
        # Take only the most recent 10 activities
        recent_activities = all_activities[:10]
        
        # Format datetime objects to strings
        for activity in recent_activities:
            if activity.get('time'):
                if hasattr(activity['time'], 'isoformat'):
                    activity['time'] = activity['time'].isoformat()
                    
            if activity.get('appointment_datetime'):
                if hasattr(activity['appointment_datetime'], 'isoformat'):
                    activity['appointment_datetime'] = activity['appointment_datetime'].isoformat()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "activities": recent_activities,
            "count": len(recent_activities)
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch recent activities",
            "details": str(e)
        }), 500


# ---------------------------
# Doctor Ratings APIs
# ---------------------------
@doctor_bp.route("/ratings", methods=["GET"])
@jwt_required()
def get_doctor_ratings():
    """Get all ratings for the logged-in doctor"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all ratings with patient and appointment details
        ratings_query = """
            SELECT 
                r.id,
                r.rating,
                r.review,
                r.created_at,
                p.full_name as patient_name,
                p.email as patient_email,
                a.appointment_datetime,
                a.reason as appointment_reason
            FROM ratings r
            INNER JOIN patient p ON r.patient_id = p.id
            INNER JOIN appointments a ON r.appointment_id = a.id
            WHERE r.doctor_id = %s
            ORDER BY r.created_at DESC
        """
        
        cursor.execute(ratings_query, (doctor_id,))
        ratings = cursor.fetchall()
        
        # Get rating statistics
        stats_query = """
            SELECT 
                COUNT(*) as total_ratings,
                AVG(rating) as average_rating,
                SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_star,
                SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_star,
                SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_star,
                SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_star,
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
            FROM ratings 
            WHERE doctor_id = %s
        """
        
        cursor.execute(stats_query, (doctor_id,))
        stats = cursor.fetchone()
        
        # Format datetime objects
        for rating in ratings:
            if rating.get('created_at'):
                if hasattr(rating['created_at'], 'isoformat'):
                    rating['created_at'] = rating['created_at'].isoformat()
            if rating.get('appointment_datetime'):
                if hasattr(rating['appointment_datetime'], 'isoformat'):
                    rating['appointment_datetime'] = rating['appointment_datetime'].isoformat()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "ratings": ratings,
            "statistics": {
                "total_ratings": stats['total_ratings'] or 0,
                "average_rating": round(float(stats['average_rating'] or 0), 2),
                "star_distribution": {
                    "5": stats['five_star'] or 0,
                    "4": stats['four_star'] or 0,
                    "3": stats['three_star'] or 0,
                    "2": stats['two_star'] or 0,
                    "1": stats['one_star'] or 0
                }
            }
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch ratings",
            "details": str(e)
        }), 500


@doctor_bp.route("/ratings/summary", methods=["GET"])
@jwt_required()
def get_rating_summary():
    """Get rating summary for dashboard"""
    try:
        doctor_id = get_jwt_identity()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current ratings from the database
        summary_query = """
            SELECT 
                COALESCE(AVG(rating), 0) as average_rating,
                COUNT(*) as total_reviews
            FROM ratings 
            WHERE doctor_id = %s
        """
        
        cursor.execute(summary_query, (doctor_id,))
        summary = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "rating": round(float(summary['average_rating'] or 0), 1),
            "reviewCount": summary['total_reviews'] or 0
        }), 200
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": "Failed to fetch rating summary",
            "details": str(e)
        }), 500