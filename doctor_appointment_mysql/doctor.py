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
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

        if not updates:
            return jsonify({"error": "No fields to update"}), 400

        values.append(doctor_id)

        query = f"""
            UPDATE doctors SET {', '.join(updates)}, updated_at = NOW()
            WHERE id = %s
        """
        cursor.execute(query, tuple(values))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
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
            JOIN patients p ON a.patient_id = p.id
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
            SET status = 'CONFIRMED', updated_at = NOW()
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
            SET status = 'CANCELLED', updated_at = NOW()
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
            SET status = 'COMPLETED', updated_at = NOW()
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
        
        # Validate required fields
        if not data.get('new_date') or not data.get('new_time'):
            return jsonify({
                "success": False,
                "error": "New date and time are required"
            }), 400
        
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
                "error": "Only pending or confirmed appointments can be rescheduled"
            }), 400

        # Combine new date and time
        new_datetime = f"{data['new_date']} {data['new_time']}:00"
        
        # Update appointment with new datetime
        update_query = """
            UPDATE appointments 
            SET appointment_datetime = %s, 
                status = 'CONFIRMED',
                updated_at = NOW()
            WHERE id = %s
        """
        cursor.execute(update_query, (new_datetime, appointment_id))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment rescheduled successfully",
            "new_datetime": new_datetime
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