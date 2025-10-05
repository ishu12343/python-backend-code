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
import random
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO)

patient_bp = Blueprint("patient", __name__)
CORS(patient_bp)

# ===== FORGOT PASSWORD ENDPOINTS =====

@patient_bp.route("/api/patient/forgot-password/send-otp", methods=["POST"])
def send_otp():
    """Send OTP for password reset - Only works with registered patient emails/mobiles"""
    print("Patient forgot password send OTP endpoint called")
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
            
            # Check if patient exists with this email (active patients only)
            cursor.execute(
                "SELECT id, email, full_name, is_active FROM patient WHERE email = %s", 
                (identifier,)
            )
            identifier_type = "email"
        else:
            # Validate mobile format (assuming 10 digits)
            mobile_pattern = r'^[+]?[0-9]{10,15}$'
            if not re.match(mobile_pattern, identifier.replace("-", "").replace(" ", "")):
                return jsonify({"success": False, "error": "Invalid mobile number format"}), 400
            
            # Check if patient exists with this mobile (active patients only)
            cursor.execute(
                "SELECT id, mobile, full_name, is_active FROM patient WHERE mobile = %s", 
                (identifier,)
            )
            identifier_type = "mobile"
        
        patient = cursor.fetchone()
        
        if not patient:
            return jsonify({"success": False, "error": f"No patient account found with this {identifier_type}. Please use a registered {identifier_type} address."}), 404
        
        # Check if patient account is active
        if not patient.get('is_active', True):
            return jsonify({"success": False, "error": "Your patient account is deactivated. Please contact admin."}), 403
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=10)
        
        # Store OTP in database (replace any existing OTP)
        cursor.execute(
            "UPDATE patient SET reset_otp = %s, otp_expires_at = %s WHERE id = %s",
            (otp, expiry_time, patient['id'])
        )
        conn.commit()
        
        # In production, send OTP via SMS/Email service
        # For now, we'll just return success (OTP will be visible in logs for testing)
        print(f"OTP for patient {patient['full_name']}: {otp}")  # Remove in production
        
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


@patient_bp.route("/api/patient/forgot-password/reset", methods=["POST"])
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
        
        # Find patient by identifier and get stored OTP
        is_email = "@" in identifier
        
        if is_email:
            cursor.execute(
                "SELECT id, email, full_name, reset_otp, otp_expires_at, is_active FROM patient WHERE email = %s", 
                (identifier,)
            )
        else:
            cursor.execute(
                "SELECT id, mobile, full_name, reset_otp, otp_expires_at, is_active FROM patient WHERE mobile = %s", 
                (identifier,)
            )
        
        patient = cursor.fetchone()
        
        if not patient:
            return jsonify({"success": False, "error": "Patient not found"}), 404
        
        # Check if patient account is active
        if not patient.get('is_active', True):
            return jsonify({"success": False, "error": "Your patient account is deactivated. Please contact admin."}), 403
        
        # Verify OTP exists and not expired
        if not patient['reset_otp'] or not patient['otp_expires_at']:
            return jsonify({"success": False, "error": "No OTP found. Please request a new OTP."}), 400
        
        if datetime.datetime.now() > patient['otp_expires_at']:
            # Clear expired OTP
            cursor.execute(
                "UPDATE patient SET reset_otp = NULL, otp_expires_at = NULL WHERE id = %s",
                (patient['id'],)
            )
            conn.commit()
            return jsonify({"success": False, "error": "OTP has expired. Please request a new one."}), 400
        
        if patient['reset_otp'] != otp:
            return jsonify({"success": False, "error": "Invalid OTP. Please check and try again."}), 400
        
        # Hash new password
        hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
        
        # Update password and clear OTP
        cursor.execute(
            "UPDATE patient SET password = %s, reset_otp = NULL, otp_expires_at = NULL, updated_at = NOW() WHERE id = %s",
            (hashed_password.decode("utf-8"), patient['id'])
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


# ---------------------------
# Database Schema Helper
# ---------------------------
def ensure_photo_column_size():
    """Ensure photo_path column can handle base64 image data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check current column type
        cursor.execute("""
            SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = 'doctorapp' 
            AND TABLE_NAME = 'patient' 
            AND COLUMN_NAME = 'photo_path'
        """)
        result = cursor.fetchone()
        
        if result and result[0] != 'longtext':
            logging.info("Updating photo_path column to handle base64 images...")
            cursor.execute("ALTER TABLE patient MODIFY COLUMN photo_path LONGTEXT")
            conn.commit()
            logging.info("Photo column updated successfully")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logging.warning(f"Could not update photo column: {e}")
        # Continue without failing - the column might already be correct

# ---------------------------
# Photo Processing Helper
# ---------------------------
def validate_and_process_photo(photo_data):
    """Validate and process base64 photo data"""
    if not photo_data:
        return None
        
    # Check if it's a valid base64 image
    if not photo_data.startswith('data:image/'):
        logging.warning("Invalid photo format - not a base64 image")
        return None
    
    # Check size (limit to ~2MB base64 which is ~1.5MB actual image)
    max_size = 2 * 1024 * 1024  # 2MB
    if len(photo_data) > max_size:
        logging.warning(f"Photo too large: {len(photo_data)} bytes")
        raise ValueError("Photo size too large. Please use a smaller image.")
    
    return photo_data

# ---------------------------
# Register API
# ---------------------------
@patient_bp.route("/api/patient/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        # Required Fields
        full_name = data.get("fullName")
        email = data.get("email", "").lower()
        password = data.get("password")
        mobile = data.get("mobile")

        # Optional Fields
        date_of_birth = data.get("dateOfBirth")
        gender = data.get("gender")
        blood_group = data.get("bloodGroup")
        address = data.get("address")
        city = data.get("city")
        state = data.get("state")
        zip_code = data.get("zip")
        country = data.get("country")
        allergies = data.get("allergies")
        conditions = data.get("conditions")
        medications = data.get("medications")
        surgeries = data.get("surgeries")
        emergency_contact_name = data.get("emergencyContactName")
        emergency_contact_number = data.get("emergencyContactNumber")
        document_path = data.get("documentPath")
        role = data.get("role", "PATIENT")

        # Validation
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
                full_name, email, password, mobile, gender, date_of_birth, blood_group,
                address, city, state, zip, country,
                allergies, conditions, medications, surgeries,
                emergency_contact_name, emergency_contact_number, document_path,
                role, is_active, verified, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, NOW(), NOW()
            )
        """, (
            full_name, email, hashed_password, mobile, gender, date_of_birth, blood_group,
            address, city, state, zip_code, country,
            allergies, conditions, medications, surgeries,
            emergency_contact_name, emergency_contact_number, document_path,
            role, True, False
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

        identifier = (data.get("email") or data.get("identifier", "")).lower()
        password = data.get("password")

        if not identifier or not password:
            return jsonify({"error": "Email/mobile and password required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Determine if identifier is email or mobile
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        mobile_pattern = r'^[0-9]{10}$'
        
        if re.match(email_pattern, identifier):
            cursor.execute("SELECT * FROM patient WHERE email = %s", (identifier,))
        elif re.match(mobile_pattern, identifier):
            cursor.execute("SELECT * FROM patient WHERE mobile = %s", (identifier,))
        else:
            cursor.close()
            conn.close()
            return jsonify({"error": "Please enter a valid email address or 10-digit mobile number"}), 400
            
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
            return jsonify({"error": "Invalid email/mobile or password"}), 401

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

        cursor.execute("""
            SELECT id, full_name, email, mobile, gender, date_of_birth, blood_group,
                   address, city, state, zip, country,
                   allergies, conditions, medications, surgeries,
                   emergency_contact_name, emergency_contact_number, document_path,
                   photo_path, role, is_active, verified, created_at, updated_at
            FROM patient
            WHERE id = %s
        """, (patient_id,))
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
# profile update API
# ---------------------------
@patient_bp.route("/api/patient/updateprofile", methods=["PUT"])
@jwt_required()
def update_patient_profile():
    try:
        patient_id = get_jwt_identity()
        data = request.get_json()  # handles JSON data like doctor profile
        
        # Debug logging
        logging.info(f"Patient ID: {patient_id}")
        logging.info(f"Request data: {data}")

        if not data:
            return jsonify({"error": "Missing or invalid JSON payload"}), 400

        # Ensure database can handle photo data
        ensure_photo_column_size()
        
        # Process photo data if provided
        photo_data = None
        if data.get("photo_path"):
            try:
                photo_data = validate_and_process_photo(data.get("photo_path"))
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
        
        # Fields you want to allow updating
        allowed_fields = {
            "full_name": data.get("full_name"),
            "mobile": data.get("mobile"),
            "gender": data.get("gender"),
            "date_of_birth": data.get("dob"),  # frontend sends 'dob'
            "blood_group": data.get("blood_group"),
            "address": data.get("address"),
            "photo_path": photo_data,
            "city": data.get("city"),
            "state": data.get("state"),
            "zip": data.get("zip"),
            "country": data.get("country"),
            "allergies": data.get("allergies"),
            "conditions": data.get("conditions"),
            "medications": data.get("medications"),
            "surgeries": data.get("surgeries"),
            "emergency_contact_name": data.get("emergency_contact_name"),
            "emergency_contact_number": data.get("emergency_contact_number"),
            "document_path": data.get("document_path")
        }



        fields = []
        values = []

        for field, value in allowed_fields.items():
            if value is not None:
                fields.append(f"{field} = %s")
                values.append(value)
                # Add debug logging for photo
                if field == "photo_path" and value:
                    logging.info(f"Photo data length: {len(str(value))}")

        if not fields:
            return jsonify({"error": "No fields to update"}), 400

        # values.append(patient_id)
        #
        # query = f"""
        #     UPDATE patient
        #     SET {', '.join(fields)}, updated_at = %s
        #     WHERE id = %s
        # """
        # values.insert(-1, datetime.utcnow())  # Add updated_at before patient_id

        values.append(datetime.datetime.utcnow())  # updated_at
        values.append(patient_id)  # WHERE id = %s

        query = f"""
            UPDATE patient
            SET {', '.join(fields)}, updated_at = %s
            WHERE id = %s
        """

        logging.info(f"Final query: {query}")
        logging.info(f"Final values: {values}")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(query, values)
        conn.commit()
        
        # Check how many rows were affected
        rows_affected = cursor.rowcount
        logging.info(f"Rows affected: {rows_affected}")
        
        conn.close()

        return jsonify({"message": "✅ Patient profile updated successfully"}), 200

    except Exception as e:
        logging.exception(f"Error updating patient profile: {str(e)}")
        return jsonify({"error": f"Database error: {str(e)}"}), 500


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


# ---------------------------
# List Available Doctors API
# ---------------------------
@patient_bp.route("/api/patient/doctors", methods=["GET"])
# @jwt_required()
def list_available_doctors():
    try:
        # Get query parameters for filtering
        specialty = request.args.get("specialty")
        city = request.args.get("city")
        search = request.args.get("search")
        doctor_id = request.args.get("doctor_id")
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Base query for approved and active doctors with rating information
        query = """
            SELECT 
                d.id, d.full_name, d.email, d.mobile, d.specialty, d.degree, d.experience,
                d.clinic_name, d.clinic_address, d.city, d.state, d.available_days,
                d.available_from, d.available_to, d.languages, d.profile_photo,
                COALESCE(AVG(r.rating), 0) as average_rating,
                COUNT(r.id) as total_reviews
            FROM doctors d
            LEFT JOIN ratings r ON d.id = r.doctor_id
            WHERE d.approved = 1 AND d.suspended = 0 AND d.status = 'ACTIVE'
        """
        params = []
        
        if doctor_id:
            query += " AND d.id = %s"
            params.append(doctor_id)
        else:
            # Add list filters
            if specialty:
                query += " AND d.specialty LIKE %s"
                params.append(f"%{specialty}%")
            
            if city:
                query += " AND d.city LIKE %s"
                params.append(f"%{city}%")
                
            if search:
                query += " AND (d.full_name LIKE %s OR d.specialty LIKE %s)"
                params.extend([f"%{search}%", f"%{search}%"])
        
        query += " GROUP BY d.id ORDER BY d.full_name"
        
        cursor.execute(query, params)
        doctors = cursor.fetchall()
        
        # Format the response
        formatted_doctors = []
        for doctor in doctors:
            # Convert timedelta fields to string format
            if doctor.get('available_from'):
                if hasattr(doctor['available_from'], 'total_seconds'):
                    total_seconds = int(doctor['available_from'].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    doctor['available_from'] = f"{hours:02d}:{minutes:02d}"
            
            if doctor.get('available_to'):
                if hasattr(doctor['available_to'], 'total_seconds'):
                    total_seconds = int(doctor['available_to'].total_seconds())
                    hours = total_seconds // 3600
                    minutes = (total_seconds % 3600) // 60
                    doctor['available_to'] = f"{hours:02d}:{minutes:02d}"
            
            if doctor.get('experience'):
                if hasattr(doctor['experience'], 'total_seconds'):
                    total_seconds = int(doctor['experience'].total_seconds())
                    years = total_seconds // (365 * 24 * 3600)
                    # Return experience as an integer for consistent frontend handling
                    doctor['experience'] = years
            
            # Convert languages string to a list
            if doctor.get('languages') and isinstance(doctor['languages'], str):
                doctor['languages'] = [lang.strip() for lang in doctor['languages'].split(',') if lang.strip()]
            elif not doctor.get('languages'):
                doctor['languages'] = []

            # Format rating information
            if doctor.get('average_rating'):
                doctor['average_rating'] = round(float(doctor['average_rating']), 1)
            else:
                doctor['average_rating'] = 0.0
                
            if not doctor.get('total_reviews'):
                doctor['total_reviews'] = 0
            
            formatted_doctors.append(doctor)
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "doctors": formatted_doctors,
            "count": len(formatted_doctors)
        }), 200
        
    except Exception as e:
        logging.exception("Error fetching doctors")
        return jsonify({"error": "Failed to fetch doctors"}), 500


# ---------------------------
# Book Appointment API
# ---------------------------
@patient_bp.route("/api/patient/appointments/book", methods=["POST"])
@jwt_required()
def book_appointment():
    try:
        patient_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["doctor_id", "appointment_date", "appointment_time", "reason"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"{field} is required"}), 400
        
        doctor_id = data.get("doctor_id")
        appointment_date = data.get("appointment_date")
        appointment_time = data.get("appointment_time")
        reason = data.get("reason")
        
        # Combine date and time
        appointment_datetime = f"{appointment_date} {appointment_time}"
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if doctor exists and is available
        cursor.execute("""
            SELECT id, full_name, available_days, available_from, available_to 
            FROM doctors 
            WHERE id = %s AND approved = 1 AND suspended = 0 AND status = 'ACTIVE'
        """, (doctor_id,))
        doctor = cursor.fetchone()
        
        if not doctor:
            cursor.close()
            conn.close()
            return jsonify({"error": "Doctor not found or not available"}), 404
        
        # Check for existing appointment at the same time
        cursor.execute("""
            SELECT id FROM appointments 
            WHERE doctor_id = %s AND appointment_datetime = %s AND status != 'CANCELLED'
        """, (doctor_id, appointment_datetime))
        existing_appointment = cursor.fetchone()
        
        if existing_appointment:
            cursor.close()
            conn.close()
            return jsonify({"error": "This time slot is already booked"}), 409
        
        # Create appointment
        cursor.execute("""
            INSERT INTO appointments (patient_id, doctor_id, appointment_datetime, reason, status, created_at)
            VALUES (%s, %s, %s, %s, 'PENDING', NOW())
        """, (patient_id, doctor_id, appointment_datetime, reason))
        
        appointment_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment booked successfully",
            "appointment_id": appointment_id,
            "doctor_name": doctor["full_name"]
        }), 201
        
    except Exception as e:
        logging.exception("Error booking appointment")
        return jsonify({"error": "Failed to book appointment"}), 500


# ---------------------------
# Get Patient Appointments API
# ---------------------------
@patient_bp.route("/api/patient/appointments", methods=["GET"])
@jwt_required()
def get_patient_appointments():
    try:
        patient_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                a.id, a.appointment_datetime, a.reason, a.status, a.created_at,
                d.full_name as doctor_name, d.specialty, d.clinic_name, d.mobile as doctor_mobile,
                CASE WHEN r.id IS NOT NULL THEN 1 ELSE 0 END as has_rating
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            LEFT JOIN ratings r ON a.id = r.appointment_id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_datetime DESC
        """, (patient_id,))
        
        appointments = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "appointments": appointments
        }), 200
        
    except Exception as e:
        logging.exception("Error fetching appointments")
        return jsonify({"error": "Failed to fetch appointments"}), 500


# ---------------------------
# Cancel Appointment API
# ---------------------------
@patient_bp.route("/api/patient/appointments/<int:appointment_id>/cancel", methods=["PUT"])
@jwt_required()
def cancel_appointment(appointment_id):
    try:
        patient_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if appointment exists and belongs to patient
        cursor.execute("""
            SELECT id, status FROM appointments 
            WHERE id = %s AND patient_id = %s
        """, (appointment_id, patient_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            cursor.close()
            conn.close()
            return jsonify({"error": "Appointment not found"}), 404
        
        if appointment["status"] == "CANCELLED":
            cursor.close()
            conn.close()
            return jsonify({"error": "Appointment is already cancelled"}), 400
        
        # Cancel appointment
        cursor.execute("""
            UPDATE appointments 
            SET status = 'CANCELLED' 
            WHERE id = %s
        """, (appointment_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment cancelled successfully"
        }), 200
        
    except Exception as e:
        logging.exception("Error cancelling appointment")
        return jsonify({"error": "Failed to cancel appointment"}), 500

# ---------------------------
# Reschedule Appointment API
# ---------------------------
@patient_bp.route("/api/patient/appointments/<int:appointment_id>/reschedule", methods=["POST"])
@jwt_required()
def reschedule_appointment(appointment_id):
    """Reschedule an appointment to a new date and time"""
    try:
        patient_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        if not data.get('new_date') or not data.get('new_time'):
            return jsonify({
                "success": False,
                "error": "New date and time are required"
            }), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this patient
        cursor.execute("""
            SELECT id, status, doctor_id FROM appointments 
            WHERE id = %s AND patient_id = %s
        """, (appointment_id, patient_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] not in ['PENDING', 'CONFIRMED', 'CANCELLED']:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Only pending, confirmed, or cancelled appointments can be rescheduled"
            }), 400

        # Combine new date and time
        new_datetime = f"{data['new_date']} {data['new_time']}:00"
        
        # Check if the new time slot is available for the doctor
        cursor.execute("""
            SELECT id FROM appointments 
            WHERE doctor_id = %s AND appointment_datetime = %s AND status != 'CANCELLED' AND id != %s
        """, (appointment['doctor_id'], new_datetime, appointment_id))
        existing_appointment = cursor.fetchone()
        
        if existing_appointment:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "This time slot is already booked with the doctor"
            }), 409
        
        # Update appointment with new datetime and set status to PENDING for doctor approval
        cursor.execute("""
            UPDATE appointments 
            SET appointment_datetime = %s, 
                status = 'PENDING'
            WHERE id = %s
        """, (new_datetime, appointment_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Appointment rescheduled successfully. Waiting for doctor confirmation.",
            "new_datetime": new_datetime
        }), 200
        
    except Exception as e:
        logging.exception("Error rescheduling appointment")
        return jsonify({
            "success": False,
            "error": "Failed to reschedule appointment"
        }), 500


# ---------------------------
# Rate Doctor API
# ---------------------------
@patient_bp.route("/api/patient/appointments/<int:appointment_id>/rate", methods=["POST"])
@jwt_required()
def rate_doctor(appointment_id):
    """Rate a doctor after appointment completion"""
    try:
        patient_id = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        if not data.get('rating') or data.get('rating') < 1 or data.get('rating') > 5:
            return jsonify({
                "success": False,
                "error": "Rating must be between 1 and 5"
            }), 400
        
        rating = data.get('rating')
        review = data.get('review', '')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # First verify the appointment belongs to this patient and is completed
        cursor.execute("""
            SELECT id, status, doctor_id FROM appointments 
            WHERE id = %s AND patient_id = %s
        """, (appointment_id, patient_id))
        appointment = cursor.fetchone()
        
        if not appointment:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Appointment not found or unauthorized"
            }), 404
            
        if appointment['status'] != 'COMPLETED':
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "Only completed appointments can be rated"
            }), 400

        # Check if rating already exists for this appointment
        cursor.execute("""
            SELECT id FROM ratings 
            WHERE appointment_id = %s
        """, (appointment_id,))
        existing_rating = cursor.fetchone()
        
        if existing_rating:
            cursor.close()
            conn.close()
            return jsonify({
                "success": False,
                "error": "This appointment has already been rated"
            }), 409
        
        # Insert rating
        cursor.execute("""
            INSERT INTO ratings (appointment_id, patient_id, doctor_id, rating, review, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
        """, (appointment_id, patient_id, appointment['doctor_id'], rating, review))
        
        rating_id = cursor.lastrowid
        
        # Update doctor's average rating
        cursor.execute("""
            UPDATE doctors SET 
                average_rating = (
                    SELECT AVG(rating) FROM ratings WHERE doctor_id = %s
                ),
                total_reviews = (
                    SELECT COUNT(*) FROM ratings WHERE doctor_id = %s
                )
            WHERE id = %s
        """, (appointment['doctor_id'], appointment['doctor_id'], appointment['doctor_id']))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Rating submitted successfully",
            "rating_id": rating_id
        }), 201
        
    except Exception as e:
        logging.exception("Error submitting rating")
        return jsonify({
            "success": False,
            "error": "Failed to submit rating"
        }), 500


# ---------------------------
# Get Patient's Ratings API
# ---------------------------
@patient_bp.route("/api/patient/ratings", methods=["GET"])
@jwt_required()
def get_patient_ratings():
    """Get all ratings submitted by the patient"""
    try:
        patient_id = get_jwt_identity()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT 
                r.id, r.rating, r.review, r.created_at,
                a.appointment_datetime, a.reason,
                d.full_name as doctor_name, d.specialty
            FROM ratings r
            JOIN appointments a ON r.appointment_id = a.id
            JOIN doctors d ON r.doctor_id = d.id
            WHERE r.patient_id = %s
            ORDER BY r.created_at DESC
        """, (patient_id,))
        
        ratings = cursor.fetchall()
        
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
            "ratings": ratings
        }), 200
        
    except Exception as e:
        logging.exception("Error fetching patient ratings")
        return jsonify({"error": "Failed to fetch ratings"}), 500


# ---------------------------
# List All Patients API (Public)
# ---------------------------
@patient_bp.route("/api/patient/patient-list", methods=["GET"])
def list_all_patients():
    """
    Provides a public list of all patients, primarily for stats like total patient count.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, full_name, created_at FROM patient WHERE is_active = 1")
        patients = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "patients": patients,
            "count": len(patients)
        }), 200

    except Exception as e:
        logging.exception("Error fetching all patients")
        return jsonify({"error": "Failed to fetch patient list"}), 500
