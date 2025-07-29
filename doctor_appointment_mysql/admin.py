# admin_routes.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (JWTManager, create_access_token, jwt_required, get_jwt_identity)
from mongoengine import get_connection
from werkzeug.security import check_password_hash, generate_password_hash
from db import get_db_connection

admin_bp = Blueprint('admin', __name__)


# --- Admin Login ---
@admin_bp.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email, pwd = data.get('email'), data.get('password')
    db = get_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
    user = cur.fetchone()
    if user and user['is_active'] and check_password_hash(user['password'], pwd):
        token = create_access_token(identity={'id': user['id'], 'role': user['role']})
        return jsonify(token=token)
    return jsonify(error='Invalid credentials'), 401


# --- Create Admin ---
@admin_bp.route('/admin/create', methods=['POST'])
@jwt_required()
def create_admin():
    identity = get_jwt_identity()
    if identity['role'] != 'SUPER_ADMIN':
        return jsonify(error="Not authorized"), 403

    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = generate_password_hash(data.get('password'))
    role = data.get('role', 'ADMIN')

    db = get_connection()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO admin (full_name, email, password, role) VALUES (%s, %s, %s, %s)",
                    (full_name, email, password, role))
        db.commit()
        return jsonify(message="Admin created successfully")
    except Exception as e:
        return jsonify(error=str(e)), 500


# --- List Doctors ---
@admin_bp.route('/admin/doctors', methods=['GET'])
@jwt_required()
def list_doctors():
    db = get_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, approved, suspended, documents_verified FROM doctors")
    return jsonify(cur.fetchall())


# --- Approve Doctor ---
@admin_bp.route('/admin/doctors/<int:doc_id>/approve', methods=['PUT'])
@jwt_required()
def approve_doctor(doc_id):
    db = get_connection()
    cur = db.cursor()
    cur.execute("UPDATE doctors SET approved=1 WHERE id=%s", (doc_id,))
    db.commit()
    return jsonify(message='Doctor approved')


# --- Reject Doctor ---
@admin_bp.route('/admin/doctors/<int:doc_id>/reject', methods=['PUT'])
@jwt_required()
def reject_doctor(doc_id):
    db = get_connection()
    cur = db.cursor()
    cur.execute("UPDATE doctors SET approved=0 WHERE id=%s", (doc_id,))
    db.commit()
    return jsonify(message='Doctor rejected')


# --- List Patients ---
@admin_bp.route('/admin/patients', methods=['GET'])
@jwt_required()
def list_patients():
    db = get_connection()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, email, mobile, is_active FROM patient")
    return jsonify(cur.fetchall())


# --- Deactivate Patient ---
@admin_bp.route('/admin/patients/<int:pat_id>/deactivate', methods=['PUT'])
@jwt_required()
def deactivate_patient(pat_id):
    db = get_connection()
    cur = db.cursor()
    cur.execute("UPDATE patient SET is_active=FALSE WHERE id=%s", (pat_id,))
    db.commit()
    return jsonify(message='Patient deactivated')
