# db.py
import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "root",
    "database": "doctorapp"
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)
