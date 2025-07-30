from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta

# ✅ Declare blacklist early to avoid circular imports
blacklist = set()

# ✅ Create app
app = Flask(__name__)
CORS(app)

# ✅ JWT Config
app.config['JWT_SECRET_KEY'] = 'admin_123'  # Change before deployment
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=99999)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']

# ✅ Initialize JWT
jwt = JWTManager(app)

# ✅ Token revocation logic (use blacklist from same file)
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklist

# ✅ Import and register blueprints AFTER declaring blacklist
from doctor import doctor_bp
from patient import patient_bp
from admin import admin_bp

app.register_blueprint(doctor_bp)
app.register_blueprint(patient_bp)
app.register_blueprint(admin_bp)

# ✅ Test route
@app.route("/ping")
def ping():
    return {"message": "Server is running"}

if __name__ == "__main__":
    app.run(debug=True)
