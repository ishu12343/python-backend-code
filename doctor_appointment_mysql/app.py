from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

# Create app
app = Flask(__name__)
CORS(app)  # Enables CORS

# ✅ Add JWT Config
app.config['JWT_SECRET_KEY'] = 'admin_123'     # 🔐 CHANGE this before deploying
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# ✅ Initialize JWT
jwt = JWTManager(app)

# Import and register blueprints
from doctor import doctor_bp
from patient import patient_bp
from admin import admin_bp

app.register_blueprint(doctor_bp)
app.register_blueprint(patient_bp)
app.register_blueprint(admin_bp)

# Test route
@app.route("/ping")
def ping():
    return {"message": "Server is running"}

# Run app
if __name__ == "__main__":
    app.run(debug=True)
