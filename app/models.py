from . import db
from datetime import datetime, timedelta

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    mobile = db.Column(db.String(20), nullable=False)  # Can add validation later
    dob = db.Column(db.Date, nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)  # Optionally encrypt this
    status = db.Column(db.String(20), default='inactive')  # Status: active, archived, inactive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    predictions = db.relationship('Prediction', backref='user', lazy=True)


class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction_type = db.Column(db.String(50), nullable=False)  
    input_data = db.Column(db.Text, nullable=False)
    result = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional: Add a status field
    status = db.Column(db.String(20), default='completed')  # E.g., completed, failed


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)  # Relates to Admin
    action = db.Column(db.String(255), nullable=False)  # E.g., "User Activated"
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Optional
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)  # Enforce one OTP per email
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=10))  # OTP validity


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store hashed passwords
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional: Add a role field for future scalability
    role = db.Column(db.String(50), default='admin')  # E.g., admin, super-admin

class MedicinalPlants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    scientific_name = db.Column(db.String(255), nullable=False)    
    uses = db.Column(db.Text, nullable=True)
    origin = db.Column(db.String(255), nullable=True)
    availability = db.Column(db.String(255), nullable=True)
    related_species = db.Column(db.String(255), nullable=True)
    climate = db.Column(db.String(255), nullable=True)
    soil = db.Column(db.String(255), nullable=True)
    image_name = db.Column(db.String(255), nullable=False)  # Image stored in static/herbal
    status = db.Column(db.String(20), default='pending') 

class MedicinalPlantsDiseases(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disease_name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    medicinal_plants_used = db.Column(db.Text, nullable=True)
    comabination = db.Column(db.String(255), nullable=False)  # Related Herbal Plants
    combination_description = db.Column(db.Text, nullable=True)
    image_name_one = db.Column(db.String(255), nullable=False)
    image_name_two = db.Column(db.String(255), nullable=False)
    image_name_three = db.Column(db.String(255), nullable=False)
    