from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .models import User, OTP, Prediction, Admin, MedicinalPlants, MedicinalPlantsDiseases
from .helpers import send_otp_signin, send_otp_reset, send_otp_signup
from . import db
import bcrypt
from datetime import datetime, timedelta
import random
from werkzeug.utils import secure_filename
import os
from urllib.parse import unquote

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

# Herbal Plants Page
@main.route("/herbal_plants")
def herbal_plants():
    search_query = request.args.get('search', '').lower()
    approved_plants = MedicinalPlants.query.filter_by(status='approved').all()

    if search_query:
        plants = [plant for plant in plants if search_query in plant.description.lower()]

    return render_template('herbal_plants.html', plants=approved_plants)

# Detailed Herbal Plant Page
@main.route("/herbal-plants/detail/<string:predicted_label>")
def herbal_plant_detail(predicted_label):
    predicted_label = unquote(predicted_label)  # ✅ Ensure correct decoding
    plant = MedicinalPlants.query.filter(MedicinalPlants.description.ilike(f"%{predicted_label}%")).first()

    if not plant:
        flash("Plant details not found.", "danger")
        return redirect(url_for("main.herbal_plants"))

    return render_template("herbal_plant_detail.html", plant=plant)



@main.route("/herbal_result")
def herbal_result():
    predicted_label = request.args.get("predicted_label")  # Get predicted plant name

    # Query the database to get the plant details by name
    plant = MedicinalPlants.query.filter_by(description=predicted_label).first()

    return render_template("herbal_result.html", predicted_label=predicted_label, plant=plant)


@main.route("/herbal_know")
def herbal_know():
    predicted_label = request.args.get("predicted_label")  # Get predicted plant name

    # Query the database to get the plant details by name
    plant = MedicinalPlants.query.filter_by(description=predicted_label).first()

    return render_template("herbal_know.html", predicted_label=predicted_label, plant=plant)




# Disease Page
@main.route("/diseases", methods=["GET", "POST"])
def diseases():
    diseases = MedicinalPlantsDiseases.query.all()

    if request.method == "POST":
        disease_id = request.form.get("disease")
        disease = MedicinalPlantsDiseases.query.get(disease_id)
        return render_template("disease.html", diseases=diseases, selected_disease=disease)

    return render_template("disease.html", diseases=diseases, selected_disease=None)

@main.route('/feedback', methods=['GET', 'POST'])
def feedback():
    return render_template('feedback.html')



# ✅ Define the absolute path for image storage
IMAGE_FOLDER = r"C:\Users\chand\OneDrive\Desktop\major\Medicinal_Plant\UI\app\static\plant"

@main.route('/Dynamic', methods=['GET', 'POST'])
def Dynamic():
    if request.method == 'POST':
        description = request.form['description']
        common_name = request.form['common_name']
        scientific_name = request.form['scientific_name']
        availability = request.form['availability']
        climate = request.form['climate']
        soil = request.form['soil']
        origin = request.form['origin']
        uses = request.form['uses']

        # ✅ Check if plant already exists
        plant = MedicinalPlants.query.filter_by(description=description).first()
        if plant:
            flash('Plant Already Exists.', 'danger')
            return render_template('submit_plant.html')

        # ✅ Handle the image file
        plant_image = request.files['image_name']
        image_filename = None
        if plant_image:
            filename = secure_filename(plant_image.filename)
            image_filename = filename  # ✅ Store only filename in DB

            # ✅ Ensure the target directory exists
            if not os.path.exists(IMAGE_FOLDER):
                os.makedirs(IMAGE_FOLDER)

            # ✅ Save the image to the specified directory
            image_save_path = os.path.join(IMAGE_FOLDER, filename)
            plant_image.save(image_save_path)

        # ✅ Create new plant entry with correct column names
        new_plant = MedicinalPlants(
            description=description,
            common_name=common_name,
            scientific_name=scientific_name,
            availability=availability,
            climate=climate,
            soil=soil,  # ✅ Use correct column name
            origin=origin,
            uses=uses,  # ✅ Use correct column name
            image_name=image_filename, # ✅ Store filename in DB
            status='pending'
        )

        db.session.add(new_plant)
        db.session.commit()

        flash('Plant submitted successfully!', 'success')
        return redirect(url_for('main.Dynamic'))

    return render_template('submit_plant.html')







@main.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password').encode('utf-8')

        # Fetch user from the database
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not registered.', 'danger')
            return render_template('signin.html')

        if not bcrypt.checkpw(password, user.password.encode('utf-8')):
            flash('Incorrect password.', 'danger')
            return render_template('signin.html')

        if user.status == 'inactive':
            flash('Waiting for admin approval.', 'warning')
            return render_template('signin.html')

        # Generate OTP and store in the database
        otp = random.randint(100000, 999999)
        otp_expiration = datetime.utcnow() + timedelta(minutes=10)

        otp_entry = OTP.query.filter_by(email=email).first()
        if otp_entry:
            otp_entry.otp = otp
            otp_entry.created_at = otp_expiration
        else:
            new_otp = OTP(email=email, otp=str(otp), created_at=otp_expiration)
            db.session.add(new_otp)

        db.session.commit()

        # Send OTP
        send_otp_signin(email, otp)
        flash('OTP sent to your email.', 'success')

        session['signin_email'] = email
        return redirect(url_for('main.verify_signin_otp'))

    return render_template('signin.html')



@main.route('/verify_signin_otp', methods=['GET', 'POST'])
def verify_signin_otp():
    email = session.get('signin_email')
    if not email:
        return redirect(url_for('main.signin'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        otp_entry = OTP.query.filter_by(email=email).first()

        if not otp_entry:
            flash('No OTP found for this email.', 'danger')
            return redirect(url_for('main.signin'))

        if otp_entry.created_at < datetime.utcnow():
            flash('OTP has expired.', 'danger')
            db.session.delete(otp_entry)
            db.session.commit()
            return redirect(url_for('main.signin'))

        if otp_entry.otp != entered_otp:
            flash('Incorrect OTP.', 'danger')
            return render_template('verify_signin_otp.html')

        # OTP validation successful
        db.session.delete(otp_entry)
        db.session.commit()
        user = User.query.filter_by(email=email).first()
        session['user_id'] = user.id
        session.pop('signin_email', None)
        flash('Sign in successful.', 'success')
        return redirect(url_for('main.herbal_plants'))

    return render_template('verify_signin_otp.html')


@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        mobile = request.form['mobile']
        dob = request.form['dob']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered.', 'danger')
            return render_template('signup.html')

        # Generate OTP and store it temporarily in the session
        otp = random.randint(100000, 999999)
        session['signup_data'] = {
            'name': name,
            'email': email,
            'password': hashed_password.decode('utf-8'),
            'mobile': mobile,
            'dob': dob,
            'security_question': security_question,
            'security_answer': security_answer,
            'otp': otp,
        }

        # Send OTP to the user's email
        send_otp_signup(email, otp)
        flash('OTP sent to your email for verification.', 'success')
        return redirect(url_for('main.verify_signup_otp'))

    return render_template('signup.html')

# verify_signup_otp
@main.route('/verify_signup_otp', methods=['GET', 'POST'])
def verify_signup_otp():
    signup_data = session.get('signup_data')
    if not signup_data:
        return redirect(url_for('main.signup'))

    if request.method == 'POST':
        entered_otp = request.form['otp']

        # Check if the OTP matches
        if str(signup_data['otp']) != entered_otp:
            flash('Incorrect OTP. Please try again.', 'danger')
            return render_template('verify_signup_otp.html')

        # Create user account after successful OTP verification
        new_user = User(
            name=signup_data['name'],
            email=signup_data['email'],
            password=signup_data['password'],
            mobile=signup_data['mobile'],
            dob=signup_data['dob'],
            security_question=signup_data['security_question'],
            security_answer=signup_data['security_answer'],
            status='inactive'  # Initially inactive, admin needs to activate
        )
        db.session.add(new_user)
        db.session.commit()

        # Clear session data after successful signup
        session.pop('signup_data', None)
        flash('Account created successfully. Waiting for admin approval.', 'success')
        return redirect(url_for('main.signin'))

    return render_template('verify_signup_otp.html')


@main.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You must be logged in to access the dashboard.', 'danger')
        return redirect(url_for('main.signin'))

    user = User.query.get(session['user_id'])

    if not user:
        flash('User not found. Please log in again.', 'danger')
        session.pop('user_id', None)
        return redirect(url_for('main.signin'))

    # Handle archived users
    if user.status == 'archived':
        return render_template('archived_dashboard.html', user=user)

    # Fetch prediction history for active users
    predictions = Prediction.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, predictions=predictions)



# Forgot Password
@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            session['reset_email'] = email  # Store email in session
            session['security_question'] = user.security_question  # Store security question
            flash('Email found. Answer the security question.', 'success')
            return redirect(url_for('main.security_question'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@main.route('/security_question', methods=['GET', 'POST'])
def security_question():
    email = session.get('reset_email')
    question = session.get('security_question')

    if not email or not question:
        flash('Session expired. Please try again.', 'warning')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        answer = request.form['security_answer']
        user = User.query.filter_by(email=email).first()

        if user and user.security_answer.lower() == answer.lower():
            otp = random.randint(100000, 999999)
            send_otp_reset(email, otp)  # Send OTP to email
            session['otp'] = otp  # Store OTP in session
            flash('Security answer correct. OTP sent to your email.', 'success')
            return redirect(url_for('main.verify_reset_otp'))
        else:
            flash('Incorrect security answer.', 'danger')

    return render_template('security_question.html', question=question)


# OTP Verification
@main.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    email = session.get('reset_email')
    otp = session.get('otp')

    if not email or not otp:
        flash('Session expired. Please try again.', 'warning')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        if str(otp) == entered_otp:
            flash('OTP verified. You can now reset your password.', 'success')
            return redirect(url_for('main.reset_password'))
        else:
            flash('Incorrect OTP. Please try again.', 'danger')

    return render_template('verify_reset_otp.html')




# Reset Password
@main.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')

    if not email:
        flash('Session expired. Please try again.', 'warning')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')

        if new_password == confirm_password:
            hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
            user = User.query.filter_by(email=email).first()
            user.password = hashed_password.decode('utf-8')
            db.session.commit()
            flash('Password reset successful. You can now log in.', 'success')
            session.pop('reset_email', None)  # Clear session data
            session.pop('otp', None)
            session.pop('security_question', None)
            return redirect(url_for('main.signin'))
        else:
            flash('Passwords do not match.', 'danger')

    return render_template('reset_password.html')


# Admin Login
@main.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        admin_user = Admin.query.filter_by(username=username).first()

        if admin_user and bcrypt.checkpw(password, admin_user.password.encode('utf-8')):
            session['admin'] = admin_user.id
            flash('Welcome Admin!', 'success')
            return redirect(url_for('main.admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('admin_login.html')

# Admin Dashboard
from flask import jsonify  # For passing data to JavaScript

@main.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('main.admin_login'))

    # Data for total users by status
    active_users = User.query.filter_by(status='active').count()
    inactive_users = User.query.filter_by(status='inactive').count()
    archived_users = User.query.filter_by(status='archived').count()
    deleted_users = User.query.filter_by(status='deleted').count()

    # Top 5 users by prediction count
    top_users = db.session.query(
        User.name, db.func.count(Prediction.id).label('predictions')
    ).join(Prediction).group_by(User.id).order_by(db.desc('predictions')).limit(5).all()

    top_users_data = {
        "labels": [user.name for user in top_users],
        "values": [user.predictions for user in top_users],
    }
    print("Top Users Data:", top_users_data)
    

    # Predictions by type
    prediction_counts = db.session.query(
        Prediction.prediction_type, db.func.count(Prediction.id)
    ).group_by(Prediction.prediction_type).all()

    prediction_data = {
        "labels": [prediction[0] for prediction in prediction_counts],
        "values": [prediction[1] for prediction in prediction_counts],
    }
    print("Prediction Data:", prediction_data)

    return render_template(
        'admin_dashboard.html',
        active_users=active_users,
        inactive_users=inactive_users,
        archived_users=archived_users,
        deleted_users=deleted_users,
        top_users_data=top_users_data,
        prediction_data=prediction_data,
    )

# Manage Users
@main.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if not session.get('admin'):
        return redirect(url_for('main.admin_login'))

    users = User.query.all()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)

        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('main.manage_users'))

        if action == 'archive':
            user.status = 'archived'
            db.session.commit()
            flash(f'User {user.name} archived.', 'warning')
        elif action == 'activate':
            user.status = 'active'
            db.session.commit()
            flash(f'User {user.name} activated.', 'success')
        elif action == 'delete':
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.name} deleted.', 'danger')

    return render_template('manage_users.html', users=users)

import csv
from io import StringIO
from flask import Response

@main.route('/download_prediction_history')
def download_prediction_history():
    if not session.get('admin'):
        flash("You must be logged in as admin to download the prediction history.", "danger")
        return redirect(url_for('main.admin_login'))

    # Query prediction data
    predictions = db.session.query(
        Prediction.id, User.name, Prediction.prediction_type,
        Prediction.input_data, Prediction.result, Prediction.created_at
    ).join(User).all()

    # Create a CSV file in memory
    si = StringIO()
    writer = csv.writer(si)
    # Write the header row
    writer.writerow(['ID', 'User', 'Type', 'Input', 'Result', 'Date'])
    # Write the data rows
    for prediction in predictions:
        writer.writerow([prediction.id, prediction.name, prediction.prediction_type, 
                         prediction.input_data, prediction.result, prediction.created_at])

    # Generate the response
    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers['Content-Disposition'] = 'attachment; filename=prediction_history.csv'
    return output

# Prediction History
@main.route('/prediction_history')
def prediction_history():
    if not session.get('admin'):
        return redirect(url_for('main.admin_login'))

    predictions = db.session.query(
        Prediction.id, User.name, Prediction.prediction_type,
        Prediction.input_data, Prediction.result, Prediction.created_at
    ).join(User).all()

    return render_template('prediction_history.html', predictions=predictions)

@main.route('/logout')
def logout():
    # Handle user logout
    if 'user_id' in session:
        session.pop('user_id', None)  # Clear user session
        flash('You have been logged out.', 'success')
        return redirect(url_for('main.signin'))

    # Handle admin logout
    if 'admin' in session:
        session.pop('admin', None)  # Clear admin session
        flash('Admin has been logged out.', 'success')
        return redirect(url_for('main.admin_login'))

    # Fallback for unauthorized access to logout
    flash('You are not logged in.', 'info')
    return redirect(url_for('main.index'))



#@main.route('/approve_plants')
#def approve_plants():
#pending_plants = MedicinalPlants.query.filter_by(status='pending').all()
#return render_template('main.approval.html', plants=pending_plants)


@main.route('/approve/<int:plant_id>', methods=['POST'])
def approve_plant(plant_id):
    plant = MedicinalPlants.query.get_or_404(plant_id)
    plant.status = 'approved'
    db.session.commit()
    flash(f'{plant.common_name} approved!', 'success')
    return redirect(url_for('main.approve_plants'))

@main.route('/reject/<int:plant_id>', methods=['POST'])
def reject_plant(plant_id):
    plant = MedicinalPlants.query.get_or_404(plant_id)
    
    # Delete the plant from the database
    db.session.delete(plant)
    db.session.commit()
    
    flash(f'{plant.common_name} has been rejected and removed from the database.', 'danger')
    return redirect(url_for('main.approve_plants'))


@main.route('/approve_plants')
def approve_plants():
    plants = MedicinalPlants.query.filter_by(status='pending').all()
    return render_template('approve_plants.html', plants=plants)

@main.route('/download_pending_plants')
def download_pending_plants():
    if not session.get('admin'):
        flash("You must be logged in as admin to download the pending plant submissions.", "danger")
        return redirect(url_for('main.admin_login'))

    # Query pending plant submissions
    pending_plants = db.session.query(
        MedicinalPlants.id, MedicinalPlants.common_name, MedicinalPlants.scientific_name,
        MedicinalPlants.description, MedicinalPlants.availability, MedicinalPlants.climate,
        MedicinalPlants.soil, MedicinalPlants.origin, MedicinalPlants.uses, MedicinalPlants.status
    ).filter_by(status='pending').all()

    # Create a CSV file in memory
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Common Name', 'Scientific Name', 'Description', 'Availability',
                     'Climate', 'Soil', 'Origin', 'Uses', 'Status'])

    for plant in pending_plants:
        writer.writerow([plant.id, plant.common_name, plant.scientific_name, plant.description,
                         plant.availability, plant.climate, plant.soil, plant.origin,
                         plant.uses, plant.status])

    # Generate the response
    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers['Content-Disposition'] = 'attachment; filename=pending_plants.csv'
    return output

