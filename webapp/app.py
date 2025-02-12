from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import numpy as np
import pickle
import requests
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
import sqlite3
from feature import FeatureExtraction
from convert import convertion

# Load the new model
with open("newmodel.pkl", "rb") as file:
    gbc = pickle.load(file)

app = Flask(__name__, static_folder='static')
CORS(app)

# Secret key for session management
app.secret_key = 'your_secret_key_here'  # Replace with a secure, random key

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# **Database Model for Reported URLs**
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)

# **Create Database Tables**
with app.app_context():
    db.create_all()

# **Initialize User Database**
def init_user_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT,
                            email TEXT UNIQUE,
                            password TEXT)''')
        conn.commit()

init_user_db()

# **Home Page**
@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

# **API to Report a URL (Requires Login)**
@app.route('/report', methods=['POST'])
def report_url():
    if 'user_email' not in session:
        return jsonify({'status': 'error', 'message': 'You must be logged in to report URLs.'}), 401

    data = request.json
    new_report = Report(email=session['user_email'], url=data['url'])
    db.session.add(new_report)
    db.session.commit()
    return jsonify({'message': 'Report saved successfully!'})

# **API to Fetch All Reports**
@app.route('/reports', methods=['GET'])
def get_reports():
    reports = Report.query.all()
    reports_list = [{'email': r.email, 'url': r.url, 'time': r.reported_at.strftime('%Y-%m-%d %H:%M:%S')} for r in reports]
    return jsonify(reports_list)

# **User Login**
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password required'}), 400

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        session['user_email'] = email  # Store user email in session
        return jsonify({'status': 'success', 'message': 'Login successful'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

# **User Logout**
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_email', None)
    return jsonify({'status': 'success', 'message': 'Logged out successfully'}), 200

# **User Signup**
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
            conn.commit()
        return jsonify({'status': 'success', 'message': 'Signup successful'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Email already registered'}), 400

# **Use Cases Page**
@app.route('/usecases', methods=['GET'])
def usecases():
    return render_template('usecases.html')

# **Blacklist for manually flagged phishing URLs**
BLACKLISTED_URLS = [
    "https://netmirror.app/",
    "http://malicious-site.com",
    "http://phishing-example.com"
]

# **Function to Check if a Website Exists**
def is_url_valid(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.status_code < 400
    except requests.RequestException:
        return False

# **URL Prediction**
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data['url']

        if url in BLACKLISTED_URLS:
            return jsonify({
                'url': url,
                'is_malicious': True,
                'confidence': 100.0,
                'prediction': "Phishing (Manually Blacklisted)",
                'status': 'success'
            })

        if not is_url_valid(url):
            return jsonify({
                'url': url,
                'is_malicious': True,
                'confidence': 100.0,
                'prediction': "Phishing (Non-Existent Website)",
                'status': 'success'
            })

        obj = FeatureExtraction(url)
        input_features = np.array(obj.getFeaturesList()).reshape(1, -1)

        prediction = gbc.predict(input_features)[0]
        confidence_score = gbc.predict_proba(input_features)[0, 1] * 100

        name = convertion(url, int(prediction))

        return jsonify({
            'url': url,
            'is_malicious': bool(prediction == -1),
            'confidence': float(confidence_score),
            'prediction': name,
            'status': 'success'
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
