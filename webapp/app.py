from flask import Flask, request, jsonify, render_template
from tensorflow import keras
from urllib.parse import urlparse
import numpy as np
import re
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
import sqlite3



app = Flask(__name__, static_folder='static')
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model for Reported URLs
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

# API to Report a URL
@app.route('/report', methods=['POST'])
def report_url():
    data = request.json
    new_report = Report(email=data['email'], url=data['url'])
    db.session.add(new_report)
    db.session.commit()
    return jsonify({'message': 'Report saved successfully!'})

# API to Fetch All Reports
@app.route('/reports', methods=['GET'])
def get_reports():
    reports = Report.query.all()
    reports_list = [{'email': r.email, 'url': r.url, 'time': r.reported_at.strftime('%Y-%m-%d %H:%M:%S')} for r in reports]
    return jsonify(reports_list)

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
        return jsonify({'status': 'success', 'message': 'Login successful'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
    
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


# Load the model
def load_model():
    return keras.models.load_model('Malicious_URL_Prediction.h5')  # Adjusted path

model = load_model()

# Feature extraction functions
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
    
def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1

def is_legitimate_domain(url):
    legitimate_domains = {
        'google.com',
        'mail.google.com',
        'gmail.com',
        'whatsapp.com',
        'web.whatsapp.com',
        'youtube.com',
        'facebook.com',
        'microsoft.com',
        'outlook.com',
        'linkedin.com',
        'github.com',
        'apple.com',
        'icloud.com',
        'amazon.com',
        "github.com"
    }
    
    try:
        domain = urlparse(url).netloc.lower()
        return any(domain.endswith(legitimate) for legitimate in legitimate_domains)
    except:
        return False

def extract_features(url):
    # 'hostname_length', 'path_length', 'fd_length', 'count-', 'count@', 'count?', 'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits','count-letters', 'count_dir', 'use_of_ip'
    hostname_length = len(urlparse(url).netloc)
    path_length = len(urlparse(url).path)
    f_length = fd_length(url)
    count_1 = url.count('-')
    count_2 = url.count('@')
    count_3 = url.count('?')
    count_4 = url.count('%')
    count_5 = url.count('.')
    count_6 = url.count('=')
    count_7 = url.count('http')
    count_8 = url.count('https')
    count_9 = url.count('www')
    count_10 = digit_count(url)
    count_11 = letter_count(url)
    count_12 = no_of_dir(url)
    count_13 = having_ip_address(url)
    output = [hostname_length, path_length, f_length, count_1, count_2, count_3, count_4, count_5, count_6, count_7, count_8, count_9, count_10, count_11, count_12, count_13]
    print(output)
    features = np.array([output]) 
    return features

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data['url']
        
        # Check for legitimate domains first
        if is_legitimate_domain(url):
            return jsonify({
                'url': url,
                'is_malicious': False,
                'confidence': 5.0,  # Low percentage indicates high confidence in safety
                'status': 'success'
            })
            
        # Your existing prediction code
        input_features = extract_features(url)
        prediction = model.predict(input_features)
        percentage_value = prediction[0][0] * 100
        
        return jsonify({
            'url': url,
            'is_malicious': bool(prediction[0] >= 0.5),
            'confidence': float(percentage_value),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True)