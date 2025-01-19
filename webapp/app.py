from flask import Flask, request, jsonify, render_template
from tensorflow import keras
from urllib.parse import urlparse
import numpy as np
import re
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

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
    app.run(host='0.0.0.0', port=5001)