from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow frontend to communicate with backend

# SQLite Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reports.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model for Reported URLs
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create Database Tables
with app.app_context():
    db.create_all()

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

if __name__ == '__main__':
    app.run(debug=True)
