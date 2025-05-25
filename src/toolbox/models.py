from toolbox import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def get_id(self):
        return str(self.id)  # Flask-Login attend une string

    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(100), unique=True, nullable=False)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=False)
    summary_json = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<ScanResult {self.scan_id} for {self.target}>'