from toolbox import db
from flask_login import UserMixin
from datetime import datetime, timezone

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
    
class SQLMapScanResult(db.Model):
    __tablename__ = 'sql_map_scan_results'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(128), unique=True, nullable=False)
    target_url = db.Column(db.String, nullable=False)
    method = db.Column(db.String(10), default='GET')
    output_file = db.Column(db.String(255))
    raw_output = db.Column(db.Text)
    task_id = db.Column(db.String, unique=True)
    task_type = db.Column(db.String, default="sqlmap")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=True) 
    summary_json = db.Column(db.Text, nullable=False, default='{}') 
    dbms = db.Column(db.String, nullable=True)
    vulnerabilities = db.Column(db.Text, nullable=True)
    enable_forms_crawl = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f"<SQLMapScanResult scan_id={self.scan_id} target_url={self.target_url}>"

class HydraScanResult(db.Model):
    __tablename__ = 'hydra_scan_results'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(128), unique=True, nullable=False)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=True) 
    summary_json = db.Column(db.Text, nullable=False, default='{}')

    def __repr__(self):
        return f"<HydraScanResult scan_id={self.scan_id} target={self.target}>"
    
class ZAPScanResult(db.Model):
    __tablename__ = 'zap_scan_results'
    id = db.Column(db.Integer, primary_key=True)
    # On passe scan_id en String(255) pour pouvoir y loger l’URL complète + suffixe
    scan_id = db.Column(db.String(255), unique=True, nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    target_url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=True)
    summary_json = db.Column(db.Text, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    task_id = db.Column(db.String(100), nullable=True)
    task_type = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f'<ZAPScanResult {self.scan_id}>'    

class TimelineEvent(db.Model):
    __tablename__ = 'timeline_events'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    scan_id = db.Column(db.String(255), nullable=True)  # si applicable
    user = db.Column(db.String(100), nullable=True)  # optionnel : qui a déclenché l’action

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.replace(tzinfo=timezone.utc).isoformat(),
            'event_type': self.event_type,
            'message': self.message,
            'scan_id': self.scan_id,
            'user': self.user
        }