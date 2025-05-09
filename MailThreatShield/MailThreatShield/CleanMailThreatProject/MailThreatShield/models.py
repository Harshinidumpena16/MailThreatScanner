import json
from datetime import datetime
from app import db

class ScanHistory(db.Model):
    """Model for storing email scan history in the database"""
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(20), unique=True, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    subject = db.Column(db.String(255), nullable=True)
    sender = db.Column(db.String(255), nullable=True)
    recipient = db.Column(db.String(255), nullable=True)
    threat_level = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Completed')
    
    # Store the full report as JSON
    full_report = db.Column(db.Text, nullable=True)
    
    def __init__(self, report_id, subject, sender, recipient, threat_level, full_report=None):
        self.report_id = report_id
        self.subject = subject
        self.sender = sender
        self.recipient = recipient
        self.threat_level = threat_level
        self.full_report = json.dumps(full_report) if full_report else None
    
    def to_dict(self):
        """Convert record to dictionary for API responses"""
        return {
            "report_id": self.report_id,
            "date": self.date.strftime("%b %d, %Y, %I:%M %p"),
            "subject": self.subject,
            "sender": self.sender,
            "threat_level": self.threat_level,
            "status": self.status
        }
    
    def get_full_report(self):
        """Get the full report as a dictionary"""
        if self.full_report:
            try:
                return json.loads(self.full_report)
            except:
                return None
        return None

class DashboardMetric(db.Model):
    """Model for storing dashboard metrics"""
    __tablename__ = 'dashboard_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Integer, nullable=False, default=0)
    previous_value = db.Column(db.Integer, nullable=False, default=0)
    
    def __init__(self, name, value=0, previous_value=0):
        self.name = name
        self.value = value
        self.previous_value = previous_value
    
    def calculate_change(self):
        """Calculate percentage change"""
        if self.previous_value > 0:
            return round(((self.value - self.previous_value) / self.previous_value) * 100)
        elif self.value > 0:
            return 100
        else:
            return 0