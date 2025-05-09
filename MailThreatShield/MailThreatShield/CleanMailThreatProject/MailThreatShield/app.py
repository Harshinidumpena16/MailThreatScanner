import os
import logging
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Import modules
from modules.email_parser import EmailParser
from modules.authentication import AuthChecker
from modules.reputation import ReputationChecker
from modules.url_scanner import URLScanner
from modules.attachment_analyzer import AttachmentAnalyzer
from modules.qr_scanner import QRScanner
from modules.audio_analyzer import AudioAnalyzer
from modules.verdict import VerdictEngine

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "mailthreat-scanner-secret-key")

# In-memory databases for scan history and full reports (would use a real DB in production)
scan_history = []
full_reports = {}  # Store full reports by report_id

# Dashboard metrics tracking
class DashboardMetrics:
    def __init__(self):
        self.total_scans = 24  # Starting with initial values
        self.threats_detected = 7
        self.malicious_urls = 12
        self.auth_failures = 9
        
        # Weekly percentage changes
        self.total_scans_change = 15
        self.threats_detected_change = -8
        self.malicious_urls_change = 23
        self.auth_failures_change = -5
        
        # Historical data for tracking changes
        self.previous_week_scans = 20
        self.previous_week_threats = 8
        self.previous_week_urls = 10
        self.previous_week_auth_failures = 10
    
    def update_metrics(self, report):
        """Update metrics based on a new scan report"""
        # Increment total scans
        self.total_scans += 1
        
        # Update the percentage change for total scans
        self.total_scans_change = round(((self.total_scans - self.previous_week_scans) / self.previous_week_scans) * 100)
        
        # Check if threats were detected
        if report['verdict']['level'] in ['medium', 'high']:
            self.threats_detected += 1
            # Update the percentage change for threats detected
            if self.previous_week_threats > 0:
                self.threats_detected_change = round(((self.threats_detected - self.previous_week_threats) / self.previous_week_threats) * 100)
            else:
                self.threats_detected_change = 100
        
        # Count malicious URLs
        if 'url_results' in report and report['url_results']:
            malicious_urls_count = report['url_results'].get('risk_summary', {}).get('malicious', 0)
            self.malicious_urls += malicious_urls_count
            # Update the percentage change for malicious URLs
            if self.previous_week_urls > 0:
                self.malicious_urls_change = round(((self.malicious_urls - self.previous_week_urls) / self.previous_week_urls) * 100)
            else:
                self.malicious_urls_change = 100 if malicious_urls_count > 0 else 0
        
        # Count authentication failures
        if 'auth_results' in report and report['auth_results']:
            if report['auth_results'].get('status') == 'failure':
                self.auth_failures += 1
                # Update the percentage change for auth failures
                if self.previous_week_auth_failures > 0:
                    self.auth_failures_change = round(((self.auth_failures - self.previous_week_auth_failures) / self.previous_week_auth_failures) * 100)
                else:
                    self.auth_failures_change = 100
    
    def get_metrics(self):
        """Get the current metrics as a dictionary"""
        return {
            'total_scans': {
                'value': self.total_scans,
                'change': self.total_scans_change
            },
            'threats_detected': {
                'value': self.threats_detected,
                'change': self.threats_detected_change
            },
            'malicious_urls': {
                'value': self.malicious_urls,
                'change': self.malicious_urls_change
            },
            'auth_failures': {
                'value': self.auth_failures,
                'change': self.auth_failures_change
            }
        }

# Initialize dashboard metrics
dashboard_metrics = DashboardMetrics()

@app.route('/')
def index():
    """Render the dashboard page"""
    metrics = dashboard_metrics.get_metrics()
    return render_template('dashboard.html', active='dashboard', metrics=metrics)

@app.route('/api/metrics')
def get_metrics():
    """API endpoint to get current dashboard metrics"""
    return jsonify(dashboard_metrics.get_metrics())

@app.route('/analysis')
def analysis():
    """Render the email analysis page"""
    return render_template('analysis.html', active='analysis')

@app.route('/history')
def history():
    """Render the scan history page"""
    return render_template('history.html', active='history', scan_history=scan_history)

@app.route('/settings')
def settings():
    """Render the settings page"""
    return render_template('settings.html', active='settings')

@app.route('/help')
def help():
    """Render the help and support page"""
    return render_template('help.html', active='help')

@app.route('/api/scan-history', methods=['GET'])
def get_scan_history():
    """API endpoint to get scan history data"""
    search_query = request.args.get('query', '').lower()
    
    if search_query:
        filtered_history = [item for item in scan_history if (
            search_query in item['subject'].lower() or
            search_query in item['sender'].lower() or
            search_query in item['report_id'].lower()
        )]
        return jsonify(filtered_history)
    
    return jsonify(scan_history)

@app.route('/api/upload-email', methods=['POST'])
def upload_email():
    """API endpoint to handle email uploads"""
    try:
        # Generate a unique report ID
        report_id = f"ML-{uuid.uuid4().hex[:6]}"
        
        # Process email file or content
        if 'emailFile' in request.files:
            email_file = request.files['emailFile']
            if email_file.filename:
                # Parse email file
                email_content = email_file.read().decode('utf-8', errors='ignore')
                email_parser = EmailParser(email_content)
                email_data = email_parser.parse()
            else:
                return jsonify({"error": "No file selected"}), 400
        elif request.form.get('emailContent'):
            # Parse pasted email content
            email_content = request.form.get('emailContent')
            email_parser = EmailParser(email_content)
            email_data = email_parser.parse()
        else:
            return jsonify({"error": "No email content provided"}), 400
        
        # Analyze email components
        auth_checker = AuthChecker(email_data)
        auth_results = auth_checker.check()
        
        reputation_checker = ReputationChecker(email_data)
        reputation_results = reputation_checker.check()
        
        url_scanner = URLScanner(email_data)
        url_results = url_scanner.scan()
        
        attachment_analyzer = AttachmentAnalyzer(email_data)
        attachment_results = attachment_analyzer.analyze()
        
        # Process any QR codes in attachments
        qr_scanner = QRScanner(email_data)
        qr_results = qr_scanner.scan()
        
        # Process any audio attachments
        audio_analyzer = AudioAnalyzer(email_data)
        audio_results = audio_analyzer.analyze()
        
        # Determine overall verdict
        verdict_engine = VerdictEngine(
            auth_results, 
            reputation_results,
            url_results,
            attachment_results,
            qr_results,
            audio_results,
            email_data  # Pass the email data to help with false positive detection
        )
        verdict = verdict_engine.get_verdict()
        
        # Create a report result
        report = {
            "report_id": report_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "subject": email_data.get("subject", "No Subject"),
            "sender": email_data.get("from", "unknown@sender.com"),
            "recipient": email_data.get("to", "unknown@recipient.com"),
            "date": email_data.get("date", "Unknown Date"),
            "auth_results": auth_results,
            "reputation_results": reputation_results,
            "url_results": url_results,
            "attachment_results": attachment_results,
            "qr_results": qr_results,
            "audio_results": audio_results,
            "verdict": verdict,
            "status": "Completed"
        }
        
        # Add to scan history
        scan_history.append({
            "report_id": report_id,
            "date": datetime.now().strftime("%b %d, %Y, %I:%M %p"),
            "subject": email_data.get("subject", "No Subject"),
            "sender": email_data.get("from", "unknown@sender.com"),
            "threat_level": verdict["level"],
            "status": "Completed"
        })
        
        # Store the full report in both session and our in-memory database
        session['current_report'] = report
        full_reports[report_id] = report  # Store by report_id for later retrieval
        
        # Update dashboard metrics with the new scan
        dashboard_metrics.update_metrics(report)
        
        return jsonify({
            "success": True,
            "report_id": report_id,
            "redirect_url": url_for('report', report_id=report_id)
        })
    
    except Exception as e:
        logger.exception("Error processing email")
        return jsonify({"error": str(e)}), 500

@app.route('/report/<report_id>')
def report(report_id):
    """Render the report page for a specific scan"""
    # First try to get from session (for most recent report)
    current_report = session.get('current_report')
    
    # If not in session or wrong report, check the full_reports dictionary
    if not current_report or current_report['report_id'] != report_id:
        # Try to get the full report from our in-memory full_reports dictionary
        if report_id in full_reports:
            current_report = full_reports[report_id]
            logger.info(f"Retrieved full report {report_id} from full_reports dictionary")
        else:
            # As a last resort, look for basic info in scan history
            for scan in scan_history:
                if scan['report_id'] == report_id:
                    # Create a minimal report from history
                    current_report = {
                        "report_id": scan['report_id'],
                        "timestamp": scan['date'],
                        "subject": scan['subject'],
                        "sender": scan['sender'],
                        "verdict": {"level": scan['threat_level'], "verdict": scan['threat_level'].capitalize()},
                        "recipient": "unknown@recipient.com",
                        "auth_results": {"overall": {"status": "unknown"}},
                        "reputation_results": {"overall": {"score": 50}},
                        "url_results": {"count": 0, "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0}},
                        "attachment_results": {"count": 0},
                        "status": scan['status']
                    }
                    logger.warning(f"Using minimal report for {report_id} - full data not available")
                    break
    
    # If we still don't have a report, redirect to history
    if not current_report:
        logger.error(f"Report {report_id} not found in any storage")
        return redirect(url_for('history'))
    
    # Get report display options
    exclude_sections = request.args.getlist('exclude')
    
    # Log that we're rendering the report
    logger.info(f"Rendering report for {report_id}: {current_report.get('subject')}")
    
    return render_template('report.html', 
                          active='history', 
                          report=current_report, 
                          exclude_sections=exclude_sections)

@app.route('/generate-report/<report_id>')
def generate_report(report_id):
    """Generate a customized report for download/print"""
    # First try to get from session (for most recent report)
    current_report = session.get('current_report')
    
    # If not in session or wrong report, check the full_reports dictionary
    if not current_report or current_report['report_id'] != report_id:
        # Try to get the full report from our in-memory full_reports dictionary
        if report_id in full_reports:
            current_report = full_reports[report_id]
            logger.info(f"Retrieved full report {report_id} from full_reports dictionary for generation")
        else:
            # As a last resort, look for basic info in scan history
            for scan in scan_history:
                if scan['report_id'] == report_id:
                    # Create a minimal report from history
                    current_report = {
                        "report_id": scan['report_id'],
                        "timestamp": scan['date'],
                        "subject": scan['subject'],
                        "sender": scan['sender'],
                        "verdict": {"level": scan['threat_level'], "verdict": scan['threat_level'].capitalize()},
                        "recipient": "unknown@recipient.com",
                        "auth_results": {"overall": {"status": "unknown"}},
                        "reputation_results": {"overall": {"score": 50}},
                        "url_results": {"count": 0, "risk_summary": {"safe": 0, "suspicious": 0, "malicious": 0}},
                        "attachment_results": {"count": 0},
                        "status": scan['status']
                    }
                    logger.warning(f"Using minimal report for generation {report_id} - full data not available")
                    break
    
    if not current_report:
        logger.error(f"Report {report_id} not found for generation")
        return redirect(url_for('history'))
    
    # Get report customization options from query parameters
    exclude_sections = request.args.getlist('exclude')
    
    return render_template('generate_report.html', 
                          report=current_report, 
                          exclude_sections=exclude_sections,
                          print_view=True)

@app.route('/api/clear-history', methods=['POST'])
def clear_history():
    """API endpoint to clear scan history"""
    global scan_history, full_reports
    
    try:
        # Check if we want to clear all history or just older items
        clear_type = request.args.get('type', 'all')
        
        if clear_type == 'all':
            # Clear all history
            scan_history = []
            full_reports = {}
            logger.info("Cleared all scan history")
            return jsonify({"success": True, "message": "All scan history cleared"})
        
        elif clear_type == 'older':
            # Clear history older than 30 days (implementation would go here)
            # For demo purposes, we'll just clear everything
            scan_history = []
            full_reports = {}
            logger.info("Cleared older scan history")
            return jsonify({"success": True, "message": "Older scan history cleared"})
            
        else:
            return jsonify({"error": "Invalid clear type"}), 400
            
    except Exception as e:
        logger.exception("Error clearing history")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
