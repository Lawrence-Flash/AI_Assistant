import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create database base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_key_for_testing")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cybersecurity.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the app with the extension
db.init_app(app)

# Import routes and models after initializing db to avoid circular imports
with app.app_context():
    from models import ScanResult
    from utils import run_nmap_scan, is_valid_target
    db.create_all()

@app.route('/')
def index():
    """Render the main page of the application"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Endpoint to handle scan requests"""
    target = request.form.get('target', '')
    
    if not is_valid_target(target):
        return jsonify({
            'success': False,
            'error': 'Invalid target. Please provide a valid IP address or domain name.'
        })
    
    # Run the scan
    success, result = run_nmap_scan(target)
    
    if success:
        # Save scan result to database
        scan_result = ScanResult(
            target=target,
            result=result,
            timestamp=datetime.now()
        )
        db.session.add(scan_result)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'result': result,
            'scan_id': scan_result.id
        })
    else:
        return jsonify({
            'success': False,
            'error': result  # Result contains error message
        })

@app.route('/scan/<int:scan_id>')
def scan_details(scan_id):
    """Display detailed results of a specific scan"""
    scan_result = ScanResult.query.get_or_404(scan_id)
    return render_template('scan_results.html', scan=scan_result)

@app.route('/history')
def history():
    """Display history of all scans"""
    scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template('history.html', scans=scans)

@app.route('/check_nmap', methods=['GET'])
def check_nmap_availability():
    """Check if Nmap is available on the system"""
    from utils import check_nmap
    return jsonify({'available': check_nmap()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
