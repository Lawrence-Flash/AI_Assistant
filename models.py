from datetime import datetime
from extensions import db  # Import db from extensions

class ScanResult(db.Model):
    """Model for storing network scan results"""
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f'<ScanResult {self.id}: {self.target}>'
    
    def get_summary(self):
        """Extract a summary from the scan results"""
        try:
            lines = self.result.split('\n')
            open_ports = [line for line in lines if 'open' in line]
            return f"Found {len(open_ports)} open ports" if open_ports else "No open ports found"
        except Exception:
            return "Scan completed"
    
    def get_formatted_timestamp(self):
        """Return a nicely formatted timestamp string"""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")