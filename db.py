import sqlite3
import os
from datetime import datetime

DB_FILE = 'cybersecurity.db'

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Core scan results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            nmap_result TEXT,
            osint_result TEXT,
            ai_analysis TEXT,
            risk_level TEXT DEFAULT 'LOW',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Safe migration for existing databases missing new structured columns
    for col_def in [
        ("nmap_result", "TEXT"),
        ("osint_result", "TEXT"),
        ("ai_analysis", "TEXT"),
        ("risk_level", "TEXT DEFAULT 'LOW'"),
        ("client_tag", "TEXT DEFAULT 'General'"),
        ("analyst_notes", "TEXT DEFAULT ''")
    ]:
        try:
            cursor.execute(f"ALTER TABLE scan_results ADD COLUMN {col_def[0]} {col_def[1]}")
        except sqlite3.OperationalError:
            pass # Column already exists
            
    # Watchlist for continuous monitoring
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            scan_type TEXT DEFAULT 'fast',
            interval_hours INTEGER DEFAULT 24,
            last_scanned DATETIME
        )
    ''')
    
    # Attack surface diff logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diff_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            diff_text TEXT NOT NULL,
            alert_level TEXT DEFAULT 'info',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Persistent key-value settings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    # OSINT archives
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS osint_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def save_scan(target, result, nmap_result=None, osint_result=None, ai_analysis=None, risk_level="LOW", client_tag="General", analyst_notes=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (target, result, nmap_result, osint_result, ai_analysis, risk_level, client_tag, analyst_notes, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        target, 
        result, 
        nmap_result or "", 
        osint_result or "", 
        ai_analysis or "", 
        risk_level or "LOW",
        client_tag or "General",
        analyst_notes or "",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, timestamp, result, risk_level, client_tag, analyst_notes FROM scan_results ORDER BY timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_scan_by_id(scan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, timestamp, result, nmap_result, osint_result, ai_analysis, risk_level, client_tag, analyst_notes 
        FROM scan_results 
        WHERE id = ?
    ''', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "target": row[1],
        "timestamp": row[2],
        "result": row[3],
        "nmap_result": row[4] or "",
        "osint_result": row[5] or "",
        "ai_analysis": row[6] or "",
        "risk_level": row[7] or "LOW",
        "client_tag": row[8] or "General",
        "analyst_notes": row[9] or ""
    }

def update_scan_notes(scan_id, analyst_notes, client_tag=None):
    conn = get_connection()
    cursor = conn.cursor()
    if client_tag is not None:
        cursor.execute('''
            UPDATE scan_results SET analyst_notes = ?, client_tag = ? WHERE id = ?
        ''', (analyst_notes, client_tag, scan_id))
    else:
        cursor.execute('''
            UPDATE scan_results SET analyst_notes = ? WHERE id = ?
        ''', (analyst_notes, scan_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def delete_scan(scan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_results WHERE id = ?', (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def get_latest_scan(target):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT nmap_result, result FROM scan_results WHERE target = ? ORDER BY timestamp DESC LIMIT 1
    ''', (target,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0] if row[0] else row[1]
    return None

def get_watchlist():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, scan_type, interval_hours, last_scanned FROM watchlist ORDER BY id DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_watchlist_target(target_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, scan_type, interval_hours, last_scanned FROM watchlist WHERE id = ?
    ''', (target_id,))
    row = cursor.fetchone()
    conn.close()
    return row

def add_to_watchlist(target, scan_type="fast", interval_hours=24):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO watchlist (target, scan_type, interval_hours)
            VALUES (?, ?, ?)
        ''', (target, scan_type, interval_hours))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def delete_from_watchlist(target_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM watchlist WHERE id = ?', (target_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def update_watchlist_time(target):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE watchlist SET last_scanned = ? WHERE target = ?
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), target))
    conn.commit()
    conn.close()

def save_diff_log(target, diff_text, alert_level='info'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO diff_logs (target, diff_text, alert_level, timestamp)
        VALUES (?, ?, ?, ?)
    ''', (target, diff_text, alert_level, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_diff_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, diff_text, alert_level, timestamp FROM diff_logs ORDER BY timestamp DESC LIMIT 50
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_setting(key, default_value=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default_value

def set_setting(key, value):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    ''', (key, value))
    conn.commit()
    conn.close()

def save_osint(target, result):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO osint_results (target, result, timestamp)
        VALUES (?, ?, ?)
    ''', (target, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_latest_osint(target):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT result FROM osint_results WHERE target = ? ORDER BY timestamp DESC LIMIT 1
    ''', (target,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None
