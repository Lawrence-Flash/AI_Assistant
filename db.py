import sqlite3
import os
from datetime import datetime

DB_FILE = 'cybersecurity.db'

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            scan_type TEXT DEFAULT 'fast',
            interval_hours INTEGER DEFAULT 24,
            last_scanned DATETIME
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diff_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            diff_text TEXT NOT NULL,
            alert_level TEXT DEFAULT 'info',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
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

def save_scan(target, result):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (target, result, timestamp)
        VALUES (?, ?, ?)
    ''', (target, result, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, timestamp, result FROM scan_results ORDER BY timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_latest_scan(target):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT result FROM scan_results WHERE target = ? ORDER BY timestamp DESC LIMIT 1
    ''', (target,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def get_watchlist():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, target, scan_type, interval_hours, last_scanned FROM watchlist
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows

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
