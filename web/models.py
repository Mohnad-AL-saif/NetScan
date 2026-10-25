import sqlite3
import os
import json
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scanner.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            targets TEXT NOT NULL,
            ports TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            result_json TEXT,
            nmap_command TEXT,
            tcp_args TEXT,
            udp_args TEXT,
            udp_enabled BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            banner TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS finding_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            finding_id INTEGER NOT NULL,
            finding_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss REAL DEFAULT 0,
            cve TEXT,
            vulnerable BOOLEAN NOT NULL DEFAULT 0,
            detail TEXT,
            command TEXT,
            category TEXT DEFAULT 'misc',
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT
        );
    ''')
    conn.commit()

    admin = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin:
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('admin', generate_password_hash('admin123'), 'admin')
        )
        conn.commit()

    conn.close()


# --- User CRUD ---

def create_user(username, password, role='user'):
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            (username, generate_password_hash(password), role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def authenticate_user(username, password):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(u) for u in users]


def update_user_role(user_id, role):
    conn = get_db()
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


# --- Scan CRUD ---

def create_scan(user_id, name, targets, ports, tcp_args='', udp_args='', udp_enabled=False):
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO scans (user_id, name, targets, ports, status, tcp_args, udp_args, udp_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (user_id, name, targets, ports, 'running', tcp_args, udp_args, 1 if udp_enabled else 0)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def set_scan_nmap_command(scan_id, nmap_command):
    conn = get_db()
    conn.execute('UPDATE scans SET nmap_command = ? WHERE id = ?', (nmap_command, scan_id))
    conn.commit()
    conn.close()


def update_scan_status(scan_id, status, result_json=None):
    conn = get_db()
    if status in ('completed', 'failed', 'stopped'):
        conn.execute(
            'UPDATE scans SET status = ?, completed_at = ?, result_json = ? WHERE id = ?',
            (status, datetime.now().isoformat(), result_json, scan_id)
        )
    else:
        conn.execute(
            'UPDATE scans SET status = ?, result_json = ? WHERE id = ?',
            (status, result_json, scan_id)
        )
    conn.commit()
    conn.close()


def get_scan(scan_id):
    conn = get_db()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    return dict(scan) if scan else None


def get_user_scans(user_id, limit=None):
    conn = get_db()
    query = 'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC'
    if limit:
        query += f' LIMIT {int(limit)}'
    scans = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    return [dict(s) for s in scans]


def get_all_scans(limit=None):
    conn = get_db()
    query = 'SELECT scans.*, users.username FROM scans JOIN users ON scans.user_id = users.id ORDER BY scans.created_at DESC'
    if limit:
        query += f' LIMIT {int(limit)}'
    scans = conn.execute(query).fetchall()
    conn.close()
    return [dict(s) for s in scans]


def delete_scan(scan_id):
    conn = get_db()
    conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()


# --- Scan Results CRUD ---

def save_scan_results(scan_id, results):
    conn = get_db()
    for r in results:
        conn.execute(
            'INSERT INTO scan_results (scan_id, ip, port, protocol, state, service, banner) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (scan_id, r['ip'], r['port'], r['protocol'], r['state'], r['service'], r['banner'])
        )
    conn.commit()
    conn.close()


def save_scan_result(scan_id, port_data):
    """Save a single port result immediately when discovered. Dedup by (scan_id, ip, port, protocol)."""
    conn = get_db()
    existing = conn.execute(
        'SELECT id FROM scan_results WHERE scan_id=? AND ip=? AND port=? AND protocol=?',
        (scan_id, port_data['ip'], port_data['port'], port_data.get('protocol', 'tcp'))
    ).fetchone()
    if not existing:
        conn.execute(
            'INSERT INTO scan_results (scan_id, ip, port, protocol, state, service, banner) VALUES (?,?,?,?,?,?,?)',
            (scan_id, port_data['ip'], port_data['port'], port_data.get('protocol', 'tcp'),
             port_data.get('state', 'open'), port_data.get('service', ''), port_data.get('banner', ''))
        )
        conn.commit()
    conn.close()


def update_scan_result_details(scan_id, port_data):
    """Update a port's service/banner after Phase 2 completes."""
    conn = get_db()
    conn.execute(
        'UPDATE scan_results SET service=?, banner=? WHERE scan_id=? AND ip=? AND port=?',
        (port_data.get('service', ''), port_data.get('banner', ''),
         scan_id, port_data['ip'], port_data['port'])
    )
    conn.commit()
    conn.close()


def get_scan_results(scan_id):
    conn = get_db()
    results = conn.execute(
        'SELECT * FROM scan_results WHERE scan_id = ? ORDER BY ip, port', (scan_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in results]


# --- Finding Results CRUD ---

def save_finding_results(scan_id, findings):
    conn = get_db()
    for f in findings:
        conn.execute(
            '''INSERT INTO finding_results
            (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_id, f['ip'], f['port'], f['finding_id'], f['finding_name'],
             f['severity'], f['cvss'], f['cve'], f['vulnerable'], f['detail'], f.get('command', ''), f['category'])
        )
    conn.commit()
    conn.close()


def save_single_finding(scan_id, finding):
    """Save a single finding immediately when checked."""
    conn = get_db()
    conn.execute(
        '''INSERT INTO finding_results
        (scan_id, ip, port, finding_id, finding_name, severity, cvss, cve, vulnerable, detail, command, category)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (scan_id, finding['ip'], finding['port'], finding['finding_id'],
         finding['finding_name'], finding['severity'], finding['cvss'],
         finding['cve'], finding['vulnerable'], finding['detail'],
         finding.get('command', ''), finding['category'])
    )
    conn.commit()
    conn.close()


def get_finding_results(scan_id, severity=None, port=None, category=None, vulnerable_only=True):
    conn = get_db()
    query = 'SELECT * FROM finding_results WHERE scan_id = ?'
    params = [scan_id]

    if vulnerable_only:
        query += ' AND vulnerable = 1'
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if port:
        query += ' AND port = ?'
        params.append(int(port))
    if category:
        query += ' AND category = ?'
        params.append(category)

    query += ' ORDER BY CASE severity WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 WHEN "Low" THEN 4 ELSE 5 END, cvss DESC'

    results = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in results]


def get_finding_stats(scan_id):
    conn = get_db()
    stats = {}
    for sev in ('Critical', 'High', 'Medium', 'Low', 'Info'):
        count = conn.execute(
            'SELECT COUNT(*) FROM finding_results WHERE scan_id = ? AND vulnerable = 1 AND severity = ?',
            (scan_id, sev)
        ).fetchone()[0]
        stats[sev.lower()] = count
    stats['total'] = sum(stats.values())
    conn.close()
    return stats


def get_all_finding_categories(scan_id):
    conn = get_db()
    rows = conn.execute(
        'SELECT DISTINCT category FROM finding_results WHERE scan_id = ? AND vulnerable = 1 ORDER BY category',
        (scan_id,)
    ).fetchall()
    conn.close()
    return [r['category'] for r in rows]


def get_dashboard_stats(user_id):
    conn = get_db()
    scan_count = conn.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,)).fetchone()[0]
    total_findings = conn.execute(
        'SELECT COUNT(*) FROM finding_results fr JOIN scans s ON fr.scan_id = s.id WHERE s.user_id = ? AND fr.vulnerable = 1',
        (user_id,)
    ).fetchone()[0]
    critical_findings = conn.execute(
        'SELECT COUNT(*) FROM finding_results fr JOIN scans s ON fr.scan_id = s.id WHERE s.user_id = ? AND fr.vulnerable = 1 AND fr.severity = "Critical"',
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return {
        'scan_count': scan_count,
        'total_findings': total_findings,
        'critical_findings': critical_findings
    }


# --- Settings CRUD ---

def get_setting(key, default=None):
    conn = get_db()
    row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else default


def set_setting(key, value):
    conn = get_db()
    existing = conn.execute('SELECT id FROM settings WHERE key = ?', (key,)).fetchone()
    if existing:
        conn.execute('UPDATE settings SET value = ? WHERE key = ?', (value, key))
    else:
        conn.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()


def get_all_settings():
    conn = get_db()
    rows = conn.execute('SELECT key, value FROM settings ORDER BY key').fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}
