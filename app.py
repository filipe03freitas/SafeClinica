import datetime
import sqlite3
import os
from flask import Flask, render_template, redirect, send_from_directory, url_for, request, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from collections import deque

app = Flask(__name__)
app.secret_key = 'tester'  
CORS(app) 
socketio = SocketIO(app, cors_allowed_origins="*")

security_events = deque(maxlen=100)  
connected_devices = {}

def init_db():
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS clinics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT UNIQUE,
                 admin_user TEXT UNIQUE,
                 admin_password TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 clinic_id INTEGER,
                 timestamp TEXT,
                 ip TEXT,
                 event_type TEXT,
                 description TEXT,
                 severity TEXT,
                 FOREIGN KEY (clinic_id) REFERENCES clinics(id))''')
    
    conn.commit()
    conn.close()

def log_alert(clinic_id, ip, event_type, description, severity="medium"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    c.execute("INSERT INTO alerts (clinic_id, timestamp, ip, event_type, description, severity) VALUES (?, ?, ?, ?, ?, ?)",
              (clinic_id, timestamp, ip, event_type, description, severity))
    conn.commit()
    conn.close()
    
    event_data = {
        'timestamp': timestamp,
        'ip': ip,
        'event': description,
        'level': severity,
        'clinic_id': clinic_id
    }
    socketio.emit('new_security_event', event_data, room=f'clinic_{clinic_id}')

def get_current_devices(clinic_id):
    return {ip: time.isoformat() for ip, time in connected_devices.items()}

def get_recent_alerts(clinic_id, limit=10):
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, ip, description, severity 
        FROM alerts 
        WHERE clinic_id = ? 
        ORDER BY timestamp DESC 
        LIMIT ?
    """, (clinic_id, limit))
    alerts = [{
        'timestamp': row[0],
        'ip': row[1],
        'event': row[2],
        'level': row[3]
    } for row in c.fetchall()]
    conn.close()
    return alerts

@app.route('/')
def index():
    """Redireciona automaticamente para a tela de login"""
    return redirect(url_for('login'))

@app.route('/dynamic-config.js')
def dynamic_config():
    return f"""
    window.APP_CONFIG = {{
        API_BASE_URL: "{request.host_url}",
        NGROK_URL: "https://e985-168-181-51-223.ngrok-free.app"
    }};
    """, 200, {'Content-Type': 'application/javascript'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('safeclinica.db')
        c = conn.cursor()
        c.execute("SELECT id, name, admin_password FROM clinics WHERE admin_user = ?", (username,))
        clinic = c.fetchone()
        conn.close()
        
        if clinic and check_password_hash(clinic[2], password):
            session['clinic_id'] = clinic[0]
            session['clinic_name'] = clinic[1]
            log_alert(clinic[0], request.remote_addr, 'login', 'Login bem-sucedido', 'info')
            return redirect(url_for('clinic_dashboard'))
        
        flash('Usuário ou senha incorretos')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        clinic_name = request.form['clinic_name']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            conn = sqlite3.connect('safeclinica.db')
            c = conn.cursor()
            c.execute("INSERT INTO clinics (name, admin_user, admin_password) VALUES (?, ?, ?)",
                      (clinic_name, username, password))
            clinic_id = c.lastrowid
            conn.commit()
            conn.close()
            
            log_alert(clinic_id, request.remote_addr, 'registration', 'Nova clínica registrada', 'info')
            flash('Cadastro realizado com sucesso! Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nome da clínica ou usuário já existente')
    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'clinic_id' in session:
        log_alert(session['clinic_id'], request.remote_addr, 'logout', 'Usuário deslogado', 'info')
    session.clear()
    return redirect(url_for('login'))

@app.route('/clinic/dashboard')
def clinic_dashboard():
    if 'clinic_id' not in session:
        return redirect(url_for('login'))
    
    clinic_id = session['clinic_id']
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    c.execute("""
        SELECT id, timestamp, ip, event_type, description, severity 
        FROM alerts 
        WHERE clinic_id = ? 
        ORDER BY timestamp DESC 
        LIMIT 50
    """, (clinic_id,))
    alerts = c.fetchall()
    conn.close()
    
    return render_template('clinic_dashboard.html',
                         clinic_name=session['clinic_name'],
                         alerts=alerts)

@app.route('/api/report', methods=['POST', 'OPTIONS'])
def report():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.json
        clinic_id = session.get('clinic_id', 1) 
        log_alert(clinic_id, data['ip'], data.get('event_type', 'Unknown'), 
                data.get('description', ''), data.get('severity', 'medium'))
        
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Erro no /api/report: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    clinic_id = session.get('clinic_id', 1)
    return jsonify(get_recent_alerts(clinic_id))

@socketio.on('connect')
def handle_connect():
    if 'clinic_id' in session:
        clinic_id = session['clinic_id']
        ip = request.remote_addr
        connected_devices[ip] = datetime.datetime.now()
        join_room(f'clinic_{clinic_id}')
        emit('initial_data', {
            'devices': get_current_devices(clinic_id),
            'events': get_recent_alerts(clinic_id)
        })

@socketio.on('request_update')
def handle_update_request():
    if 'clinic_id' in session:
        clinic_id = session['clinic_id']
        emit('update_data', {
            'devices': get_current_devices(clinic_id),
            'events': get_recent_alerts(clinic_id)
        }, room=f'clinic_{clinic_id}')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                           'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0')