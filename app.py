import sqlite3
import os
import zipfile
import io
import pyotp
import base64
import qrcode
from flask import Flask, make_response, render_template, redirect, send_from_directory, url_for, request, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from collections import deque
from datetime import datetime
from io import BytesIO
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.secret_key = os.urandom(24)  
CORS(app) 
socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelo de usuário
class User(UserMixin):
    def __init__(self, id, username, password_hash, totp_secret=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.totp_secret = totp_secret

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
    c = conn.cursor()
    c.execute("SELECT id, admin_user, admin_password, totp_secret FROM clinics WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(id=user_data[0], username=user_data[1], password_hash=user_data[2], totp_secret=user_data[3])
    return None

security_events = deque(maxlen=100)  
connected_devices = {}

def init_db():
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS clinics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT UNIQUE,
                 admin_user TEXT UNIQUE,
                 admin_password TEXT,
                 totp_secret TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 clinic_id INTEGER,
                 timestamp TEXT,
                 ip TEXT,
                 event_type TEXT,
                 description TEXT,
                 severity TEXT,
                 FOREIGN KEY (clinic_id) REFERENCES clinics(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT PRIMARY KEY,
                 custom_name TEXT,
                 first_seen TEXT,
                 last_seen TEXT,
                 is_banned INTEGER DEFAULT 0)''')
    
    conn.commit()
    conn.close()
    
def generate_2fa_qr_code(secret, username):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SafeClinica"
    )
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

def log_alert(clinic_id, ip, event_type, description, severity="medium"):
    """
    Registra um alerta de segurança no banco de dados e atualiza as informações do dispositivo.
    
    Args:
        clinic_id (int): ID da clínica associada ao alerta
        ip (str): Endereço IP do dispositivo
        event_type (str): Tipo de evento (login, logout, access_attempt, etc.)
        description (str): Descrição detalhada do evento
        severity (str): Nível de severidade (low, medium, high, critical)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
        c = conn.cursor()

        c.execute("""
            INSERT INTO alerts 
            (clinic_id, timestamp, ip, event_type, description, severity) 
            VALUES (?, ?, ?, ?, ?, ?)
            """, 
            (clinic_id, timestamp, ip, event_type, description, severity))

        c.execute("""
            INSERT INTO devices (ip, last_seen, first_seen)
            VALUES (?, ?, COALESCE((SELECT first_seen FROM devices WHERE ip = ?), ?))
            ON CONFLICT(ip) DO UPDATE SET 
                last_seen = excluded.last_seen
            """, 
            (ip, timestamp, ip, timestamp))

        conn.commit()

        event_data = {
            'timestamp': timestamp,
            'ip': ip,
            'event_type': event_type,
            'description': description,
            'severity': severity,
            'clinic_id': clinic_id
        }

        socketio.emit('new_security_event', event_data, room=f'clinic_{clinic_id}')

        socketio.emit('update_stats', {
            'clinic_id': clinic_id,
            'new_alert': True
        }, room=f'clinic_{clinic_id}')

    except sqlite3.Error as e:
        print(f"ERRO no log_alert: {str(e)}")
        with open('error_log.txt', 'a') as f:
            f.write(f"{timestamp} - Erro ao registrar alerta: {str(e)}\n")
        
    except Exception as e:
        print(f"ERRO inesperado no log_alert: {str(e)}")
        
    finally:
        if 'conn' in locals():
            conn.close()
        
def get_db_connection():
    conn = sqlite3.connect('safeclinica.db', timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")  # Melhora o acesso concorrente
    return conn

def get_current_devices(clinic_id):
    return {ip: time.isoformat() for ip, time in connected_devices.items()}

def get_recent_alerts(clinic_id, limit=10):
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)

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
    if 'clinic_id' in session:
        ip = request.remote_addr
        connected_devices[ip] = datetime.now()
    return redirect(url_for('login'))

@app.route('/dynamic-config.js')
def dynamic_config():
    return f"""
    window.APP_CONFIG = {{
        API_BASE_URL: "{request.host_url}",
        NGROK_URL: "https://e985-168-181-51-223.ngrok-free.app"
    }};
    """, 200, {'Content-Type': 'application/javascript'}

@app.route('/login', methods=['POST'])
def login():
    # Limpa sessão anterior
    session.clear()

    # Aceita apenas JSON
    if not request.is_json:
        return jsonify({
            'success': False,
            'message': 'Content-Type must be application/json'
        }), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({
            'success': False,
            'message': 'Usuário e senha são obrigatórios'
        }), 400

    try:
        conn = sqlite3.connect('safeclinica.db')
        c = conn.cursor()
        c.execute(
            "SELECT id, name, admin_password, totp_secret FROM clinics WHERE admin_user = ?",
            (username,)
        )
        clinic = c.fetchone()
        conn.close()

        if clinic and check_password_hash(clinic[2], password):
            session['temp_user_id'] = clinic[0]
            session['temp_username'] = username

            if clinic[3]:  # Se tem 2FA ativado
                return jsonify({
                    'success': True,
                    'requires2fa': True
                })

            # Login sem 2FA
            user = User(id=clinic[0], username=username, password_hash=clinic[2])
            login_user(user)
            session['clinic_id'] = clinic[0]
            session['clinic_name'] = clinic[1]

            return jsonify({
                'success': True,
                'redirect': url_for('clinic_dashboard')
            })

        return jsonify({
            'success': False,
            'message': 'Usuário ou senha incorretos'
        }), 401

    except Exception as e:
        print(f"Erro no login: {str(e)}")
        session.clear()
        return jsonify({
            'success': False,
            'message': 'Erro durante o login'
        }), 500
        
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        clinic_name = request.form['clinic_name']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            conn = sqlite3.connect('safeclinica.db', timeout=30, check_same_thread=False)
            c = conn.cursor()
            
            c.execute("INSERT INTO clinics (name, admin_user, admin_password) VALUES (?, ?, ?)",
                     (clinic_name, username, password))
            conn.commit()
            
            c.execute("SELECT id FROM clinics WHERE admin_user = ?", (username,))
            clinic_id = c.fetchone()[0]
            conn.close()
            
            # Autentica e redireciona diretamente
            user = User(id=clinic_id, username=username, password_hash=password)
            login_user(user)
            session['clinic_id'] = clinic_id
            session['clinic_name'] = clinic_name
            
            return redirect(url_for('clinic_dashboard'))  # Redirecionamento HTTP tradicional
            
        except sqlite3.IntegrityError:
            flash('Nome da clínica ou usuário já existente')
        except Exception as e:
            flash(f'Erro durante o cadastro: {str(e)}')
        
        return redirect(url_for('register'))  # Volta para o registro em caso de erro
    
    return render_template('login.html', show_register=True)
"""@app.route('/logout')
def logout():
    try:
        if 'clinic_id' in session:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip = request.remote_addr
            
            log_alert(
                session['clinic_id'], 
                ip,
                'logout', 
                f'Usuário {session.get("clinic_name", "desconhecido")} deslogado',
                'info'
            )
            
            session.clear()
            flash('Logout realizado com sucesso', 'success')
        
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"ERRO NO LOGOUT: {str(e)}")
        session.clear() 
        return redirect(url_for('login'))
"""

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    try:
        if 'clinic_id' in session:
            log_alert(
                session['clinic_id'], 
                request.remote_addr,
                'logout', 
                f'Usuário {session.get("clinic_name", "desconhecido")} deslogado',
                'info'
            )
        
        session.clear()
        
        if request.method == 'POST':
            return jsonify({
                'success': True,
                'message': 'Logout realizado com sucesso'
            }), 200

        else:
            flash('Logout realizado com sucesso', 'success')
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"ERRO NO LOGOUT: {str(e)}")
        session.clear() 
        
        if request.method == 'POST':
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500
        else:
            flash('Ocorreu um erro durante o logout', 'danger')
            return redirect(url_for('login'))

@app.route('/clinic/dashboard')
def clinic_dashboard():
    if 'clinic_id' not in session:
        return redirect(url_for('login'))
    
    clinic_id = session['clinic_id']
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)

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

@app.route('/api/device/<ip>')
def get_device_info(ip):
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
    device = c.fetchone()
    
    c.execute("""
        SELECT timestamp, event_type, description 
        FROM alerts 
        WHERE ip = ? 
        ORDER BY timestamp DESC
        LIMIT 100
    """, (ip,))
    history = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'device': device if device else {
            'ip': ip,
            'custom_name': ip,
            'first_seen': None,
            'last_seen': None
        },
        'history': [{
            'timestamp': row[0],
            'event': row[1],
            'description': row[2]
        } for row in history]
    })

@app.route('/api/device/rename', methods=['POST'])
def rename_device():
    data = request.json
    ip = data['ip']
    new_name = data['name']
    
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    
    c.execute("SELECT 1 FROM devices WHERE ip = ?", (ip,))
    if c.fetchone():
        c.execute("UPDATE devices SET custom_name = ? WHERE ip = ?", (new_name, ip))
    else:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO devices (ip, custom_name, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                 (ip, new_name, now, now))
    
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/device_details')
def device_details():
    ip = request.args.get('ip')
    clinic_id = session.get('clinic_id')
    
    if not clinic_id:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
    c = conn.cursor()
    
    c.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
    device = c.fetchone()
    
    c.execute("""
        SELECT timestamp, event_type, description, severity 
        FROM alerts 
        WHERE ip = ? AND clinic_id = ?
        ORDER BY timestamp DESC
    """, (ip, clinic_id))
    
    history = c.fetchall()
    conn.close()
    
    return render_template('device_details.html',
                         device=device if device else {'ip': ip, 'custom_name': ip},
                         history=history)

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

@app.route('/api/connected_devices')
def get_connected_devices():
    if 'clinic_id' not in session:
        return jsonify([])
    
    active_devices = {
        ip: time.isoformat() 
        for ip, time in connected_devices.items() 
        if (datetime.now() - time).seconds < 300
    }
    
    return jsonify([
        {'ip': ip, 'last_seen': last_seen} 
        for ip, last_seen in active_devices.items()
    ])


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
        
@socketio.on('connect')
def handle_connect():
    if 'clinic_id' in session:
        ip = request.remote_addr
        connected_devices[ip] = datetime.now()
        emit('device_update', {
            'count': len(connected_devices),
            'devices': list(connected_devices.keys())
        }, broadcast=True)

@socketio.on('request_update')
def handle_update_request():
    if 'clinic_id' in session:
        clinic_id = session['clinic_id']
        emit('update_data', {
            'devices': get_current_devices(clinic_id),
            'events': get_recent_alerts(clinic_id)
        }, room=f'clinic_{clinic_id}')
        
@app.route('/update_device_name', methods=['POST'])
def update_device_name():
    if 'clinic_id' not in session:
        return jsonify({'status': 'error', 'message': 'Não autenticado'}), 401
    
    data = request.json
    ip = data['ip']
    new_name = data['name']
    
    conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
    c = conn.cursor()
    
    try:
        c.execute("SELECT 1 FROM devices WHERE ip = ?", (ip,))
        if c.fetchone():
            c.execute("UPDATE devices SET custom_name = ? WHERE ip = ?", (new_name, ip))
        else:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO devices (ip, custom_name, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                     (ip, new_name, now, now))
        
        conn.commit()
        return jsonify({'status': 'success'})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    finally:
        conn.close()

@app.route('/download_logs')
def download_logs():
    try:
        if 'clinic_id' not in session:
            return redirect(url_for('login'))

        clinic_id = session['clinic_id']
        clinic_name = session.get('clinic_name', 'logs')
        
        conn = sqlite3.connect('safeclinica.db')
        c = conn.cursor()
        c.execute("""
            SELECT timestamp, ip, event_type, description, severity 
            FROM alerts 
            WHERE clinic_id = ? 
            ORDER BY timestamp DESC
        """, (clinic_id,))
        logs = c.fetchall()
        conn.close()

        csv_content = "Data/Hora,IP,Tipo de Evento,Descrição,Severidade\n"
        for log in logs:
            csv_content += f'"{log[0]}","{log[1]}","{log[2]}","{log[3]}","{log[4]}"\n'

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr(
                f'logs_{clinic_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv', 
                csv_content
            )
        zip_buffer.seek(0)

        response = make_response(zip_buffer.read())
        response.headers['Content-Disposition'] = (
            f'attachment; filename=logs_{clinic_name}_{datetime.now().strftime("%Y%m%d")}.zip'
        )
        response.headers['Content-type'] = 'application/zip'
        
        return response

    except Exception as e:
        print(f"Erro ao gerar download: {str(e)}")
        flash("Ocorreu um erro ao gerar o arquivo de download", "error")
        return redirect(url_for('admin_dashboard'))
    
    

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                           'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        user_code = request.form.get('code')
        secret = session.get('2fa_secret')
        
        # Verifica se o código está correto
        if not pyotp.TOTP(secret).verify(user_code):
            flash('❌ Código inválido! Tente novamente.', 'error')
            return redirect(url_for('setup_2fa'))
        
        conn = sqlite3.connect('safeclinica.db')
        c = conn.cursor()
        c.execute("UPDATE clinics SET totp_secret = ? WHERE id = ?", 
                 (secret, current_user.id))
        conn.commit()
        conn.close()
        
        flash('✅ 2FA ativado com sucesso!', 'success')
        return redirect(url_for('clinic_dashboard'))
    
    secret = pyotp.random_base32()
    session['2fa_secret'] = secret 
    
    qr_code = generate_2fa_qr_code(secret, current_user.username)
    return render_template('setup_2fa.html', qr_code=qr_code)

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    if 'temp_user_id' not in session:
        return jsonify({'success': False, 'message': 'Sessão expirada'}), 401

    if not request.is_json:
        return jsonify({'success': False, 'message': 'Formato inválido'}), 400

    data = request.get_json()
    code = data.get('code')

    try:
        conn = sqlite3.connect('safeclinica.db')
        c = conn.cursor()
        c.execute("""
            SELECT totp_secret 
            FROM clinics 
            WHERE id = ?
        """, (session['temp_user_id'],))
        result = c.fetchone()
        conn.close()

        if not result or not pyotp.TOTP(result[0]).verify(code, valid_window=1):
            return jsonify({
                'success': False,
                'message': 'Código inválido ou expirado'
            }), 401

        # Login bem-sucedido
        user = User(
            id=session['temp_user_id'],
            username=session['temp_username'],
            password_hash=''
        )
        login_user(user)
        session['clinic_id'] = user.id
        session['clinic_name'] = session['temp_username']
        session.pop('temp_user_id', None)
        session.pop('temp_username', None)

        return jsonify({
            'success': True,
            'redirect': url_for('clinic_dashboard')
        })

    except Exception as e:
        print(f"Erro na verificação 2FA: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Erro interno no servidor'
        }), 500

@app.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        # Verificar se já tem 2FA ativado
        if current_user.totp_secret:
            return jsonify({
                'success': False,
                'message': '2FA já está ativado para esta conta'
            }), 400
            
        # Ativar 2FA
        secret = request.form.get('secret')
        user_code = request.form.get('code')
        
        if not secret or not user_code:
            return jsonify({
                'success': False,
                'message': 'Dados incompletos'
            }), 400
        
        if not pyotp.TOTP(secret).verify(user_code):
            return jsonify({
                'success': False,
                'message': 'Código inválido'
            }), 400
        
        # Salvar no banco de dados
        conn = sqlite3.connect('safeclinica.db', check_same_thread=False)
        c = conn.cursor()
        c.execute("UPDATE clinics SET totp_secret = ? WHERE id = ?", 
                 (secret, current_user.id))
        conn.commit()
        conn.close()
        
        # Atualizar objeto de usuário
        current_user.totp_secret = secret
        
        return jsonify({
            'success': True,
            'message': '2FA ativado com sucesso!',
            'redirect': url_for('clinic_dashboard')
        })
    
    # GET request - mostrar página de ativação
    if current_user.totp_secret:
        return redirect(url_for('clinic_dashboard'))
    
    secret = pyotp.random_base32()
    qr_code = generate_2fa_qr_code(secret, current_user.username)
    
    return render_template('enable_2fa.html', 
                         secret=secret, 
                         qr_code=qr_code,
                         username=current_user.username)
    
def generate_2fa_qr_code(secret, username):
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SafeClinica"
    )
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

if __name__ == '__main__':
    init_db()
    socketio.run(app, 
                debug=True, 
                host='0.0.0.0',
                port=5000)