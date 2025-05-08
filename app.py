import datetime
import sqlite3
from flask import Flask, render_template, redirect, send_from_directory, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Troque por uma chave forte em produção


# Configuração inicial do banco de dados
def init_db():
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    
    # Tabela de clínicas
    c.execute('''CREATE TABLE IF NOT EXISTS clinics
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT UNIQUE,
                 admin_user TEXT UNIQUE,
                 admin_password TEXT)''')
    
    # Tabela de alertas (agora com clinic_id)
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

# Função para registrar alertas (agora com clinic_id)
def log_alert(clinic_id, ip, event_type, description, severity="medium"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    c.execute("INSERT INTO alerts (clinic_id, timestamp, ip, event_type, description, severity) VALUES (?, ?, ?, ?, ?, ?)",
              (clinic_id, timestamp, ip, event_type, description, severity))
    conn.commit()
    conn.close()

# Rotas de Autenticação
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
            conn.commit()
            conn.close()
            flash('Cadastro realizado com sucesso! Faça login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nome da clínica ou usuário já existente')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Rotas Protegidas
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'clinic_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    
    # Dados da clínica
    c.execute("SELECT * FROM clinics WHERE id = ?", (session['clinic_id'],))
    clinic = c.fetchone()
    
    # Alertas da clínica
    c.execute("SELECT * FROM alerts WHERE clinic_id = ? ORDER BY timestamp DESC LIMIT 10", (session['clinic_id'],))
    alerts = c.fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         clinic=clinic,
                         alerts=alerts)

@app.route('/clinic/dashboard')
def clinic_dashboard():
    if 'clinic_id' not in session:
        return redirect(url_for('login'))
    
    # Similar ao admin, mas com visualização simplificada
    conn = sqlite3.connect('safeclinica.db')
    c = conn.cursor()
    c.execute("SELECT * FROM alerts WHERE clinic_id = ? ORDER BY timestamp DESC LIMIT 10", (session['clinic_id'],))
    alerts = c.fetchall()
    conn.close()
    
    return render_template('clinic_dashboard.html',
                         clinic_name=session['clinic_name'],
                         alerts=alerts)



@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                           'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if app.debug:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response
    
    @app.before_request
    def log_requests():
        if request.path != '/favicon.ico':
            app.logger.debug(f"{request.method} {request.path}")
        
        
if __name__ == '__main__':
    init_db()
    app.run(debug=True)