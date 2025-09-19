from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import threading
import socket
from threading import Thread
import uuid

from utils.dump_analyzer import analyze_dump
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    dumps = db.relationship('MemoryDump', backref='owner', lazy=True)

class MemoryDump(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)  # Физическое имя файла (dump_20250919_121729_6b751d49.mem)
    original_name = db.Column(db.String(255), nullable=False)  # Человеко-читаемое имя (memory_dump_20250919_121729.mem)
    file_size = db.Column(db.BigInteger, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_complete = db.Column(db.Boolean, default=False)
    analysis_result = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source_ip = db.Column(db.String(45))
    machine_name = db.Column(db.String(255))
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Вспомогательные функции
def analyze_dump_async(dump_id):
    with app.app_context():
        dump = MemoryDump.query.get(dump_id)
        if dump:
            dump_path = os.path.join(app.config['UPLOAD_FOLDER'], dump.filename)
            report_path = os.path.join(app.config['REPORT_FOLDER'], f"{dump.filename}.json")
            
            try:
                analysis_result = analyze_dump(dump_path)
                
                # Сохраняем отчет
                with open(report_path, 'w') as f:
                    json.dump(analysis_result, f, indent=2)
                
                dump.analysis_result = json.dumps(analysis_result)
                dump.analysis_complete = True
                db.session.commit()
                
                print(f"✅ Analysis completed for dump {dump_id}")
                
            except Exception as e:
                print(f"❌ Error analyzing dump {dump_id}: {e}")
                dump.analysis_result = json.dumps({"error": str(e)})
                db.session.commit()

# TCP сервер для приема дампов
def tcp_server():
    HOST = '0.0.0.0'
    PORT = 4444
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"📡 TCP dump receiver listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = None, None
            try:
                conn, addr = s.accept()
                print(f"🔗 New connection from {addr[0]}:{addr[1]}")
                
                # Создаем уникальное имя файла (только timestamp и uuid)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                unique_id = str(uuid.uuid4())[:8]
                filename = f"dump_{timestamp}_{unique_id}.mem"  # Физическое имя файла
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Имя машины будет определено после анализа
                machine_name = f"machine_{addr[0].replace('.', '_')}"
                original_name = f"memory_dump_{timestamp}.mem"  # Человеко-читаемое имя
                
                print(f"📥 Receiving dump from {addr[0]}, saving as {filename}")
                
                # Принимаем дамп
                total_received = 0
                with open(filepath, 'wb') as f:
                    while True:
                        data = conn.recv(8192)
                        if not data:
                            break
                        f.write(data)
                        total_received += len(data)
                        if total_received % (1024 * 1024 * 100) == 0:
                            print(f"📊 Received {total_received/(1024*1024):.2f} MB")
                
                file_size = os.path.getsize(filepath)
                print(f"✅ Dump received successfully: {file_size/(1024*1024*1024):.2f} GB")
                
                # Создаем запись в базе данных
                with app.app_context():
                    admin_user = User.query.filter_by(is_admin=True).first()
                    if not admin_user:
                        admin_user = User(
                            username='admin',
                            password_hash=generate_password_hash('admin'),
                            is_admin=True
                        )
                        db.session.add(admin_user)
                        db.session.commit()
                    
                    dump = MemoryDump(
                        filename=filename,           # Физическое имя файла
                        original_name=original_name, # Человеко-читаемое имя
                        file_size=file_size,
                        user_id=admin_user.id,
                        source_ip=addr[0],
                        machine_name=machine_name    # Будет уточнено при анализе
                    )
                    db.session.add(dump)
                    db.session.commit()
                    
                    # Запускаем анализ в отдельном потоке
                    thread = threading.Thread(target=analyze_dump_async, args=(dump.id,))
                    thread.start()
                    print(f"🔍 Analysis started for dump {dump.id}")
                
            except Exception as e:
                print(f"❌ TCP error: {e}")
            finally:
                if conn:
                    try:
                        conn.close()
                    except:
                        pass

# Маршруты
@app.route('/')
@login_required
def dashboard():
    # Все пользователи видят все дампы
    dumps = MemoryDump.query.order_by(MemoryDump.upload_date.desc()).all()
    return render_template('dashboard.html', dumps=dumps, is_admin=current_user.is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
        
@app.route('/dump/<int:dump_id>')
@login_required
def download_dump(dump_id):
    dump = MemoryDump.query.get_or_404(dump_id)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], dump.filename)
    
    if not os.path.exists(filepath) or not os.access(filepath, os.R_OK):
        flash('File not found or no access permission')
        return redirect(url_for('dashboard'))
    
    print(f"✅ Downloading: {filepath}")
    
    # Используем original_name для скачивания
    download_filename = dump.original_name
    
    response = send_file(
        filepath,
        as_attachment=True,
        download_name=download_filename,
        mimetype='application/octet-stream'
    )
    
    print(f"File sent successfully: {download_filename}")
    return response

@app.route('/report/<int:dump_id>')
@login_required
def view_report(dump_id):
    # Все авторизованные пользователи могут просматривать отчеты
    dump = MemoryDump.query.get_or_404(dump_id)
    
    if not dump.analysis_complete:
        return jsonify({'status': 'pending'})
    
    return jsonify(json.loads(dump.analysis_result))

@app.route('/delete/<int:dump_id>', methods=['POST'])
@login_required
def delete_dump(dump_id):
    # Только админы могут удалять дампы
    if not current_user.is_admin:
        flash('Access denied: Only administrators can delete dumps')
        return redirect(url_for('dashboard'))
    
    dump = MemoryDump.query.get_or_404(dump_id)
    
    # Удаляем файлы
    dump_path = os.path.join(app.config['UPLOAD_FOLDER'], dump.filename)
    report_path = os.path.join(app.config['REPORT_FOLDER'], f"{dump.filename}.json")
    
    if os.path.exists(dump_path):
        os.remove(dump_path)
    if os.path.exists(report_path):
        os.remove(report_path)
    
    db.session.delete(dump)
    db.session.commit()
    
    flash('Dump deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/delete_all', methods=['POST'])
@login_required
def delete_all_dumps():
    # Только админы могут удалять все дампы
    if not current_user.is_admin:
        flash('Access denied: Only administrators can delete all dumps')
        return redirect(url_for('dashboard'))
    
    dumps = MemoryDump.query.all()
    for dump in dumps:
        dump_path = os.path.join(app.config['UPLOAD_FOLDER'], dump.filename)
        report_path = os.path.join(app.config['REPORT_FOLDER'], f"{dump.filename}.json")
        
        if os.path.exists(dump_path):
            os.remove(dump_path)
        if os.path.exists(report_path):
            os.remove(report_path)
    
    MemoryDump.query.delete()
    db.session.commit()
    
    flash('All dumps deleted successfully')
    return redirect(url_for('dashboard'))

@app.route('/server_status')
@login_required
def server_status():
    """Статус сервера для админов"""
    if not current_user.is_admin:
        flash('Access denied: Only administrators can view server status')
        return redirect(url_for('dashboard'))
    
    total_dumps = MemoryDump.query.count()
    total_size = db.session.query(db.func.sum(MemoryDump.file_size)).scalar() or 0
    analyzing_dumps = MemoryDump.query.filter_by(analysis_complete=False).count()
    
    return jsonify({
        'status': 'running',
        'total_dumps': total_dumps,
        'total_size_gb': total_size / (1024**3),
        'analyzing_dumps': analyzing_dumps,
        'tcp_port': 4444
    })


# Создаем начального админа при первом запуске
def create_default_admin():
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            
            # Создаем тестового пользователя
            test_user = User(
                username='user',
                password_hash=generate_password_hash('user'),
                is_admin=False
            )
            db.session.add(test_user)
            
            db.session.commit()
            print("✅ Default users created:")
            print("   👑 Admin: username='admin', password='admin'")
            print("   👤 User:  username='user',  password='user'")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    # Запускаем TCP сервер в отдельном потоке
    tcp_thread = Thread(target=tcp_server, daemon=True)
    tcp_thread.start()
    print("📡 TCP dump receiver started on port 4444")
    
    # Запускаем веб-сервер
    from waitress import serve
    print("🌐 Web server starting on http://0.0.0.0:5000")
    print("💡 Login with: admin/admin or user/user")
    serve(app, host='0.0.0.0', port=5000)