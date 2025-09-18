import os
import json
import socket
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
import eventlet
eventlet.monkey_patch()

from config import Config
from models import db, User, MemoryDump

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(role='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

# Socket server for receiving dumps
class DumpServer:
    def __init__(self, host='0.0.0.0', port=5001):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
    
    def handle_client(self, client_socket, address):
        try:
            print(f"Connection from {address}")
            
            # Создаем имя файла на основе timestamp и IP
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dump_{address[0]}_{timestamp}.bin"
            original_filename = f"memory_dump_{timestamp}.bin"
            
            # Сохраняем файл напрямую (без метаданных)
            dump_path = app.config['DUMP_DIR'] / filename
            total_size = 0
            
            with open(dump_path, 'wb') as f:
                while True:
                    data = client_socket.recv(app.config['BUFFER_SIZE'])
                    if not data:
                        break
                    f.write(data)
                    total_size += len(data)
            
            # Сохраняем в базу данных
            with app.app_context():
                dump = MemoryDump(
                    filename=filename,
                    original_filename=original_filename,
                    size=total_size,
                    source_ip=address[0],
                    dump_metadata=json.dumps({
                        'protocol': 'raw_tcp',
                        'received_at': datetime.now().isoformat(),
                        'client_address': address[0]
                    }),
                    uploaded_by=1  # Default to admin
                )
                db.session.add(dump)
                db.session.commit()
            
            print(f"Received raw dump: {filename} ({total_size} bytes) from {address}")
            
        except Exception as e:
            print(f"Error handling client {address}: {e}")
            # Clean up partially written file
            if 'dump_path' in locals() and dump_path.exists():
                try:
                    os.remove(dump_path)
                except:
                    pass
        finally:
            client_socket.close()
    
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"Raw dump server listening on {self.host}:{self.port}")
        print("Ready to accept direct memory dumps without metadata...")
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            
dump_server = DumpServer()

# Routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
        
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    dumps = MemoryDump.query.order_by(MemoryDump.uploaded_at.desc()).all()
    return render_template('dashboard.html', dumps=dumps, is_admin=current_user.is_admin())

@app.route('/download/<int:dump_id>')
@login_required
def download_dump(dump_id):
    dump = MemoryDump.query.get_or_404(dump_id)
    dump_path = app.config['DUMP_DIR'] / dump.filename
    
    if not dump_path.exists():
        flash('File not found')
        return redirect(url_for('dashboard'))
    
    return send_file(
        dump_path,
        as_attachment=True,
        download_name=dump.original_filename
    )

@app.route('/delete/<int:dump_id>', methods=['POST'])
@login_required
def delete_dump(dump_id):
    if not current_user.is_admin():
        flash('Permission denied')
        return redirect(url_for('dashboard'))
    
    dump = MemoryDump.query.get_or_404(dump_id)
    dump_path = app.config['DUMP_DIR'] / dump.filename
    
    try:
        if dump_path.exists():
            os.remove(dump_path)
        db.session.delete(dump)
        db.session.commit()
        flash('Dump deleted successfully')
    except Exception as e:
        flash(f'Error deleting dump: {e}')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# API endpoints
@app.route('/api/dumps')
@login_required
def api_dumps():
    dumps = MemoryDump.query.order_by(MemoryDump.uploaded_at.desc()).all()
    return jsonify([{
        'id': dump.id,
        'filename': dump.original_filename,
        'size': dump.size,
        'uploaded_at': dump.uploaded_at.isoformat(),
        'source_ip': dump.source_ip,
        'metadata': dump.get_metadata()  # Используем метод get_metadata
    } for dump in dumps])

def start_server():
    create_tables()
    
    # Start dump server in background
    server_thread = threading.Thread(target=dump_server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Start web server
    try:
        # Use waitress for production serving on Windows/Linux
        from waitress import serve
        print(f"Web server starting on {app.config['HOST']}:{app.config['PORT']}")
        serve(app, host=app.config['HOST'], port=app.config['PORT'])
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        dump_server.stop()

if __name__ == '__main__':
    start_server()