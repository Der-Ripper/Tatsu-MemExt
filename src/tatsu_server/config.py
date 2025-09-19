import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'database.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Настройки для загрузки файлов
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 * 1024  # 16GB max file size
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    REPORT_FOLDER = os.path.join(basedir, 'reports')
    
    # Сессия
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Создаем папки если их нет
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)