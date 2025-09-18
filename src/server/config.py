import os
from pathlib import Path

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    BASE_DIR = Path(__file__).parent
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR}/app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DUMP_DIR = BASE_DIR / 'dumps'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024 * 1024  # 16GB max file size
    HOST = '0.0.0.0'
    PORT = 5000
    SOCKET_PORT = 5001
    BUFFER_SIZE = 4096
    MAX_METADATA_SIZE = 1024  # 1KB max for metadata
    
    # Create directories if they don't exist
    DUMP_DIR.mkdir(exist_ok=True)