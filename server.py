import os
import re
import uuid
import json
import mimetypes
import boto3
import secrets
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import logging
from pathlib import Path
from functools import wraps
import hashlib
import hmac

# Firebase Admin SDK
try:
    import firebase_admin
    from firebase_admin import credentials, auth
    FIREBASE_AVAILABLE = True
    
    # Initialize Firebase Admin SDK
    firebase_credentials_path = os.getenv('FIREBASE_CREDENTIALS_PATH')
    if firebase_credentials_path and os.path.exists(firebase_credentials_path):
        cred = credentials.Certificate(firebase_credentials_path)
        firebase_admin.initialize_app(cred)
        logging.info("Firebase Admin SDK initialized with service account")
    else:
        # Try to initialize with default credentials (for Railway/Heroku)
        try:
            firebase_admin.initialize_app()
            logging.info("Firebase Admin SDK initialized with default credentials")
        except Exception as e:
            logging.warning(f"Firebase Admin SDK initialization failed: {e}")
            FIREBASE_AVAILABLE = False
except ImportError:
    firebase_admin = None
    auth = None
    FIREBASE_AVAILABLE = False
    logging.warning("Firebase Admin SDK not available - Firebase authentication disabled")

# Optional ClamAV import
try:
    import clamd
    CLAMAV_AVAILABLE = True
except ImportError:
    clamd = None
    CLAMAV_AVAILABLE = False
    logging.warning("ClamAV not available - malware scanning disabled")

# Load environment variables from env.local (development) or system env (production)
if os.path.exists('env.local'):
    load_dotenv('env.local')
else:
    load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

# Session configuration for production
app.config['SESSION_COOKIE_SECURE'] = False  # Set to False for Railway (they handle HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.getenv('ADMIN_SESSION_TIMEOUT', 3600)))
app.config['SESSION_COOKIE_DOMAIN'] = None  # Let Flask set the domain automatically

# CORS Configuration for production
CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*')
if CORS_ORIGINS == '*':
    CORS(app, origins=['*'], supports_credentials=True)
else:
    # Parse multiple origins if provided
    origins = [origin.strip() for origin in CORS_ORIGINS.split(',')]
    CORS(app, origins=origins, supports_credentials=True)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB max file size
ALLOWED_MIME_TYPES = {
    'application/pdf', 'text/plain', 'image/jpeg', 'image/png', 
    'image/gif', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv', 'application/zip', 'application/x-rar-compressed', 'application/octet-stream'
}

# Admin Configuration
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH', '')
ADMIN_SESSION_TIMEOUT = int(os.getenv('ADMIN_SESSION_TIMEOUT', 3600))  # 1 hour

# Visitor tracking storage (use Redis in production)
visitor_stats = {
    'total_visits': 0,
    'unique_visitors': set(),
    'daily_visits': {},
    'page_views': {},
    'upload_stats': {
        'total_uploads': 0,
        'total_size': 0,
        'uploads_by_date': {}
    },
    'download_stats': {
        'total_downloads': 0,
        'downloads_by_date': {}
    }
}

# File extension to MIME type mapping for better detection
FILE_EXTENSIONS = {
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xls': 'application/vnd.ms-excel',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.csv': 'text/csv',
    '.zip': 'application/zip',
    '.rar': 'application/x-rar-compressed',
    '.encrypted': 'application/octet-stream',
    '.enc': 'application/octet-stream',
    '.bin': 'application/octet-stream'
}

# Storage Configuration
STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'local').lower()  # local, s3, gcs, azure

# Local Storage Configuration - Use absolute path for Railway compatibility
if STORAGE_TYPE == 'local':
    # Use /tmp for Railway or absolute path for better compatibility
    LOCAL_STORAGE_PATH = os.getenv('LOCAL_STORAGE_PATH', '/tmp/ncryp-uploads')
    if LOCAL_STORAGE_PATH.startswith('./'):
        # Convert relative path to absolute path
        LOCAL_STORAGE_PATH = os.path.abspath(LOCAL_STORAGE_PATH)
    
    # Ensure the directory exists and is writable
    try:
        os.makedirs(LOCAL_STORAGE_PATH, exist_ok=True)
        # Test write permissions
        test_file = os.path.join(LOCAL_STORAGE_PATH, 'test_write.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        logging.info(f"Local storage initialized at: {LOCAL_STORAGE_PATH}")
    except Exception as e:
        logging.error(f"Failed to initialize local storage at {LOCAL_STORAGE_PATH}: {e}")
        # Fallback to /tmp if the configured path fails
        LOCAL_STORAGE_PATH = '/tmp/ncryp-uploads'
        os.makedirs(LOCAL_STORAGE_PATH, exist_ok=True)
        logging.info(f"Using fallback storage path: {LOCAL_STORAGE_PATH}")
else:
    LOCAL_STORAGE_PATH = './uploads'  # Default for non-local storage

# AWS S3 Configuration (optional)
if STORAGE_TYPE == 's3':
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )
    SECURE_BUCKET = os.getenv('S3_BUCKET_NAME', 'ncryp-secure-storage')
else:
    s3_client = None

# Google Cloud Storage Configuration (optional)
if STORAGE_TYPE == 'gcs':
    try:
        from google.cloud import storage
        gcs_client = storage.Client()
        GCS_BUCKET_NAME = os.getenv('GCS_BUCKET_NAME', 'ncryp-secure-storage')
        gcs_bucket = gcs_client.bucket(GCS_BUCKET_NAME)
    except ImportError:
        logging.warning("Google Cloud Storage not available - install google-cloud-storage")
        gcs_client = None
        gcs_bucket = None
else:
    gcs_client = None
    gcs_bucket = None

# Azure Blob Storage Configuration (optional)
if STORAGE_TYPE == 'azure':
    try:
        from azure.storage.blob import BlobServiceClient
        azure_connection_string = os.getenv('AZURE_CONNECTION_STRING')
        azure_container_name = os.getenv('AZURE_CONTAINER_NAME', 'ncryp-secure-storage')
        if azure_connection_string:
            azure_client = BlobServiceClient.from_connection_string(azure_connection_string)
            azure_container = azure_client.get_container_client(azure_container_name)
        else:
            azure_client = None
            azure_container = None
    except ImportError:
        logging.warning("Azure Blob Storage not available - install azure-storage-blob")
        azure_client = None
        azure_container = None
else:
    azure_client = None
    azure_container = None

# ClamAV Configuration
if CLAMAV_AVAILABLE and clamd is not None:
    try:
        clamav = clamd.ClamdUnixSocket()
    except Exception:
        clamav = None
        logging.warning("ClamAV not available - malware scanning disabled")
else:
    clamav = None

# In-memory storage for demo (use Redis in production)
file_metadata = {}

class SecurityException(Exception):
    pass

class InvalidFilenameException(SecurityException):
    pass

class FileSizeExceededException(SecurityException):
    pass

class InvalidFileTypeException(SecurityException):
    pass

class MalwareDetectedException(SecurityException):
    pass

class StorageBackend:
    """Abstract storage backend interface"""
    
    def store_file(self, file_id, file_data, metadata=None):
        raise NotImplementedError
    
    def retrieve_file(self, file_id):
        raise NotImplementedError
    
    def delete_file(self, file_id):
        raise NotImplementedError

class LocalStorageBackend(StorageBackend):
    """Local file system storage backend"""
    
    def __init__(self, storage_path):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def store_file(self, file_id, file_data, metadata=None):
        try:
            file_path = self.storage_path / f"{file_id}.bin"
            logging.info(f"Storing file {file_id} at: {file_path}")
            
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            # Store metadata in a separate file
            if metadata:
                meta_path = self.storage_path / f"{file_id}.meta"
                logging.info(f"Storing metadata for {file_id} at: {meta_path}")
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f)
            
            logging.info(f"Successfully stored file {file_id}")
            return True
        except Exception as e:
            logging.error(f"Failed to store file {file_id}: {e}")
            logging.error(f"Storage path: {self.storage_path}")
            logging.error(f"Storage path exists: {self.storage_path.exists()}")
            logging.error(f"Storage path is writable: {os.access(self.storage_path, os.W_OK)}")
            return False
    
    def retrieve_file(self, file_id):
        file_path = self.storage_path / f"{file_id}.bin"
        if not file_path.exists():
            return None
        
        with open(file_path, 'rb') as f:
            return f.read()
    
    def delete_file(self, file_id):
        try:
            file_path = self.storage_path / f"{file_id}.bin"
            meta_path = self.storage_path / f"{file_id}.meta"
            
            logging.info(f"Attempting to delete file {file_id}")
            logging.info(f"File path: {file_path}")
            logging.info(f"Meta path: {meta_path}")
            logging.info(f"File exists: {file_path.exists()}")
            logging.info(f"Meta exists: {meta_path.exists()}")
            
            deleted_files = 0
            
            if file_path.exists():
                file_path.unlink()
                deleted_files += 1
                logging.info(f"Deleted file: {file_path}")
            
            if meta_path.exists():
                meta_path.unlink()
                deleted_files += 1
                logging.info(f"Deleted meta: {meta_path}")
            
            logging.info(f"Total files deleted: {deleted_files}")
            # Return True if at least one file was deleted
            return deleted_files > 0
        except Exception as e:
            logging.error(f"Local storage delete error for {file_id}: {e}")
            return False

class S3StorageBackend(StorageBackend):
    """AWS S3 storage backend"""
    
    def __init__(self, s3_client, bucket_name):
        self.s3_client = s3_client
        self.bucket_name = bucket_name
    
    def store_file(self, file_id, file_data, metadata=None):
        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=f"{file_id}.bin",
                Body=file_data,
                ServerSideEncryption='aws:kms',
                Metadata=metadata or {}
            )
            return True
        except Exception as e:
            logging.error(f"S3 upload error: {e}")
            return False
    
    def retrieve_file(self, file_id):
        try:
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=f"{file_id}.bin"
            )
            return response['Body'].read()
        except Exception as e:
            logging.error(f"S3 download error: {e}")
            return None
    
    def delete_file(self, file_id):
        try:
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=f"{file_id}.bin"
            )
            return True
        except Exception as e:
            logging.error(f"S3 delete error: {e}")
            return False

class GCSStorageBackend(StorageBackend):
    """Google Cloud Storage backend"""
    
    def __init__(self, bucket):
        self.bucket = bucket
    
    def store_file(self, file_id, file_data, metadata=None):
        try:
            blob = self.bucket.blob(f"{file_id}.bin")
            blob.upload_from_string(file_data, content_type='application/octet-stream')
            
            if metadata:
                blob.metadata = metadata
                blob.patch()
            
            return True
        except Exception as e:
            logging.error(f"GCS upload error: {e}")
            return False
    
    def retrieve_file(self, file_id):
        try:
            blob = self.bucket.blob(f"{file_id}.bin")
            return blob.download_as_bytes()
        except Exception as e:
            logging.error(f"GCS download error: {e}")
            return None
    
    def delete_file(self, file_id):
        try:
            blob = self.bucket.blob(f"{file_id}.bin")
            blob.delete()
            return True
        except Exception as e:
            logging.error(f"GCS delete error: {e}")
            return False

class AzureStorageBackend(StorageBackend):
    """Azure Blob Storage backend"""
    
    def __init__(self, container_client):
        self.container_client = container_client
    
    def store_file(self, file_id, file_data, metadata=None):
        try:
            blob_client = self.container_client.get_blob_client(f"{file_id}.bin")
            blob_client.upload_blob(file_data, overwrite=True, metadata=metadata)
            return True
        except Exception as e:
            logging.error(f"Azure upload error: {e}")
            return False
    
    def retrieve_file(self, file_id):
        try:
            blob_client = self.container_client.get_blob_client(f"{file_id}.bin")
            return blob_client.download_blob().readall()
        except Exception as e:
            logging.error(f"Azure download error: {e}")
            return None
    
    def delete_file(self, file_id):
        try:
            blob_client = self.container_client.get_blob_client(f"{file_id}.bin")
            blob_client.delete_blob()
            return True
        except Exception as e:
            logging.error(f"Azure delete error: {e}")
            return False

# Initialize storage backend
if STORAGE_TYPE == 'local':
    logging.info(f"Initializing local storage backend at: {LOCAL_STORAGE_PATH}")
    storage_backend = LocalStorageBackend(LOCAL_STORAGE_PATH)
elif STORAGE_TYPE == 's3' and s3_client:
    logging.info(f"Initializing S3 storage backend with bucket: {SECURE_BUCKET}")
    storage_backend = S3StorageBackend(s3_client, SECURE_BUCKET)
elif STORAGE_TYPE == 'gcs' and gcs_bucket:
    logging.info(f"Initializing GCS storage backend with bucket: {GCS_BUCKET_NAME}")
    storage_backend = GCSStorageBackend(gcs_bucket)
elif STORAGE_TYPE == 'azure' and azure_container:
    logging.info(f"Initializing Azure storage backend with container: {azure_container_name}")
    storage_backend = AzureStorageBackend(azure_container)
else:
    # Fallback to local storage
    logging.warning(f"Storage type '{STORAGE_TYPE}' not available, falling back to local storage")
    logging.info(f"Using fallback local storage at: {LOCAL_STORAGE_PATH}")
    storage_backend = LocalStorageBackend(LOCAL_STORAGE_PATH)

logging.info(f"Storage backend initialized successfully: {type(storage_backend).__name__}")

def validate_filename(filename):
    """Validate filename for security"""
    if not filename or len(filename) > 200:
        raise InvalidFilenameException("Invalid filename")
    
    # Very permissive validation for mobile compatibility
    # Only block: path separators, control characters, and null bytes
    # Allow: most printable characters and Unicode
    if not re.match(r'^[^\x00\x01-\x1f\x7f\/\\]{1,200}$', filename):
        logging.warning(f"Filename validation failed for: {repr(filename)}")
        raise InvalidFilenameException("Filename contains invalid characters")
    
    # Additional security check: prevent path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        raise InvalidFilenameException("Filename contains invalid path characters")
    
    return secure_filename(filename)

def validate_file_size(file_size):
    """Validate file size"""
    if file_size > app.config['MAX_CONTENT_LENGTH']:
        raise FileSizeExceededException("File size exceeds maximum allowed")
    return True

def validate_mime_type(file_data, filename=None):
    """Validate MIME type using file extension and content analysis"""
    try:
        # Check if this is an encrypted file
        if filename and (filename.endswith('.encrypted') or filename.endswith('.enc') or filename.endswith('.bin')):
            return 'application/octet-stream'
        
        # First try to get MIME type from filename extension
        if filename:
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type and mime_type in ALLOWED_MIME_TYPES:
                return mime_type
        
        # Fallback: check file extension mapping
        if filename:
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext in FILE_EXTENSIONS:
                mime_type = FILE_EXTENSIONS[file_ext]
                if mime_type in ALLOWED_MIME_TYPES:
                    return mime_type
        
        # If we can't determine the type, reject the file for security
        raise InvalidFileTypeException(f"File type not allowed. Allowed types: {', '.join(ALLOWED_MIME_TYPES)}")
        
    except Exception as e:
        if isinstance(e, InvalidFileTypeException):
            raise e
        raise InvalidFileTypeException(f"Could not determine file type: {str(e)}")

def scan_for_malware(file_data):
    """Scan file for malware using ClamAV"""
    if not clamav:
        return True  # Skip scanning if ClamAV not available
    
    try:
        scan_result = clamav.instream(file_data)
        stream_result = scan_result.get('stream') if scan_result else None
        if stream_result and len(stream_result) > 0 and stream_result[0] == 'FOUND':
            raise MalwareDetectedException("Malware detected in file")
        return True
    except Exception as e:
        logging.error(f"Malware scan error: {e}")
        return True  # Continue if scan fails

def generate_share_id():
    """Generate a unique 8-character share ID"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))

def track_visitor():
    """Track visitor statistics"""
    try:
        # Get visitor IP
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()
        
        # Get current date
        today = datetime.utcnow().date().isoformat()
        
        # Update visitor stats
        visitor_stats['total_visits'] += 1
        if visitor_ip:
            visitor_stats['unique_visitors'].add(visitor_ip)
        
        # Track daily visits
        if today not in visitor_stats['daily_visits']:
            visitor_stats['daily_visits'][today] = 0
        visitor_stats['daily_visits'][today] += 1
        
        # Track page views
        page = request.path
        if page not in visitor_stats['page_views']:
            visitor_stats['page_views'][page] = 0
        visitor_stats['page_views'][page] += 1
        
    except Exception as e:
        logging.error(f"Visitor tracking error: {str(e)}")

def require_admin(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.info(f"Admin endpoint accessed: {request.endpoint}")
        logging.info(f"Session admin flag: {session.get('admin')}")
        logging.info(f"Full session: {dict(session)}")
        
        if not session.get('admin'):
            logging.warning(f"Admin access denied for {request.remote_addr}")
            return jsonify({'error': 'Admin authentication required'}), 401
        
        logging.info(f"Admin access granted for {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function

def require_firebase_admin(f):
    """Decorator to require Firebase admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.info(f"Firebase admin endpoint accessed: {request.endpoint}")
        
        # Get Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logging.warning(f"Missing or invalid Authorization header for {request.remote_addr}")
            return jsonify({'error': 'Firebase authentication required'}), 401
        
        id_token = auth_header.split('Bearer ')[1]
        
        try:
            if not FIREBASE_AVAILABLE or not auth:
                logging.error("Firebase Admin SDK not available")
                return jsonify({'error': 'Firebase authentication not configured'}), 500
            
            # Verify the Firebase ID token
            decoded_token = auth.verify_id_token(id_token)
            user_id = decoded_token['uid']
            email = decoded_token.get('email', '')
            
            logging.info(f"Firebase authentication successful for user: {email} ({user_id})")
            
            # Store user info in request context for use in the endpoint
            request.firebase_user = {
                'uid': user_id,
                'email': email
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            logging.error(f"Firebase authentication failed: {str(e)}")
            return jsonify({'error': 'Invalid Firebase token'}), 401
    
    return decorated_function

def update_upload_stats(file_size):
    """Update upload statistics"""
    try:
        today = datetime.utcnow().date().isoformat()
        
        visitor_stats['upload_stats']['total_uploads'] += 1
        visitor_stats['upload_stats']['total_size'] += file_size
        
        if today not in visitor_stats['upload_stats']['uploads_by_date']:
            visitor_stats['upload_stats']['uploads_by_date'][today] = {'count': 0, 'size': 0}
        visitor_stats['upload_stats']['uploads_by_date'][today]['count'] += 1
        visitor_stats['upload_stats']['uploads_by_date'][today]['size'] += file_size
        
    except Exception as e:
        logging.error(f"Upload stats error: {str(e)}")

def update_download_stats():
    """Update download statistics"""
    try:
        today = datetime.utcnow().date().isoformat()
        
        visitor_stats['download_stats']['total_downloads'] += 1
        
        if today not in visitor_stats['download_stats']['downloads_by_date']:
            visitor_stats['download_stats']['downloads_by_date'][today] = 0
        visitor_stats['download_stats']['downloads_by_date'][today] += 1
        
    except Exception as e:
        logging.error(f"Download stats error: {str(e)}")

def verify_admin_password(password, stored_hash):
    """Verify admin password against stored hash"""
    try:
        if not stored_hash or ':' not in stored_hash:
            return False
        
        salt, hash_value = stored_hash.split(':', 1)
        hash_obj = hmac.new(salt.encode(), password.encode(), hashlib.sha256)
        return hmac.compare_digest(hash_obj.hexdigest(), hash_value)
    except Exception:
        return False

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and encrypt a file"""
    track_visitor()  # Track visitor
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        logging.info(f"Uploading file: {file.filename}")

        # Validate filename
        try:
            validate_filename(file.filename)
        except InvalidFilenameException as e:
            logging.error(f"Filename validation failed: {str(e)}")
            return jsonify({'error': str(e)}), 400

        # Read file data
        file_data = file.read()
        logging.info(f"File size: {len(file_data)} bytes")
        
        # Validate file size
        try:
            validate_file_size(len(file_data))
        except FileSizeExceededException as e:
            logging.error(f"File size validation failed: {str(e)}")
            return jsonify({'error': str(e)}), 400

        # Validate MIME type
        try:
            mime_type = validate_mime_type(file_data, file.filename)
            logging.info(f"Detected MIME type: {mime_type}")
        except InvalidFileTypeException as e:
            logging.error(f"MIME type validation failed: {str(e)}")
            return jsonify({'error': str(e)}), 400

        # Scan for malware
        try:
            scan_for_malware(file_data)
        except MalwareDetectedException as e:
            logging.error(f"Malware scan failed: {str(e)}")
            return jsonify({'error': str(e)}), 400

        # Generate unique file ID and share ID
        file_id = str(uuid.uuid4())
        share_id = generate_share_id()
        
        # Ensure share_id is unique (in production, use database with unique constraint)
        while share_id in [f.get('share_id') for f in file_metadata.values()]:
            share_id = generate_share_id()

        # Store file using appropriate backend
        storage_backend.store_file(file_id, file_data)

        # Store metadata
        metadata = {
            'id': file_id,
            'share_id': share_id,
            'filename': file.filename,
            'size': len(file_data),
            'upload_date': datetime.utcnow().isoformat(),
            'encrypted': True,
            'mime_type': mime_type
        }
        
        file_metadata[file_id] = metadata
        
        # Store metadata in storage backend
        storage_backend.store_file(f"{file_id}.meta", json.dumps(metadata).encode('utf-8'))

        # Update upload statistics
        update_upload_stats(len(file_data))

        logging.info(f"File uploaded successfully: {file_id} (share_id: {share_id})")
        
        return jsonify({
            'file_id': file_id,
            'share_id': share_id,
            'filename': file.filename,
            'size': len(file_data),
            'message': 'File encrypted and uploaded successfully'
        }), 201

    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/files', methods=['GET'])
def list_files():
    """List uploaded files"""
    track_visitor()  # Track visitor
    
    try:
        files = []
        for file_id, metadata in file_metadata.items():
            # Check if file has share_id (new format) or expires_at (old format)
            if 'share_id' in metadata:
                # New format - include share_id
                files.append({
                    'id': file_id,
                    'share_id': metadata['share_id'],
                    'filename': metadata['filename'],
                    'size': metadata['size'],
                    'upload_date': metadata['upload_date'],
                    'encrypted': metadata.get('encrypted', False)
                })
            elif 'expires_at' in metadata:
                # Old format - check expiration
                if datetime.fromisoformat(metadata['expires_at']) > datetime.utcnow():
                    files.append({
                        'id': file_id,
                        'filename': metadata['filename'],
                        'size': metadata['size'],
                        'upload_date': metadata['upload_date'],
                        'encrypted': metadata.get('encrypted', False)
                    })
        
        return jsonify({'files': files}), 200
    except Exception as e:
        logging.error(f"List files error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/files/<file_id>', methods=['GET'])
def download_file(file_id):
    """Download a file by ID (supports both UUID and share_id)"""
    track_visitor()  # Track visitor
    
    try:
        # Check if file_id is a share_id (8 characters, alphanumeric)
        if len(file_id) == 8 and file_id.isalnum():
            # Search by share_id
            file_meta = None
            for meta in file_metadata.values():
                if meta.get('share_id') == file_id:
                    file_meta = meta
                    break
            
            if not file_meta:
                return jsonify({'error': 'File not found'}), 404
        else:
            # Search by UUID
            file_meta = file_metadata.get(file_id)
            if not file_meta:
                return jsonify({'error': 'File not found'}), 404

        # Retrieve file from storage
        file_data = storage_backend.retrieve_file(file_meta['id'])
        
        if not file_data:
            return jsonify({'error': 'File not found in storage'}), 404

        # Create response with encrypted file
        response = Response(file_data)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename="{file_meta["filename"]}.encrypted"'
        response.headers['Content-Length'] = len(file_data)
        
        # Update download statistics
        update_download_stats()
        
        return response

    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/files/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete file by ID"""
    try:
        if file_id not in file_metadata:
            return jsonify({'error': 'File not found'}), 404
        
        # Delete from storage backend
        delete_success = storage_backend.delete_file(file_id)
        if not delete_success:
            logging.error(f"Storage backend failed to delete file {file_id}")
            return jsonify({'error': 'Failed to delete file from storage'}), 500
        
        # Remove metadata
        del file_metadata[file_id]
        
        return jsonify({'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        logging.error(f"Delete error for file {file_id}: {e}")
        return jsonify({'error': f'Delete failed: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'storage_type': STORAGE_TYPE,
        'clamav_available': clamav is not None
    }), 200

@app.route('/api/search/<share_id>', methods=['GET'])
def search_file(share_id):
    """Search for a file by share ID and return metadata"""
    track_visitor()  # Track visitor
    
    try:
        # Validate share_id format
        if len(share_id) != 8 or not share_id.isalnum():
            return jsonify({'error': 'Invalid share ID format'}), 400

        # Search for file with matching share_id
        file_meta = None
        for meta in file_metadata.values():
            if meta.get('share_id') == share_id:
                file_meta = meta
                break

        if not file_meta:
            return jsonify({'error': 'File not found'}), 404

        # Return file metadata (without sensitive information)
        return jsonify({
            'found': True,
            'filename': file_meta['filename'],
            'size': file_meta['size'],
            'upload_date': file_meta['upload_date'],
            'share_id': file_meta['share_id']
        }), 200

    except Exception as e:
        logging.error(f"Search error: {str(e)}")
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        logging.info(f"Admin login attempt from {request.remote_addr}")
        logging.info(f"Username: {username}")
        
        if username != ADMIN_USERNAME or not verify_admin_password(password, ADMIN_PASSWORD_HASH):
            logging.warning(f"Admin login failed for {request.remote_addr}")
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Make session permanent and set admin flag
        session.permanent = True
        session['admin'] = True
        session['admin_login_time'] = datetime.utcnow().isoformat()
        
        logging.info(f"Admin login successful for {request.remote_addr}")
        logging.info(f"Session after login: {dict(session)}")
        logging.info(f"Session permanent: {session.permanent}")
        
        response = jsonify({'message': 'Admin login successful'})
        response.headers['X-Session-Admin'] = 'true'
        response.headers['X-Session-Time'] = session['admin_login_time']
        
        return response, 200
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/admin/logout', methods=['POST'])
@require_admin
def admin_logout():
    """Admin logout endpoint"""
    try:
        session.clear()
        return jsonify({'message': 'Admin logout successful'}), 200
    except Exception as e:
        logging.error(f"Logout error: {str(e)}")
        return jsonify({'error': f'Logout failed: {str(e)}'}), 500

@app.route('/api/admin/stats', methods=['GET'])
@require_firebase_admin
def get_admin_stats():
    """Admin stats endpoint"""
    try:
        logging.info(f"Admin stats request from {request.remote_addr}")
        logging.info(f"Firebase user: {getattr(request, 'firebase_user', 'Not set')}")
        
        stats_data = {
            'total_visits': visitor_stats['total_visits'],
            'unique_visitors': len(visitor_stats['unique_visitors']),
            'daily_visits': visitor_stats['daily_visits'],
            'page_views': visitor_stats['page_views'],
            'upload_stats': visitor_stats['upload_stats'],
            'download_stats': visitor_stats['download_stats']
        }
        
        logging.info(f"Returning stats: {stats_data}")
        return jsonify(stats_data), 200
    except Exception as e:
        logging.error(f"Stats error: {str(e)}")
        return jsonify({'error': f'Stats failed: {str(e)}'}), 500

@app.route('/api/admin/files', methods=['GET'])
@require_firebase_admin
def get_admin_files():
    """Admin endpoint to get all files with metadata"""
    try:
        logging.info(f"Admin files request from {request.remote_addr}")
        logging.info(f"Firebase user: {getattr(request, 'firebase_user', 'Not set')}")
        
        files = []
        for file_id, metadata in file_metadata.items():
            files.append({
                'id': file_id,
                'share_id': metadata.get('share_id'),
                'filename': metadata['filename'],
                'size': metadata['size'],
                'upload_date': metadata['upload_date'],
                'encrypted': metadata.get('encrypted', False),
                'mime_type': metadata.get('mime_type', 'unknown')
            })
        
        logging.info(f"Returning {len(files)} files")
        return jsonify({'files': files}), 200
    except Exception as e:
        logging.error(f"Admin files error: {str(e)}")
        return jsonify({'error': f'Failed to get files: {str(e)}'}), 500

@app.route('/api/admin/test-session', methods=['GET'])
def test_session():
    """Test endpoint to check if sessions are working"""
    try:
        logging.info(f"Session test request from {request.remote_addr}")
        logging.info(f"Current session: {dict(session)}")
        
        # Set a test value in session
        session['test_value'] = 'session_working'
        
        return jsonify({
            'session_working': True,
            'session_data': dict(session),
            'admin_logged_in': session.get('admin', False)
        }), 200
    except Exception as e:
        logging.error(f"Session test error: {str(e)}")
        return jsonify({'error': f'Session test failed: {str(e)}'}), 500

if __name__ == '__main__':
    # Configure logging
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    logging.basicConfig(level=getattr(logging, log_level.upper()))
    
    # Create S3 bucket if using S3 and it doesn't exist
    if STORAGE_TYPE == 's3' and s3_client:
        try:
            s3_client.head_bucket(Bucket=SECURE_BUCKET)
        except Exception:
            s3_client.create_bucket(Bucket=SECURE_BUCKET)
            logging.info(f"Created S3 bucket: {SECURE_BUCKET}")
    
    # Get port from environment (Railway sets PORT)
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logging.info(f"Starting NCryp server with {STORAGE_TYPE} storage backend")
    logging.info(f"Server will run on {host}:{port}")
    logging.info(f"Debug mode: {debug}")
    
    app.run(debug=debug, host=host, port=port)