import os
import re
import uuid
import json
import mimetypes
import boto3
import secrets
import string
from datetime import datetime
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import logging
from pathlib import Path

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
CORS(app, origins=['*'])  # Allow all origins for now, configure properly in production

# Configuration
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB max file size
ALLOWED_MIME_TYPES = {
    'application/pdf', 'text/plain', 'image/jpeg', 'image/png', 
    'image/gif', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv', 'application/zip', 'application/x-rar-compressed', 'application/octet-stream'
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

# Generate a short, shareable ID (8 characters, alphanumeric)
def generate_share_id():
    """Generate a short, shareable ID for files"""
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(8))

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload and store an encrypted file"""
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

        logging.info(f"File uploaded successfully: {file_id} (share_id: {share_id})")
        
        return jsonify({
            'success': True,
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

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create S3 bucket if using S3 and it doesn't exist
    if STORAGE_TYPE == 's3' and s3_client:
        try:
            s3_client.head_bucket(Bucket=SECURE_BUCKET)
        except Exception:
            s3_client.create_bucket(Bucket=SECURE_BUCKET)
            logging.info(f"Created S3 bucket: {SECURE_BUCKET}")
    
    logging.info(f"Starting NCryp server with {STORAGE_TYPE} storage backend")
    app.run(debug=True, host='0.0.0.0', port=5000)