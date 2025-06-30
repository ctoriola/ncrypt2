# NCryp - Secure Encrypted File Transfer

NCryp is a secure client-side encrypted file transfer application that allows users to upload files with end-to-end encryption and share them with others using unique share IDs.

## Features

### 🔐 **Client-Side Encryption**
- Files are encrypted in your browser before upload using AES-GCM
- Your data never leaves your device unencrypted
- Uses Web Crypto API for secure encryption

### 📤 **Easy File Sharing**
- Upload files and get a unique 8-character share ID
- Share the ID with anyone to let them download your encrypted file
- No accounts or registration required

### 🔍 **Simple File Discovery**
- Search for files using share IDs
- Download encrypted files shared with you
- Clean, intuitive interface

### 🛡️ **Security Features**
- Malware scanning with ClamAV (optional)
- File type validation
- Size limits and security checks
- Multiple storage backend support

### 📊 **Admin Dashboard**
- Monitor visitor statistics and analytics
- Track file uploads and downloads
- View all stored files and metadata
- Secure admin authentication

### 📱 **Modern UI**
- Responsive design for all devices
- Dark mode support
- Drag-and-drop file upload
- Progress tracking

## How It Works

1. **Upload**: Drag and drop a file, enter a passphrase, and get a share ID
2. **Share**: Send the share ID to anyone you want to share the file with
3. **Download**: Recipients enter the share ID to download the encrypted file
4. **Decrypt**: Use the original passphrase to decrypt the file
5. **Monitor**: Use the admin dashboard to track usage and manage files

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd NCryp
   ```

2. **Install backend dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install frontend dependencies**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

4. **Configure environment**
   ```bash
   cp env.example env.local
   # Edit env.local with your configuration
   ```

5. **Set up admin credentials**
   ```bash
   python generate_admin_password.py
   # Follow the instructions to set up admin password
   ```

6. **Start the application**
   ```bash
   # Windows
   start.bat
   
   # Linux/Mac
   ./start.sh
   ```

   Or run manually:
   ```bash
   # Terminal 1 - Backend
   python server.py
   
   # Terminal 2 - Frontend
   cd frontend
   npm run dev
   ```

7. **Open your browser**
   Navigate to `http://localhost:5173`

## Configuration

### Environment Variables

Create an `env.local` file with the following variables:

```bash
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=your-secret-key-here

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your-generated-password-hash
ADMIN_SESSION_TIMEOUT=3600

# File Upload Settings
MAX_FILE_SIZE=104857600  # 100MB in bytes
ALLOWED_EXTENSIONS=pdf,txt,jpg,jpeg,png,gif,doc,docx,xls,xlsx,csv,zip,rar

# Storage Configuration
STORAGE_TYPE=local  # local, s3, gcs, azure

# Local Storage
LOCAL_STORAGE_PATH=./uploads

# AWS S3 (optional)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# Google Cloud Storage (optional)
GCS_BUCKET_NAME=your-bucket-name

# Azure Blob Storage (optional)
AZURE_CONNECTION_STRING=your-connection-string
AZURE_CONTAINER_NAME=your-container-name

# ClamAV (optional)
CLAMAV_ENABLED=false
```

### Setting Up Admin Access

1. **Generate a secure admin password**:
   ```bash
   python generate_admin_password.py
   ```

2. **Update your env.local file** with the generated password hash:
   ```bash
   ADMIN_PASSWORD_HASH=your-generated-hash-here
   ```

3. **Access the admin dashboard**:
   - Go to the "Admin" tab in the application
   - Login with username: `admin` and your chosen password
   - View statistics, manage files, and monitor usage

### Storage Backends

NCryp supports multiple storage backends:

- **Local Storage** (default): Files stored on local filesystem
- **AWS S3**: Cloud storage with Amazon S3
- **Google Cloud Storage**: Cloud storage with Google Cloud
- **Azure Blob Storage**: Cloud storage with Microsoft Azure

See [STORAGE_SETUP.md](STORAGE_SETUP.md) for detailed setup instructions.

## Usage

### Uploading and Sharing Files

1. Go to the "Upload & Share" tab
2. Drag and drop a file or click to select
3. Enter a secure passphrase (minimum 8 characters)
4. Wait for encryption and upload to complete
5. Copy the generated share ID
6. Share the ID with others via email, messaging, etc.

### Downloading Shared Files

1. Go to the "Download Shared" tab
2. Enter the 8-character share ID
3. Click "Search" to find the file
4. Click "Download Encrypted File" to download
5. Go to the "Decrypt Files" tab to decrypt with the original passphrase

### Decrypting Files

1. Go to the "Decrypt Files" tab
2. Select the encrypted file
3. Enter the original passphrase
4. Click "Decrypt" to download the original file

### Admin Dashboard

1. Go to the "Admin" tab
2. Login with your admin credentials
3. View overview statistics:
   - Total visits and unique visitors
   - Upload and download counts
   - Storage usage information
4. Manage files:
   - View all uploaded files
   - See file metadata and share IDs
   - Monitor file status
5. View analytics:
   - Daily visit trends
   - Page view statistics
   - Usage patterns

## Security

### Encryption Details
- **Algorithm**: AES-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Key Size**: 256 bits
- **Salt**: 16 bytes (random)
- **IV**: 12 bytes (random)

### Security Features
- Client-side encryption (files encrypted before upload)
- Secure key derivation from passphrase
- File type validation
- Malware scanning (optional)
- No server-side access to unencrypted files
- Secure admin authentication with HMAC-SHA256
- Session-based admin access with timeout

## API Endpoints

### File Management
- `POST /api/upload` - Upload encrypted file
- `GET /api/files` - List user's files
- `GET /api/files/<file_id>` - Download file by ID or share ID
- `DELETE /api/files/<file_id>` - Delete file

### File Sharing
- `GET /api/search/<share_id>` - Search for file by share ID

### Admin Endpoints
- `POST /api/admin/login` - Admin login
- `POST /api/admin/logout` - Admin logout
- `GET /api/admin/stats` - Get visitor and usage statistics
- `GET /api/admin/files` - Get all files with metadata

## Development

### Project Structure
```
NCryp/
├── server.py              # Flask backend
├── requirements.txt       # Python dependencies
├── env.example           # Environment template
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── App.jsx       # Main app component
│   │   └── main.jsx      # App entry point
│   ├── package.json      # Node dependencies
│   └── vite.config.js    # Vite configuration
└── uploads/              # Local file storage
```

### Running in Development

```bash
# Backend (Flask)
python server.py

# Frontend (React + Vite)
cd frontend
npm run dev
```

### Building for Production

```bash
# Build frontend
cd frontend
npm run build

# Serve with Flask
python server.py
```

## Deployment

### Railway
1. Connect your GitHub repository to Railway
2. Set environment variables in Railway dashboard
3. Deploy automatically on push

### Heroku
1. Create a Heroku app
2. Set environment variables
3. Deploy using Git

### Docker
```bash
docker build -t ncryp .
docker run -p 5000:5000 ncryp
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the configuration examples

## Security Considerations

- Always use strong, unique passphrases
- Share passphrases securely (not through the same channel as share IDs)
- Regularly rotate passphrases for sensitive files
- Consider the security implications of your chosen storage backend
- Keep the application and dependencies updated 