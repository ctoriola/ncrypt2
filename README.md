# NCryp - Secure Encrypted File Transfer

NCryp is a secure client-side encrypted file storage and transfer system with a modern React frontend and Flask backend. It features user authentication, tiered subscriptions, and supports multiple cloud storage backends.

## 🌟 Features

### 🔐 Security
- **Client-side encryption** using AES-GCM before upload
- **Zero-knowledge storage** - files are encrypted before reaching the server
- **Malware scanning** with ClamAV integration
- **Secure file validation** and MIME type checking

### 👥 User Management
- **User authentication** with registration and login
- **Tiered subscription system** with different upload limits
- **Anonymous usage** with limited uploads (2 files per session)
- **Session management** with secure cookies

### 📁 File Management
- **Drag-and-drop upload** with progress tracking
- **Shareable file IDs** for easy file sharing
- **File search** by share ID
- **File listing** with download and delete options
- **Client-side decryption** for secure file access

### ☁️ Storage Options
- **Local filesystem** storage (default)
- **AWS S3** integration
- **Google Cloud Storage** integration
- **Azure Blob Storage** integration

### 🎨 User Interface
- **Modern React UI** with dark/light mode
- **Responsive design** for mobile and desktop
- **Real-time progress** indicators
- **Toast notifications** for user feedback

## 📊 Subscription Tiers

| Tier | Upload Limit | Price | Features |
|------|-------------|-------|----------|
| **Free** | 2 files | $0/month | Basic encryption, file sharing |
| **Basic** | 10 files | $5/month | Advanced encryption, priority support |
| **Pro** | 100 files | $15/month | Enterprise encryption, 24/7 support |
| **Enterprise** | 1000 files | $50/month | Custom limits, dedicated support |

**Anonymous users** can upload 2 files per session without registration.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- SQLite (included) or PostgreSQL/MySQL
- ClamAV (optional, for malware scanning)

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd NCryp
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   cp env.example env.local
   # Edit env.local with your configuration
   ```

4. **Initialize the database**
   ```bash
   python -c "from server import app, db; app.app_context().push(); db.create_all()"
   ```

5. **Run the backend**
   ```bash
   python server.py
   ```

### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   # Create .env file
   echo "VITE_API_URL=http://localhost:5000" > .env
   ```

4. **Run the development server**
   ```bash
   npm run dev
   ```

## 🔧 Configuration

### Environment Variables

#### Required
- `SECRET_KEY`: Flask secret key for sessions
- `DATABASE_URL`: Database connection string
- `STORAGE_BACKEND`: Storage backend type (local, s3, gcs, azure)

#### Optional
- `MAX_FILE_SIZE`: Maximum file size in bytes (default: 100MB)
- `CLAMAV_HOST`: ClamAV host for malware scanning
- `CORS_ORIGINS`: Allowed CORS origins

### Database Setup

The application uses SQLAlchemy with support for:
- **SQLite** (default, good for development)
- **PostgreSQL** (recommended for production)
- **MySQL** (alternative for production)

### Storage Backend Configuration

#### Local Storage (Default)
```bash
STORAGE_BACKEND=local
LOCAL_STORAGE_PATH=uploads
```

#### AWS S3
```bash
STORAGE_BACKEND=s3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket
```

#### Google Cloud Storage
```bash
STORAGE_BACKEND=gcs
GOOGLE_CLOUD_PROJECT=your-project
GOOGLE_CLOUD_BUCKET=your-bucket
GOOGLE_APPLICATION_CREDENTIALS=path/to/key.json
```

#### Azure Blob Storage
```bash
STORAGE_BACKEND=azure
AZURE_STORAGE_ACCOUNT=your-account
AZURE_STORAGE_KEY=your-key
AZURE_CONTAINER_NAME=your-container
```

## 📖 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "user123",
  "email": "user@example.com",
  "password": "securepassword"
}
```

#### Login User
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "user123",
  "password": "securepassword"
}
```

#### Get Current User
```http
GET /api/auth/me
```

#### Logout
```http
POST /api/auth/logout
```

### File Management Endpoints

#### Upload File
```http
POST /api/upload
Content-Type: multipart/form-data

file: [encrypted file data]
```

#### List Files
```http
GET /api/files
```

#### Download File
```http
GET /api/files/{file_id}
# or
GET /api/files/{share_id}
```

#### Delete File
```http
DELETE /api/files/{file_id}
```

#### Search File
```http
GET /api/search/{share_id}
```

## 🛠️ Development

### Project Structure
```
NCryp/
├── server.py              # Main Flask application
├── models.py              # Database models
├── auth.py                # Authentication routes
├── requirements.txt       # Python dependencies
├── env.example           # Environment variables template
├── frontend/             # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── workers/      # Web Workers
│   │   └── App.jsx       # Main app component
│   ├── package.json      # Node.js dependencies
│   └── vite.config.js    # Vite configuration
└── uploads/              # File storage (local backend)
```

### Database Models

#### User
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email address
- `password_hash`: Bcrypt hashed password
- `subscription_tier`: Subscription level (free, basic, pro, enterprise)
- `subscription_expires`: Subscription expiration date
- `created_at`: Account creation timestamp

#### FileRecord
- `id`: Primary key
- `file_id`: Unique file UUID
- `share_id`: 8-character shareable ID
- `filename`: Original filename
- `size`: File size in bytes
- `user_id`: Associated user (null for anonymous)
- `session_id`: Session ID for anonymous users
- `upload_date`: Upload timestamp

### Security Features

1. **Client-side Encryption**: Files are encrypted using AES-GCM before upload
2. **Password Hashing**: User passwords are hashed with Bcrypt
3. **Session Management**: Secure session cookies with CSRF protection
4. **File Validation**: MIME type and size validation
5. **Malware Scanning**: Optional ClamAV integration
6. **Rate Limiting**: Upload limits based on subscription tier

## 🚀 Deployment

### Railway Deployment
The application is configured for Railway deployment with:
- Automatic database setup
- Environment variable configuration
- Build and deployment scripts

### Docker Deployment
```bash
# Build the image
docker build -t ncryp .

# Run the container
docker run -p 5000:5000 -e DATABASE_URL=sqlite:///ncryp.db ncryp
```

### Production Considerations
1. **Use HTTPS**: Set `SESSION_COOKIE_SECURE=True`
2. **Database**: Use PostgreSQL or MySQL for production
3. **Storage**: Use cloud storage (S3, GCS, Azure) for scalability
4. **Monitoring**: Set up logging and monitoring
5. **Backup**: Regular database and file backups

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the configuration examples

## 🔄 Changelog

### v2.0.0 - Tiered Subscription System
- Added user authentication and registration
- Implemented tiered subscription system
- Added anonymous user support with 2-file limit
- Enhanced UI with user profile and subscription management
- Improved file tracking and user association

### v1.0.0 - Initial Release
- Client-side encryption
- File upload and sharing
- Multiple storage backends
- Modern React UI 