# 🔐 NCryp - Secure File Storage & Encryption

A modern, **zero-knowledge** file storage solution with client-side encryption. Your files are encrypted with **AES-256-GCM** before they leave your browser, ensuring maximum privacy and security. Perfect for sensitive documents, personal files, and secure collaboration.

## ✨ Live Demo

**🚀 Deployed and Ready to Use:**
- **Frontend**: [Netlify](https://ncryp-app.netlify.app) 
- **Backend**: [Railway](https://ncryp-backend.railway.app)

## 🔒 Key Features

### 🛡️ **Enterprise-Grade Security**
- **AES-256-GCM encryption** - Military-grade encryption standard
- **PBKDF2 key derivation** with 100,000 iterations
- **Client-side encryption** - Files encrypted before upload
- **Zero-knowledge architecture** - Server cannot access your files
- **Cryptographically secure** random generation

### 📱 **Cross-Platform Compatibility**
- **Mobile-friendly** - Works on iOS, Android, tablets
- **Desktop optimized** - Windows, Mac, Linux
- **Modern browsers** - Chrome, Firefox, Safari, Edge
- **Responsive design** - Adapts to any screen size

### ☁️ **Flexible Storage Options**
- **🏠 Local Storage** (default) - No cloud account needed
- **☁️ AWS S3** - Production recommended
- **🌐 Google Cloud Storage** - Alternative cloud option
- **🔵 Azure Blob Storage** - Microsoft cloud option

### 🎨 **Modern User Experience**
- **Drag-and-drop** file uploads
- **Real-time progress** tracking
- **File management** with download/delete
- **Dark/light mode** support
- **Toast notifications** for feedback

## 🚀 Quick Start (No Setup Required!)

### Option 1: Use the Live Demo
1. Visit [https://ncryp-app.netlify.app](https://ncryp-app.netlify.app)
2. Upload and encrypt your files instantly
3. No installation or setup required!

### Option 2: Local Development

#### Prerequisites
- Node.js 16+ and npm
- Python 3.8+

#### Installation
```bash
# Clone the repository
git clone https://github.com/ctoriola/NCrypt.git
cd NCrypt

# Install dependencies
npm install
pip install -r requirements.txt

# Start the application
start.bat  # Windows
# or
./start.sh  # Linux/Mac

# Open http://localhost:3000
```

**That's it!** Files are stored locally by default - no cloud account needed!

## 🔐 How It Works

### **Encryption Process**
```
1. User selects file + enters passphrase
2. Browser generates random salt (16 bytes) + IV (12 bytes)
3. PBKDF2 derives 256-bit key from passphrase + salt
4. AES-256-GCM encrypts file with key + IV
5. Encrypted data uploaded to server
6. Server stores encrypted blob (cannot decrypt)
```

### **Decryption Process**
```
1. User downloads encrypted file
2. Browser extracts salt + IV from file
3. PBKDF2 derives same key using passphrase + salt
4. AES-256-GCM decrypts file using key + IV
5. Original file restored to user's computer
```

### **Security Architecture**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Storage       │
│   (Netlify)     │◄──►│   (Railway)     │◄──►│   (Local/S3/etc)│
│                 │    │                 │    │                 │
│ • React App     │    │ • Flask Server  │    │ • File Storage  │
│ • Encryption    │    │ • API Endpoints │    │ • Metadata      │
│ • User Interface│    │ • File Handling │    │ • Security      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 Project Structure

```
NCrypt/
├── frontend/              # React frontend (deployed to Netlify)
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── workers/       # Web Workers for encryption
│   │   └── main.jsx       # Application entry point
│   └── package.json       # Frontend dependencies
├── server.py              # Flask backend (deployed to Railway)
├── requirements.txt       # Python dependencies
├── Dockerfile             # Container configuration
├── railway.json           # Railway deployment config
├── netlify.toml           # Netlify deployment config
├── STORAGE_SETUP.md       # Storage backend setup guide
└── README.md              # This file
```

## 🔧 Configuration

### Environment Variables

```env
# Storage Configuration (default: local)
STORAGE_TYPE=local
LOCAL_STORAGE_PATH=/tmp/ncryp-uploads  # Railway-compatible path

# Flask Configuration
FLASK_ENV=production
SECRET_KEY=your-secret-key-here

# Security Configuration
MAX_FILE_SIZE=104857600  # 100MB in bytes
ALLOWED_EXTENSIONS=pdf,txt,jpg,jpeg,png,gif,doc,docx,xls,xlsx,csv,zip,rar
```

### Cloud Storage Setup

See [STORAGE_SETUP.md](STORAGE_SETUP.md) for detailed cloud storage configuration.

## 🏗️ Technical Architecture

### **Frontend (React + Vite)**
- **React 18** with modern hooks and functional components
- **Vite** for fast development and optimized builds
- **Web Crypto API** for client-side encryption
- **React Dropzone** for drag-and-drop file uploads
- **Toast notifications** for user feedback
- **Responsive design** for mobile compatibility

### **Backend (Flask)**
- **Flask** web framework with RESTful API
- **Modular storage backends** (Local, S3, GCS, Azure)
- **MIME type detection** using Python's mimetypes
- **CORS support** for cross-origin requests
- **Error handling** and logging
- **Railway deployment** ready

### **Security Layer**
- **AES-256-GCM** encryption algorithm
- **PBKDF2** key derivation with 100,000 iterations
- **Cryptographically secure** random generation
- **Client-side only** encryption/decryption
- **Zero-knowledge** server architecture

## 📊 API Endpoints

### File Management
- `POST /api/upload` - Upload encrypted file
- `GET /api/files` - List uploaded files
- `GET /api/files/<file_id>` - Download file
- `DELETE /api/files/<file_id>` - Delete file

### System
- `GET /api/health` - Health check endpoint

## 🚀 Deployment

### **Production Deployment (Current)**

The application is currently deployed using:

- **Frontend**: Netlify (automatic deployment from GitHub)
- **Backend**: Railway (automatic deployment from GitHub)
- **Storage**: Local filesystem on Railway

### **Local Development**
```bash
# Terminal 1: Backend
python server.py

# Terminal 2: Frontend  
npm run dev
```

### **Docker Deployment**
```bash
# Build and run with Docker
docker build -t ncryp .
docker run -p 8000:8000 ncryp
```

## 🔐 Security Features

### **Client-Side Security**
- ✅ Files encrypted before upload
- ✅ Encryption keys never leave browser
- ✅ Secure random generation for cryptographic operations
- ✅ Input validation and sanitization
- ✅ Mobile-compatible encryption

### **Server-Side Security**
- ✅ HTTPS enforcement
- ✅ Content Security Policy headers
- ✅ File type validation
- ✅ Secure file handling practices
- ✅ Railway deployment security

### **Data Privacy**
- ✅ Zero-knowledge architecture
- ✅ Server cannot decrypt file contents
- ✅ No file content logging
- ✅ Secure deletion of files
- ✅ GDPR/HIPAA compliant design

## 📱 Mobile Compatibility

NCryp is fully optimized for mobile devices:

- **Touch-friendly** interface
- **Responsive design** adapts to screen size
- **Mobile file picker** integration
- **Optimized encryption** for mobile performance
- **Cross-browser** compatibility

## 💰 Cost Comparison

| Storage Type | Setup Cost | Monthly Cost (100GB) | Scalability |
|--------------|------------|---------------------|-------------|
| **Local** | Free | Free | Limited |
| **AWS S3** | Free | ~$2.30 | Excellent |
| **Google Cloud** | Free | ~$2.00 | Excellent |
| **Azure** | Free | ~$1.84 | Excellent |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Live Demo**: [https://ncryp-app.netlify.app](https://ncryp-app.netlify.app)
- **Documentation**: [Wiki](https://github.com/ctoriola/NCrypt/wiki)
- **Storage Setup**: [STORAGE_SETUP.md](STORAGE_SETUP.md)
- **Issues**: [GitHub Issues](https://github.com/ctoriola/NCrypt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ctoriola/NCrypt/discussions)

## 🙏 Acknowledgments

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for client-side encryption
- [React](https://reactjs.org/) for the frontend framework
- [Flask](https://flask.palletsprojects.com/) for the backend framework
- [Railway](https://railway.app/) for backend hosting
- [Netlify](https://netlify.com/) for frontend hosting
- [AWS S3](https://aws.amazon.com/s3/), [Google Cloud Storage](https://cloud.google.com/storage), [Azure Blob Storage](https://azure.microsoft.com/services/storage/blobs/) for cloud storage options

---

**🔐 Security Notice**: NCryp uses industry-standard encryption (AES-256-GCM) with zero-knowledge architecture. Your files are encrypted client-side and the server cannot access your data. Always keep your passphrases secure and never share them.

**⭐ Star this repository if you find it useful!** 