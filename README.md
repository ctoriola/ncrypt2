# NCryp - Secure File Storage

A modern, client-side encrypted file storage solution with zero-knowledge architecture. Your files are encrypted before they leave your browser, ensuring maximum privacy and security.

## 🔒 Features

- **Client-side encryption** using AES-256-GCM
- **Zero-knowledge storage** - server cannot access your files
- **Multiple storage backends** - Local, AWS S3, Google Cloud, Azure
- **Malware scanning** with ClamAV integration
- **Secure file upload** with drag-and-drop interface
- **Modern UI** with dark/light mode support
- **Cross-platform** web application
- **Real-time progress** tracking
- **File management** with download and delete capabilities

## 🛡️ Security Features

- **AES-256-GCM encryption** for file content
- **PBKDF2 key derivation** with 100,000 iterations
- **Cryptographically secure** random generation
- **HTTPS enforcement** with modern TLS
- **Content Security Policy** headers
- **Malware scanning** before storage
- **Input validation** and sanitization
- **Secure file handling** with proper MIME type checking

## 🚀 Quick Start (No Cloud Account Required!)

### Prerequisites

- Node.js 16+ and npm
- Python 3.8+

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ncryp.git
   cd ncryp
   ```

2. **Install dependencies**
   ```bash
   npm install
   pip install -r requirements.txt
   ```

3. **Configure environment (uses local storage by default)**
   ```bash
   copy env.example env.local
   # No need to edit - already configured for local storage!
   ```

4. **Start the application**
   ```bash
   start.bat  # Windows
   # or
   ./start.sh  # Linux/Mac
   ```

5. **Open your browser**
   Navigate to `http://localhost:3000`

**That's it!** Files will be stored locally in the `./uploads` directory. No cloud account needed!

## ☁️ Cloud Storage Options

NCryp supports multiple storage backends. See [STORAGE_SETUP.md](STORAGE_SETUP.md) for detailed setup instructions:

- **🏠 Local Storage** (default) - No cloud account needed
- **☁️ AWS S3** - Production recommended
- **🌐 Google Cloud Storage** - Alternative cloud option
- **🔵 Azure Blob Storage** - Microsoft cloud option

## 📁 Project Structure

```
ncryp/
├── src/                    # React frontend source
│   ├── components/         # React components
│   ├── workers/           # Web Workers for encryption
│   ├── App.jsx           # Main application component
│   └── main.jsx          # Application entry point
├── server.py             # Flask backend server
├── requirements.txt      # Python dependencies
├── package.json          # Node.js dependencies
├── vite.config.js        # Vite configuration
├── hardening.nginx       # Nginx security configuration
├── STORAGE_SETUP.md      # Storage backend setup guide
├── env.local             # Environment configuration
├── env.example           # Environment template
└── README.md            # This file
```

## 🔧 Configuration

### Environment Variables

Create an `env.local` file in the root directory:

```env
# Storage Configuration (default: local)
STORAGE_TYPE=local
LOCAL_STORAGE_PATH=./uploads

# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=True
SECRET_KEY=your-secret-key-here

# Security Configuration
MAX_FILE_SIZE=104857600  # 100MB in bytes
ALLOWED_EXTENSIONS=pdf,txt,jpg,jpeg,png,gif,doc,docx,xls,xlsx,csv,zip,rar

# ClamAV Configuration (optional)
CLAMAV_HOST=localhost
CLAMAV_PORT=3310
```

### Cloud Storage Configuration

For cloud storage options, see [STORAGE_SETUP.md](STORAGE_SETUP.md) for detailed setup instructions.

## 🏗️ Architecture

### Frontend (React + Vite)
- **React 18** with modern hooks
- **Vite** for fast development and building
- **Web Workers** for background encryption
- **React Dropzone** for file uploads
- **Toast notifications** for user feedback

### Backend (Flask)
- **Flask** web framework
- **Modular storage backends** (Local, S3, GCS, Azure)
- **Python-magic** for MIME type detection
- **ClamAV** for malware scanning
- **CORS** support for cross-origin requests

### Security Layer
- **Client-side encryption** using Web Crypto API
- **AES-256-GCM** encryption algorithm
- **PBKDF2** key derivation with salt
- **Secure random** generation for IVs
- **Input validation** and sanitization

## 📊 API Endpoints

### File Management
- `POST /api/upload` - Upload encrypted file
- `GET /api/files` - List uploaded files
- `GET /api/files/<file_id>` - Download file
- `DELETE /api/files/<file_id>` - Delete file

### System
- `GET /api/health` - Health check endpoint

## 🔐 Security Considerations

### Client-Side Security
- Files are encrypted before upload
- Encryption keys never leave the browser
- Secure random generation for cryptographic operations
- Input validation and sanitization

### Server-Side Security
- HTTPS enforcement
- Content Security Policy headers
- Malware scanning with ClamAV
- File type validation using magic numbers
- Secure file handling practices

### Data Privacy
- Zero-knowledge architecture
- Server cannot decrypt file contents
- No file content logging
- Secure deletion of files

## 🚀 Deployment

### Development (Local Storage)
```bash
# No cloud setup needed!
npm install
pip install -r requirements.txt
python server.py  # Terminal 1
npm run dev       # Terminal 2
```

### Production Setup

1. **Choose a storage backend** (see [STORAGE_SETUP.md](STORAGE_SETUP.md))
2. **Build the frontend**
   ```bash
   npm run build
   ```

3. **Set up production environment**
   ```bash
   export FLASK_ENV=production
   export FLASK_DEBUG=False
   ```

4. **Use a production WSGI server**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 server:app
   ```

5. **Configure Nginx** (see `hardening.nginx`)

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN npm install && npm run build

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server:app"]
```

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

- **Documentation**: [Wiki](https://github.com/yourusername/ncryp/wiki)
- **Storage Setup**: [STORAGE_SETUP.md](STORAGE_SETUP.md)
- **Issues**: [GitHub Issues](https://github.com/yourusername/ncryp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ncryp/discussions)

## 🙏 Acknowledgments

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for client-side encryption
- [React](https://reactjs.org/) for the frontend framework
- [Flask](https://flask.palletsprojects.com/) for the backend framework
- [ClamAV](https://www.clamav.net/) for malware scanning
- [AWS S3](https://aws.amazon.com/s3/), [Google Cloud Storage](https://cloud.google.com/storage), [Azure Blob Storage](https://azure.microsoft.com/services/storage/blobs/) for cloud storage options

---

**⚠️ Security Notice**: This software is provided as-is. Always verify the security of your deployment and keep dependencies updated. 