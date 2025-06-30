# NCryp Production Deployment Guide

This guide covers deploying NCryp to production using Netlify (frontend) and Railway (backend).

## 🚀 Quick Deployment

### 1. Backend Deployment (Railway)

1. **Connect your GitHub repository to Railway**
   - Go to [Railway.app](https://railway.app)
   - Create a new project
   - Connect your GitHub repository
   - Railway will automatically detect the Python project

2. **Configure environment variables in Railway**
   ```bash
   # Required variables
   FLASK_ENV=production
   FLASK_DEBUG=False
   SECRET_KEY=your-generated-secret-key
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD_HASH=your-generated-password-hash
   STORAGE_TYPE=local
   LOCAL_STORAGE_PATH=/tmp/ncryp-uploads
   
   # Optional: Cloud storage (recommended for production)
   # STORAGE_TYPE=s3
   # AWS_ACCESS_KEY_ID=your-key
   # AWS_SECRET_ACCESS_KEY=your-secret
   # AWS_REGION=us-east-1
   # S3_BUCKET_NAME=your-bucket
   
   # CORS (set to your Netlify domain)
   CORS_ORIGINS=https://your-app-name.netlify.app
   ```

3. **Deploy**
   - Railway will automatically build and deploy
   - Get your Railway URL (e.g., `https://your-app-name.railway.app`)

### 2. Frontend Deployment (Netlify)

1. **Connect your GitHub repository to Netlify**
   - Go to [Netlify.com](https://netlify.com)
   - Create a new site from Git
   - Connect your GitHub repository

2. **Configure build settings**
   ```bash
   Base directory: frontend
   Build command: npm run build
   Publish directory: dist
   ```

3. **Set environment variables**
   ```bash
   VITE_API_URL=https://your-app-name.railway.app
   ```

4. **Deploy**
   - Netlify will automatically build and deploy
   - Get your Netlify URL (e.g., `https://your-app-name.netlify.app`)

## 🔧 Detailed Configuration

### Environment Variables

#### Railway (Backend) Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `FLASK_ENV` | Flask environment | Yes | `production` |
| `FLASK_DEBUG` | Debug mode | Yes | `False` |
| `SECRET_KEY` | Flask secret key | Yes | Generate new |
| `ADMIN_USERNAME` | Admin username | Yes | `admin` |
| `ADMIN_PASSWORD_HASH` | Admin password hash | Yes | Generate new |
| `STORAGE_TYPE` | Storage backend | Yes | `local` |
| `LOCAL_STORAGE_PATH` | Local storage path | Yes | `/tmp/ncryp-uploads` |
| `CORS_ORIGINS` | Allowed origins | Yes | Your Netlify domain |
| `MAX_FILE_SIZE` | Max file size | No | `104857600` |
| `LOG_LEVEL` | Logging level | No | `INFO` |

#### Netlify (Frontend) Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `VITE_API_URL` | Backend API URL | Yes | Your Railway URL |

### Storage Configuration

#### Option 1: Local Storage (Temporary)
```bash
STORAGE_TYPE=local
LOCAL_STORAGE_PATH=/tmp/ncryp-uploads
```
⚠️ **Warning**: Data will be lost on Railway restarts

#### Option 2: AWS S3 (Recommended)
```bash
STORAGE_TYPE=s3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name
```

#### Option 3: Google Cloud Storage
```bash
STORAGE_TYPE=gcs
GCS_BUCKET_NAME=your-bucket-name
# Set GOOGLE_APPLICATION_CREDENTIALS in Railway
```

#### Option 4: Azure Blob Storage
```bash
STORAGE_TYPE=azure
AZURE_CONNECTION_STRING=your-connection-string
AZURE_CONTAINER_NAME=your-container-name
```

## 🔐 Security Setup

### 1. Generate Secret Key
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Generate Admin Password
```bash
python generate_admin_password.py
```

### 3. Update Railway Variables
- Add the generated secret key to `SECRET_KEY`
- Add the generated password hash to `ADMIN_PASSWORD_HASH`

## 📊 Monitoring & Analytics

### Railway Monitoring
- **Logs**: View real-time logs in Railway dashboard
- **Metrics**: Monitor CPU, memory, and network usage
- **Health Checks**: Automatic health checks at `/api/health`

### Admin Dashboard
- Access via your Netlify domain → Admin tab
- Monitor visitor statistics
- Track file uploads/downloads
- View system analytics

## 🔄 Continuous Deployment

### Automatic Deployments
- **Railway**: Automatically deploys on Git push to main branch
- **Netlify**: Automatically deploys on Git push to main branch

### Manual Deployments
```bash
# Railway
railway up

# Netlify
netlify deploy --prod
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. CORS Errors
**Problem**: Frontend can't connect to backend
**Solution**: 
- Set `CORS_ORIGINS` to your exact Netlify domain
- Include protocol: `https://your-app.netlify.app`

#### 2. File Upload Failures
**Problem**: Files not uploading
**Solution**:
- Check `MAX_FILE_SIZE` setting
- Verify storage backend configuration
- Check Railway logs for errors

#### 3. Admin Login Issues
**Problem**: Can't access admin dashboard
**Solution**:
- Verify `ADMIN_PASSWORD_HASH` is correctly set
- Check that password hash was generated properly
- Ensure `SECRET_KEY` is set

#### 4. Storage Issues
**Problem**: Files disappearing after restart
**Solution**:
- Switch to cloud storage (S3, GCS, Azure)
- Local storage is ephemeral on Railway

### Debug Mode
For troubleshooting, temporarily enable debug mode:
```bash
FLASK_DEBUG=True
LOG_LEVEL=DEBUG
```

## 📈 Performance Optimization

### Frontend (Netlify)
- Automatic code splitting
- Optimized bundle sizes
- CDN distribution
- Automatic HTTPS

### Backend (Railway)
- Automatic scaling
- Health checks
- Load balancing
- Automatic restarts

## 🔒 Production Security Checklist

- [ ] Generate new `SECRET_KEY`
- [ ] Generate secure admin password
- [ ] Set `FLASK_DEBUG=False`
- [ ] Configure CORS origins
- [ ] Set up cloud storage
- [ ] Enable HTTPS (automatic on Railway/Netlify)
- [ ] Configure proper file size limits
- [ ] Set up monitoring and logging

## 🚀 Deployment Commands

### Quick Deploy
```bash
# 1. Generate production credentials
python generate_admin_password.py
python -c "import secrets; print(secrets.token_hex(32))"

# 2. Update Railway environment variables
# 3. Push to GitHub (triggers automatic deployment)
git add .
git commit -m "Production deployment"
git push
```

### Manual Railway Deploy
```bash
railway login
railway link
railway up
```

### Manual Netlify Deploy
```bash
cd frontend
npm run build
netlify deploy --prod --dir=dist
```

## 📞 Support

For deployment issues:
1. Check Railway logs
2. Check Netlify build logs
3. Verify environment variables
4. Test API endpoints directly
5. Check CORS configuration

## 🔄 Updates

To update your deployment:
1. Make changes to your code
2. Test locally if possible
3. Push to GitHub
4. Monitor deployment logs
5. Verify functionality on production 