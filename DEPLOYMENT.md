# NCryp Deployment Guide

This guide will help you deploy NCryp to production. Since this is a full-stack application (React frontend + Flask backend), you'll need to deploy them separately.

## 🚀 **Option 1: Deploy Backend to Railway (Recommended)**

### Step 1: Deploy Backend to Railway

1. **Create Railway Account**: Go to [railway.app](https://railway.app) and sign up
2. **Connect GitHub**: Connect your GitHub account to Railway
3. **Deploy from GitHub**: 
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your NCryp repository
   - Railway will automatically detect it's a Python app

4. **Configure Environment Variables**:
   - Go to your project settings
   - Add these environment variables:
   ```
   STORAGE_TYPE=local
   LOCAL_STORAGE_PATH=./uploads
   MAX_FILE_SIZE=104857600
   FLASK_ENV=production
   ```

5. **Get Your Backend URL**: Railway will give you a URL like `https://your-app-name.railway.app`

### Step 2: Deploy Frontend to Netlify

1. **Create Netlify Account**: Go to [netlify.com](https://netlify.com) and sign up
2. **Connect GitHub**: Connect your GitHub account to Netlify
3. **Deploy from GitHub**:
   - Click "New site from Git"
   - Choose your NCryp repository
   - Set build settings:
     - **Build command**: `npm run build`
     - **Publish directory**: `dist`
   - Click "Deploy site"

4. **Configure Environment Variables**:
   - Go to Site settings > Environment variables
   - Add: `VITE_API_URL=https://your-app-name.railway.app`
   - Redeploy the site

## 🚀 **Option 2: Deploy Backend to Render**

### Step 1: Deploy Backend to Render

1. **Create Render Account**: Go to [render.com](https://render.com) and sign up
2. **Create New Web Service**:
   - Connect your GitHub repository
   - Choose "Web Service"
   - Set build command: `pip install -r requirements.txt`
   - Set start command: `gunicorn server:app --bind 0.0.0.0:$PORT`
   - Choose your plan (Free tier available)

3. **Configure Environment Variables**:
   ```
   STORAGE_TYPE=local
   LOCAL_STORAGE_PATH=./uploads
   MAX_FILE_SIZE=104857600
   FLASK_ENV=production
   ```

4. **Get Your Backend URL**: Render will give you a URL like `https://your-app-name.onrender.com`

### Step 2: Deploy Frontend to Netlify

Follow the same steps as Option 1, but use your Render backend URL.

## 🚀 **Option 3: Deploy Backend to Heroku**

### Step 1: Deploy Backend to Heroku

1. **Create Heroku Account**: Go to [heroku.com](https://heroku.com) and sign up
2. **Install Heroku CLI**: Download and install from [devcenter.heroku.com](https://devcenter.heroku.com/articles/heroku-cli)
3. **Deploy**:
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

4. **Configure Environment Variables**:
   ```bash
   heroku config:set STORAGE_TYPE=local
   heroku config:set LOCAL_STORAGE_PATH=./uploads
   heroku config:set MAX_FILE_SIZE=104857600
   heroku config:set FLASK_ENV=production
   ```

5. **Get Your Backend URL**: `https://your-app-name.herokuapp.com`

### Step 2: Deploy Frontend to Netlify

Follow the same steps as Option 1, but use your Heroku backend URL.

## 🔧 **Environment Variables Reference**

### Backend Environment Variables
```bash
# Storage Configuration
STORAGE_TYPE=local                    # local, s3, gcs, azure
LOCAL_STORAGE_PATH=./uploads          # Local storage path
MAX_FILE_SIZE=104857600               # 100MB in bytes

# Flask Configuration
FLASK_ENV=production                  # production or development
SECRET_KEY=your-secret-key            # Flask secret key

# AWS S3 (if using S3 storage)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# Google Cloud Storage (if using GCS)
GCS_BUCKET_NAME=your-bucket-name

# Azure Blob Storage (if using Azure)
AZURE_CONNECTION_STRING=your-connection-string
AZURE_CONTAINER_NAME=your-container-name
```

### Frontend Environment Variables
```bash
# API Configuration
VITE_API_URL=https://your-backend-url.com
```

## 🐛 **Troubleshooting**

### Common Issues:

1. **CORS Errors**: Make sure your backend has CORS configured properly
2. **API URL Not Found**: Check that `VITE_API_URL` is set correctly in Netlify
3. **Upload Failures**: Verify file size limits and storage configuration
4. **Build Failures**: Check that all dependencies are in `package.json` and `requirements.txt`

### Testing Your Deployment:

1. **Test Backend**: Visit `https://your-backend-url.com/api/health`
2. **Test Frontend**: Visit your Netlify URL and try uploading a file
3. **Check Logs**: Use your hosting platform's log viewer to debug issues

## 🔒 **Security Considerations**

1. **HTTPS**: All production deployments should use HTTPS
2. **Environment Variables**: Never commit sensitive data to your repository
3. **CORS**: Configure CORS to only allow your frontend domain in production
4. **File Storage**: Consider using cloud storage (S3, GCS, Azure) for production

## 📝 **Next Steps**

After deployment:
1. Test all functionality (upload, download, delete, decrypt)
2. Set up monitoring and logging
3. Configure backups for your storage
4. Set up a custom domain (optional)
5. Configure SSL certificates (usually automatic)

## 🆘 **Need Help?**

If you encounter issues:
1. Check the logs in your hosting platform
2. Verify all environment variables are set correctly
3. Test the backend API endpoints directly
4. Check browser console for frontend errors 