# Railway Deployment Guide for NCryp Backend (Postgres)

This guide will help you deploy the NCryp backend to Railway with Postgres database.

## Prerequisites

1. **Railway Account**: Sign up at [railway.app](https://railway.app)
2. **GitHub Repository**: Your NCryp project should be on GitHub

## Step 1: Connect Your Repository

1. Go to [Railway Dashboard](https://railway.app/dashboard)
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose your NCryp repository
5. Select the branch you want to deploy (usually `main` or `master`)

## Step 2: Add Postgres Database

1. In your Railway project dashboard, click "New"
2. Select "Database" → "PostgreSQL"
3. Railway will automatically provision a Postgres database
4. Copy the `DATABASE_URL` from the database service

## Step 3: Configure Environment Variables

In your Railway project dashboard, go to the "Variables" tab and add these environment variables:

### Required Variables

```bash
# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-generated-secret-key-here

# Database Configuration
DATABASE_URL=your-railway-postgres-url

# Storage Configuration (choose one)
STORAGE_TYPE=local
LOCAL_STORAGE_PATH=./uploads

# CORS Configuration
CORS_ORIGINS=*

# File Upload Limits
MAX_FILE_SIZE=104857600
ALLOWED_EXTENSIONS=pdf,txt,jpg,jpeg,png,gif,doc,docx,xls,xlsx,csv,zip,rar
```

### Optional Variables (for cloud storage)

```bash
# For AWS S3
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1
S3_BUCKET_NAME=your-bucket-name

# For Google Cloud Storage
GCS_BUCKET_NAME=your-bucket-name

# For Azure Blob Storage
AZURE_CONNECTION_STRING=your-azure-connection-string
AZURE_CONTAINER_NAME=your-container-name
```

## Step 4: Generate Required Values

### Generate Secret Key
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Step 5: Deploy

1. Railway will automatically detect your Python project
2. It will install dependencies from `requirements.txt`
3. It will use the `Procfile` to start the application
4. The deployment will be available at `https://your-app-name.railway.app`

## Step 6: Create Admin User

After deployment, create your first admin user:

### Option A: Run Locally with Railway Database
```bash
# Get your Railway DATABASE_URL from the dashboard
DATABASE_URL="your-railway-postgres-url" python create_admin.py
```

### Option B: Use Railway CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and run the script
railway login
railway run python create_admin.py
```

### Option C: Add to Deployment
Add this to your `Procfile` for one-time setup:
```
setup: python create_admin.py
web: gunicorn --bind 0.0.0.0:$PORT server:app
```

## Step 7: Update Frontend Configuration

Update your frontend environment variables:

```bash
# In your frontend .env file or Netlify environment variables
VITE_API_URL=https://your-app-name.railway.app
```

## Step 8: Test Your Deployment

1. **Health Check**: Visit `https://your-app-name.railway.app/api/health`
2. **Admin Dashboard**: Visit your frontend and try logging into the admin panel
3. **File Upload**: Test uploading and downloading files

## Troubleshooting

### Common Issues

1. **Build Failures**:
   - Check that all dependencies are in `requirements.txt`
   - Ensure Python version in `runtime.txt` is correct

2. **Database Connection Issues**:
   - Verify `DATABASE_URL` is correctly set
   - Check that Postgres service is running
   - Ensure tables are created (they should auto-create)

3. **Environment Variables**:
   - Verify all required variables are set in Railway dashboard
   - Check that `DATABASE_URL` points to your Railway Postgres

4. **CORS Issues**:
   - Ensure `CORS_ORIGINS` includes your frontend domain
   - Check that frontend is making requests to the correct backend URL

5. **Admin Login Issues**:
   - Ensure admin user was created successfully
   - Check that `DATABASE_URL` is accessible from your local machine
   - Verify the admin user exists in the database

### Logs

- View logs in Railway dashboard under the "Deployments" tab
- Use `railway logs` command if you have Railway CLI installed

## Production Recommendations

1. **Use Cloud Storage**: Railway's local storage is ephemeral
2. **Set Up Monitoring**: Use Railway's built-in monitoring
3. **Enable Auto-Deploy**: Connect your GitHub repository for automatic deployments
4. **Set Up Custom Domain**: Configure a custom domain in Railway settings
5. **Database Backups**: Railway provides automatic Postgres backups

## Security Notes

1. **Never commit sensitive data**: Use environment variables
2. **Rotate secrets regularly**: Update SECRET_KEY periodically
3. **Monitor access logs**: Check Railway logs for suspicious activity
4. **Use HTTPS**: Railway provides SSL certificates automatically
5. **Change admin password**: Use a strong password for production

## Database Schema

The application uses these Postgres tables:

- **admin_users**: Admin authentication
- **files**: File metadata and information
- **file_history**: File action history
- **stats**: Application statistics

## Support

- Railway Documentation: [docs.railway.app](https://docs.railway.app)
- Railway Discord: [discord.gg/railway](https://discord.gg/railway)
- NCryp Issues: Create an issue in your GitHub repository 