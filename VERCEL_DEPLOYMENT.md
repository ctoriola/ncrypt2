# Vercel Deployment Guide for NCryp

This guide will help you deploy the NCryp backend to Vercel and update your frontend to use the new backend URL.

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
2. **Cloud Storage**: Set up AWS S3, Google Cloud Storage, or Azure Blob Storage (Vercel doesn't support persistent local storage)
3. **GitHub Repository**: Your NCryp code should be in a GitHub repository

## Step 1: Prepare Cloud Storage

Since Vercel uses serverless functions, you **must** use cloud storage instead of local storage.

### Option A: AWS S3 (Recommended)

1. Create an AWS account and S3 bucket
2. Create an IAM user with S3 permissions
3. Note down:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_REGION`
   - `S3_BUCKET_NAME`

### Option B: Google Cloud Storage

1. Create a Google Cloud project and storage bucket
2. Create a service account with storage permissions
3. Download the service account JSON file
4. Note down:
   - `GCS_BUCKET_NAME`
   - Service account JSON content

### Option C: Azure Blob Storage

1. Create an Azure storage account and container
2. Get the connection string
3. Note down:
   - `AZURE_STORAGE_CONNECTION_STRING`
   - `AZURE_CONTAINER_NAME`

## Step 2: Deploy Backend to Vercel

1. **Connect Repository to Vercel**:
   - Go to [vercel.com/dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your NCryp repository from GitHub

2. **Configure Environment Variables**:
   In your Vercel project settings, add these environment variables:

   ```bash
   # Required
   SECRET_KEY=your-secret-key-here
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD_HASH=your-generated-password-hash
   STORAGE_TYPE=s3
   VERCEL=1
   
   # AWS S3 (if using S3)
   AWS_ACCESS_KEY_ID=your-aws-access-key
   AWS_SECRET_ACCESS_KEY=your-aws-secret-key
   AWS_REGION=us-east-1
   S3_BUCKET_NAME=your-bucket-name
   
   # CORS (update with your frontend domain)
   CORS_ORIGINS=https://your-frontend-domain.netlify.app
   
   # Optional
   MAX_FILE_SIZE=104857600
   ADMIN_SESSION_TIMEOUT=3600
   ```

3. **Deploy**:
   - Vercel will automatically detect the `vercel.json` configuration
   - Click "Deploy" to start the deployment
   - Your backend will be available at `https://your-project-name.vercel.app`

## Step 3: Generate Admin Password

Run this locally to generate an admin password hash:

```bash
python generate_admin_password.py
```

Add the generated hash to your Vercel environment variables as `ADMIN_PASSWORD_HASH`.

## Step 4: Update Frontend Configuration

Update your frontend's environment variables to point to the new Vercel backend:

### In Netlify:
1. Go to your Netlify site settings
2. Update the `VITE_API_URL` environment variable:
   ```
   VITE_API_URL=https://your-project-name.vercel.app
   ```
3. Redeploy your frontend

### In Local Development:
Update your frontend's `.env` file:
```
VITE_API_URL=https://your-project-name.vercel.app
```

## Step 5: Test the Deployment

1. **Test Backend Directly**:
   ```bash
   curl https://your-project-name.vercel.app/api/health
   ```

2. **Test Frontend**:
   - Visit your frontend URL
   - Try uploading a file
   - Test file sharing and downloading
   - Test admin dashboard login

## Important Notes

### Storage Considerations
- **Vercel Limitation**: Local file storage is not persistent in serverless functions
- **Solution**: The configuration automatically defaults to S3 when `VERCEL=1` is set
- **File Size**: Vercel has a 50MB limit for serverless function responses, so large file downloads might need optimization

### Performance
- **Cold Starts**: First request after inactivity may be slower
- **Timeout**: Vercel functions have a 60-second timeout (configured in `vercel.json`)
- **Memory**: Vercel provides 1GB memory by default for serverless functions

### Environment Variables
- Set all environment variables in the Vercel dashboard
- Never commit sensitive values to your repository
- Use the `.env.vercel` template as a reference

## Troubleshooting

### Common Issues

1. **"Module not found" errors**:
   - Ensure all dependencies are in `requirements.txt`
   - Check that the Python version is compatible

2. **Storage errors**:
   - Verify your cloud storage credentials
   - Ensure the bucket/container exists and is accessible

3. **CORS errors**:
   - Update `CORS_ORIGINS` with your exact frontend domain
   - Include both `http://localhost:5173` (for development) and your production domain

4. **Admin login issues**:
   - Verify `ADMIN_PASSWORD_HASH` is correctly set
   - Check that `SECRET_KEY` is set and consistent

### Logs and Debugging

- View logs in the Vercel dashboard under "Functions" tab
- Enable debug logging by setting `LOG_LEVEL=DEBUG`
- Check the "Runtime Logs" for detailed error information

## Migration from Railway

If you're migrating from Railway:

1. **Export Environment Variables**: Copy all environment variables from Railway to Vercel
2. **Update Storage**: Switch from local storage to cloud storage
3. **Update Frontend**: Change the API URL from Railway to Vercel
4. **Test Thoroughly**: Ensure all functionality works with the new deployment

## Security Recommendations

1. **Use HTTPS**: Vercel provides HTTPS by default
2. **Secure Environment Variables**: Never expose sensitive keys in your code
3. **CORS Configuration**: Restrict CORS origins to your specific domains
4. **Regular Updates**: Keep dependencies updated for security patches

## Support

- **Vercel Documentation**: [vercel.com/docs](https://vercel.com/docs)
- **NCryp Issues**: Report issues on the GitHub repository
- **Storage Setup**: See `STORAGE_SETUP.md` for detailed cloud storage configuration
