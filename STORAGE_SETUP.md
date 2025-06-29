# Storage Backend Setup Guide

NCryp supports multiple storage backends. Choose the one that best fits your needs:

## 🏠 Local Storage (Recommended for Development)

**No cloud account required!** Files are stored locally on your machine.

### Setup:
1. Set in `env.local`:
   ```env
   STORAGE_TYPE=local
   LOCAL_STORAGE_PATH=./uploads
   ```

2. That's it! Files will be stored in the `./uploads` directory.

### Pros:
- ✅ No cloud account needed
- ✅ No internet required
- ✅ No costs
- ✅ Simple setup
- ✅ Full control over data

### Cons:
- ❌ Not scalable for production
- ❌ No backup/redundancy
- ❌ Limited by local storage space

---

## ☁️ AWS S3 (Production Recommended)

### Setup:
1. Create an AWS account
2. Create an S3 bucket
3. Create an IAM user with S3 permissions
4. Set in `env.local`:
   ```env
   STORAGE_TYPE=s3
   AWS_ACCESS_KEY_ID=your_access_key
   AWS_SECRET_ACCESS_KEY=your_secret_key
   AWS_REGION=us-east-1
   S3_BUCKET_NAME=your-bucket-name
   ```

### S3 Bucket CORS Configuration:
```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["GET", "POST", "PUT", "DELETE"],
        "AllowedOrigins": ["http://localhost:3000", "https://yourdomain.com"],
        "ExposeHeaders": []
    }
]
```

### IAM Permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

---

## 🌐 Google Cloud Storage

### Setup:
1. Create a Google Cloud account
2. Create a storage bucket
3. Set up authentication (service account or gcloud auth)
4. Set in `env.local`:
   ```env
   STORAGE_TYPE=gcs
   GCS_BUCKET_NAME=your-bucket-name
   ```

### Authentication Options:

**Option 1: Service Account (Recommended)**
1. Create a service account in Google Cloud Console
2. Download the JSON key file
3. Set environment variable:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
   ```

**Option 2: gcloud CLI**
```bash
gcloud auth application-default login
```

---

## 🔵 Azure Blob Storage

### Setup:
1. Create an Azure account
2. Create a storage account and container
3. Get the connection string
4. Set in `env.local`:
   ```env
   STORAGE_TYPE=azure
   AZURE_CONNECTION_STRING=your_connection_string
   AZURE_CONTAINER_NAME=your-container-name
   ```

### Get Connection String:
1. Go to Azure Portal → Storage Account → Access Keys
2. Copy the connection string

---

## 🆚 Storage Comparison

| Feature | Local | AWS S3 | Google Cloud | Azure |
|---------|-------|--------|--------------|-------|
| Setup Difficulty | ⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Cost | Free | Pay per use | Pay per use | Pay per use |
| Scalability | ❌ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Reliability | ⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Global CDN | ❌ | ✅ | ✅ | ✅ |
| Backup | Manual | ✅ | ✅ | ✅ |

---

## 🚀 Quick Start (No Cloud Account)

For immediate testing without any cloud setup:

1. **Copy environment template:**
   ```bash
   copy env.example env.local
   ```

2. **Edit `env.local` (already configured for local storage):**
   ```env
   STORAGE_TYPE=local
   LOCAL_STORAGE_PATH=./uploads
   ```

3. **Start the application:**
   ```bash
   start.bat  # Windows
   # or
   ./start.sh  # Linux/Mac
   ```

4. **Upload files** - they'll be stored in `./uploads/` directory

---

## 🔄 Switching Storage Backends

You can easily switch between storage backends by changing the `STORAGE_TYPE` in your `env.local` file:

```env
# For local storage
STORAGE_TYPE=local

# For AWS S3
STORAGE_TYPE=s3

# For Google Cloud Storage
STORAGE_TYPE=gcs

# For Azure Blob Storage
STORAGE_TYPE=azure
```

**Note:** When switching storage backends, existing files won't be automatically migrated. You'll need to manually transfer files if needed.

---

## 💰 Cost Estimates

### AWS S3 (us-east-1):
- Storage: $0.023 per GB/month
- Requests: $0.0004 per 1,000 GET requests
- Uploads: $0.0005 per 1,000 PUT requests

### Google Cloud Storage:
- Storage: $0.020 per GB/month
- Requests: $0.004 per 10,000 GET requests
- Uploads: $0.050 per 10,000 PUT requests

### Azure Blob Storage:
- Storage: $0.0184 per GB/month
- Requests: $0.004 per 10,000 transactions

**For personal use with <100GB storage, costs are typically <$5/month.**

---

## 🔒 Security Notes

- **Local storage**: Files are stored unencrypted on your local machine
- **Cloud storage**: Files are encrypted in transit and at rest
- **Client-side encryption**: All files are encrypted before upload regardless of storage backend
- **Access control**: Configure appropriate permissions for your cloud storage

---

## 🆘 Troubleshooting

### Local Storage Issues:
- Ensure the uploads directory has write permissions
- Check available disk space

### AWS S3 Issues:
- Verify IAM permissions
- Check bucket CORS configuration
- Ensure bucket exists and is accessible

### Google Cloud Issues:
- Verify service account permissions
- Check authentication setup
- Ensure bucket exists

### Azure Issues:
- Verify connection string format
- Check container permissions
- Ensure storage account is accessible 