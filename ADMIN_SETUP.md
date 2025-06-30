# Admin Dashboard Setup Guide

This guide will help you set up and use the NCryp admin dashboard for monitoring visitor statistics and managing files.

## Quick Setup

### 1. Generate Admin Password

Run the password generator script:

```bash
python generate_admin_password.py
```

This will output:
- A secure random password
- The password hash to add to your configuration
- Instructions for updating your env.local file

### 2. Update Configuration

Add the generated password hash to your `env.local` file:

```bash
# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your-generated-hash-here
ADMIN_SESSION_TIMEOUT=3600
```

### 3. Access Admin Dashboard

1. Start the NCryp application
2. Navigate to the "Admin" tab
3. Login with:
   - Username: `admin`
   - Password: The password generated in step 1

## Admin Dashboard Features

### Overview Tab
- **Total Visits**: Number of times the application has been accessed
- **Unique Visitors**: Number of unique IP addresses that visited
- **Total Uploads**: Number of files uploaded
- **Total Downloads**: Number of files downloaded
- **Storage Information**: Total files and storage usage

### Files Tab
- View all uploaded files with metadata
- See file names, sizes, share IDs, and upload dates
- Monitor encryption status
- Refresh to get latest data

### Analytics Tab
- **Daily Visits**: Bar chart showing visits over the last 7 days
- **Page Views**: Breakdown of which pages are most visited
- Usage patterns and trends

## Security Features

### Authentication
- Secure password hashing using HMAC-SHA256
- Salted password storage
- Session-based authentication with timeout

### Access Control
- Admin-only endpoints protected by authentication decorator
- Session timeout (configurable, default 1 hour)
- Secure logout functionality

## Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_USERNAME` | Admin login username | `admin` |
| `ADMIN_PASSWORD_HASH` | Hashed admin password | Required |
| `ADMIN_SESSION_TIMEOUT` | Session timeout in seconds | `3600` |

### Changing Admin Password

1. Generate a new password hash:
   ```bash
   python generate_admin_password.py your-new-password
   ```

2. Update the `ADMIN_PASSWORD_HASH` in your `env.local` file

3. Restart the application

## API Endpoints

### Authentication
- `POST /api/admin/login` - Admin login
- `POST /api/admin/logout` - Admin logout

### Data Access
- `GET /api/admin/stats` - Get visitor and usage statistics
- `GET /api/admin/files` - Get all files with metadata

### Example Usage

```bash
# Login
curl -X POST http://localhost:5000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  -c cookies.txt

# Get statistics
curl -X GET http://localhost:5000/api/admin/stats \
  -b cookies.txt

# Get files
curl -X GET http://localhost:5000/api/admin/files \
  -b cookies.txt

# Logout
curl -X POST http://localhost:5000/api/admin/logout \
  -b cookies.txt
```

## Visitor Tracking

The admin dashboard tracks:

### Visit Statistics
- Total page visits
- Unique visitors (by IP address)
- Daily visit trends
- Page view breakdown

### File Statistics
- Upload counts and sizes
- Download counts
- File type distribution
- Storage usage

### Data Storage
- Currently uses in-memory storage (resets on server restart)
- For production, consider using Redis or a database
- Data is automatically collected on all API requests

## Troubleshooting

### Login Issues
- Ensure the password hash is correctly copied from the generator
- Check that the `ADMIN_USERNAME` matches what you're entering
- Verify the application is running and accessible

### No Data Showing
- Visitor tracking starts when the application is first accessed
- Upload some files to see upload statistics
- Check that the backend is running and accessible

### Session Timeout
- Sessions expire after the configured timeout (default 1 hour)
- Simply log in again to continue
- Adjust `ADMIN_SESSION_TIMEOUT` if needed

## Production Considerations

### Data Persistence
- Current implementation uses in-memory storage
- For production, implement database storage for statistics
- Consider using Redis for session management

### Security
- Change default admin username
- Use strong passwords
- Consider implementing rate limiting
- Enable HTTPS in production

### Monitoring
- Set up logging for admin access
- Monitor for suspicious activity
- Regular password rotation
- Backup configuration files

## Default Credentials

After running the password generator, your default credentials will be:

- **Username**: `admin`
- **Password**: The generated secure password (save this securely!)

⚠️ **Important**: Change these credentials before deploying to production! 