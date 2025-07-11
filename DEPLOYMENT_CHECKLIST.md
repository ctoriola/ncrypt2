# Railway Deployment Checklist (Postgres)

## ✅ Pre-Deployment Setup

- [ ] **Railway Account**: Sign up at [railway.app](https://railway.app)
- [ ] **GitHub Repository**: Ensure your NCryp project is on GitHub
- [ ] **Generated Values**: Run `python railway_setup.py` to generate secrets

## 🚀 Railway Deployment Steps

### 1. Connect Repository
- [ ] Go to Railway Dashboard
- [ ] Click "New Project"
- [ ] Select "Deploy from GitHub repo"
- [ ] Choose your NCryp repository
- [ ] Select main/master branch

### 2. Add Postgres Database
- [ ] In Railway project dashboard, click "New"
- [ ] Select "Database" → "PostgreSQL"
- [ ] Copy the `DATABASE_URL` from the database service

### 3. Configure Environment Variables
- [ ] Go to project "Variables" tab
- [ ] Add all variables from `railway.env.template`
- [ ] Set `DATABASE_URL` to your Railway Postgres URL
- [ ] **Important**: Change the admin password after first login

### 4. Deploy
- [ ] Railway will automatically build and deploy
- [ ] Check deployment logs for any errors
- [ ] Verify the deployment URL

### 5. Create Admin User
- [ ] Run `python create_admin.py` locally with your DATABASE_URL
- [ ] Or use Railway CLI: `railway run python create_admin.py`
- [ ] Follow prompts to create admin user
- [ ] Note the username and password

## 🧪 Post-Deployment Testing

### Health Check
- [ ] Visit `https://your-app-name.railway.app/api/health`
- [ ] Should return `{"status": "healthy"}`

### Admin Dashboard
- [ ] Visit your frontend application
- [ ] Try logging into admin panel with created credentials
- [ ] Verify admin dashboard loads

### File Operations
- [ ] Test file upload functionality
- [ ] Test file download functionality
- [ ] Test file search by share ID

## 🔧 Frontend Configuration

### Update Frontend Environment
- [ ] Set `VITE_API_URL=https://your-app-name.railway.app`
- [ ] Deploy frontend to Netlify/Vercel
- [ ] Test frontend-backend communication

## 📊 Monitoring

### Railway Dashboard
- [ ] Check deployment status
- [ ] Monitor resource usage
- [ ] View application logs
- [ ] Monitor Postgres database usage

### Application Health
- [ ] Set up health check monitoring
- [ ] Monitor error rates
- [ ] Check response times

## 🔒 Security Checklist

- [ ] **Secrets**: All sensitive data in environment variables
- [ ] **HTTPS**: Railway provides SSL certificates
- [ ] **CORS**: Properly configured for your frontend domain
- [ ] **Admin Password**: Changed from default after first login
- [ ] **Database**: Postgres properly configured and secured

## 🚨 Troubleshooting

### Common Issues

**Build Failures**
- Check `requirements.txt` has all dependencies
- Verify Python version in `runtime.txt`
- Check Railway build logs

**Database Connection Issues**
- Verify `DATABASE_URL` is correctly set
- Check that Postgres service is running
- Ensure tables are created (they should auto-create)

**Environment Variables**
- Verify all required variables are set in Railway dashboard
- Check that `DATABASE_URL` points to your Railway Postgres

**CORS Issues**
- Verify `CORS_ORIGINS` includes frontend domain
- Check that frontend is making requests to the correct backend URL

**Admin Login Issues**
- Ensure admin user was created successfully
- Check that `DATABASE_URL` is accessible from your local machine
- Verify the admin user exists in the database

**Storage Issues**
- For local storage: Files lost on restart (use cloud storage for production)
- For cloud storage: Verify credentials and bucket permissions

### Getting Help

- **Railway Docs**: [docs.railway.app](https://docs.railway.app)
- **Railway Discord**: [discord.gg/railway](https://discord.gg/railway)
- **GitHub Issues**: Create issue in your repository

## 📈 Production Recommendations

- [ ] **Use Cloud Storage**: Avoid ephemeral local storage
- [ ] **Set Up Monitoring**: Use Railway's built-in monitoring
- [ ] **Enable Auto-Deploy**: Connect GitHub for automatic deployments
- [ ] **Set Up Custom Domain**: Configure custom domain in Railway settings
- [ ] **Database Backups**: Railway provides automatic Postgres backups
- [ ] **SSL Certificate**: Railway provides automatic SSL

## 🎯 Success Criteria

Your deployment is successful when:
- ✅ Health check endpoint responds
- ✅ Admin dashboard is accessible with created credentials
- ✅ File upload/download works
- ✅ Frontend can communicate with backend
- ✅ No errors in Railway logs
- ✅ Application responds within reasonable time
- ✅ Postgres database is connected and tables are created 