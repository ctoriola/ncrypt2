from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import enum

db = SQLAlchemy()

class SubscriptionTier(enum.Enum):
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Subscription info
    subscription_tier = db.Column(db.Enum(SubscriptionTier), default=SubscriptionTier.FREE)
    subscription_expires = db.Column(db.DateTime, nullable=True)
    
    # File tracking
    files_uploaded = db.relationship('FileRecord', backref='user', lazy=True)
    
    def get_id(self):
        return str(self.id)
    
    @property
    def can_upload(self):
        """Check if user can upload based on subscription and limits"""
        if not self.is_active:
            return False
        
        # Check subscription expiration
        if self.subscription_expires and datetime.utcnow() > self.subscription_expires:
            self.subscription_tier = SubscriptionTier.FREE
            self.subscription_expires = None
            db.session.commit()
        
        return True
    
    @property
    def upload_limit(self):
        """Get upload limit based on subscription tier"""
        limits = {
            SubscriptionTier.FREE: 2,
            SubscriptionTier.BASIC: 10,
            SubscriptionTier.PRO: 100,
            SubscriptionTier.ENTERPRISE: 1000
        }
        return limits.get(self.subscription_tier, 2)
    
    @property
    def files_uploaded_count(self):
        """Get count of files uploaded by user"""
        return len(self.files_uploaded)
    
    @property
    def can_upload_more(self):
        """Check if user can upload more files"""
        return self.files_uploaded_count < self.upload_limit

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID
    share_id = db.Column(db.String(8), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted = db.Column(db.Boolean, default=True)
    mime_type = db.Column(db.String(100))
    
    # User relationship
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for anonymous users
    
    # Session tracking for anonymous users
    session_id = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<FileRecord {self.filename}>'

class AnonymousUser:
    """Anonymous user class for non-logged in users"""
    
    def __init__(self, session_id):
        self.session_id = session_id
        self.subscription_tier = SubscriptionTier.FREE
        self.id = None  # Anonymous users don't have a database ID
    
    def get_id(self):
        return f"anon_{self.session_id}"
    
    @property
    def can_upload(self):
        return True
    
    @property
    def upload_limit(self):
        return 2  # Free tier limit for anonymous users
    
    @property
    def files_uploaded_count(self):
        # Count files uploaded in this session
        return FileRecord.query.filter_by(session_id=self.session_id).count()
    
    @property
    def can_upload_more(self):
        return self.files_uploaded_count < self.upload_limit 