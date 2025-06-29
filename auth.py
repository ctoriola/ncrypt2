from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from models import db, User, SubscriptionTier, AnonymousUser
from datetime import datetime, timedelta
import secrets
import logging

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validate input
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409
        
        # Create new user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            subscription_tier=SubscriptionTier.FREE
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log in the user
        login_user(user)
        
        logging.info(f"New user registered: {username}")
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'subscription_tier': user.subscription_tier.value,
                'upload_limit': user.upload_limit,
                'files_uploaded_count': user.files_uploaded_count
            }
        }), 201
        
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Log in the user
        login_user(user)
        
        logging.info(f"User logged in: {user.username}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'subscription_tier': user.subscription_tier.value,
                'upload_limit': user.upload_limit,
                'files_uploaded_count': user.files_uploaded_count
            }
        }), 200
        
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    """Logout user"""
    try:
        logout_user()
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200
    except Exception as e:
        logging.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """Get current user info"""
    try:
        if current_user.is_authenticated:
            return jsonify({
                'success': True,
                'user': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'email': current_user.email,
                    'subscription_tier': current_user.subscription_tier.value,
                    'upload_limit': current_user.upload_limit,
                    'files_uploaded_count': current_user.files_uploaded_count,
                    'can_upload_more': current_user.can_upload_more
                }
            }), 200
        else:
            # Return anonymous user info
            session_id = session.get('session_id')
            if not session_id:
                session_id = secrets.token_urlsafe(32)
                session['session_id'] = session_id
            
            anon_user = AnonymousUser(session_id)
            return jsonify({
                'success': True,
                'user': {
                    'id': None,
                    'username': None,
                    'email': None,
                    'subscription_tier': 'free',
                    'upload_limit': anon_user.upload_limit,
                    'files_uploaded_count': anon_user.files_uploaded_count,
                    'can_upload_more': anon_user.can_upload_more,
                    'is_anonymous': True
                }
            }), 200
            
    except Exception as e:
        logging.error(f"Get user info error: {str(e)}")
        return jsonify({'error': 'Failed to get user info'}), 500

@auth_bp.route('/api/auth/subscription', methods=['GET'])
@login_required
def get_subscription_info():
    """Get subscription information"""
    try:
        return jsonify({
            'success': True,
            'subscription': {
                'tier': current_user.subscription_tier.value,
                'upload_limit': current_user.upload_limit,
                'files_uploaded_count': current_user.files_uploaded_count,
                'can_upload_more': current_user.can_upload_more,
                'expires_at': current_user.subscription_expires.isoformat() if current_user.subscription_expires else None
            }
        }), 200
    except Exception as e:
        logging.error(f"Get subscription info error: {str(e)}")
        return jsonify({'error': 'Failed to get subscription info'}), 500

def get_current_user_or_anonymous():
    """Helper function to get current user or anonymous user"""
    if current_user.is_authenticated:
        return current_user
    else:
        session_id = session.get('session_id')
        if not session_id:
            session_id = secrets.token_urlsafe(32)
            session['session_id'] = session_id
        return AnonymousUser(session_id) 