import React, { useState } from 'react';
import { toast } from 'react-toastify';
import './UserProfile.css';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function UserProfile({ user, onLogout, onClose }) {
  const [loading, setLoading] = useState(false);

  const handleLogout = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include'
      });

      if (response.ok) {
        toast.success('Logged out successfully');
        onLogout();
      } else {
        throw new Error('Logout failed');
      }
    } catch (error) {
      toast.error('Logout failed');
    } finally {
      setLoading(false);
    }
  };

  const getSubscriptionTierName = (tier) => {
    const tierNames = {
      'free': 'Free',
      'basic': 'Basic',
      'pro': 'Pro',
      'enterprise': 'Enterprise'
    };
    return tierNames[tier] || tier;
  };

  const getSubscriptionColor = (tier) => {
    const colors = {
      'free': '#6b7280',
      'basic': '#3b82f6',
      'pro': '#8b5cf6',
      'enterprise': '#f59e0b'
    };
    return colors[tier] || '#6b7280';
  };

  const getUploadLimit = (tier) => {
    const limits = {
      'free': 2,
      'basic': 10,
      'pro': 100,
      'enterprise': 1000
    };
    return limits[tier] || 2;
  };

  const progressPercentage = user ? (user.files_uploaded_count / user.upload_limit) * 100 : 0;

  return (
    <div className="user-profile-overlay">
      <div className="user-profile-modal">
        <div className="profile-header">
          <h2>Account</h2>
          <button className="close-btn" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        {user && !user.is_anonymous ? (
          <>
            <div className="user-info">
              <div className="avatar">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
              </div>
              <div className="user-details">
                <h3>{user.username}</h3>
                <p>{user.email}</p>
              </div>
            </div>

            <div className="subscription-info">
              <div className="subscription-header">
                <h4>Subscription</h4>
                <span 
                  className="tier-badge"
                  style={{ backgroundColor: getSubscriptionColor(user.subscription_tier) }}
                >
                  {getSubscriptionTierName(user.subscription_tier)}
                </span>
              </div>

              <div className="upload-stats">
                <div className="stat-item">
                  <span className="stat-label">Files Uploaded</span>
                  <span className="stat-value">{user.files_uploaded_count} / {user.upload_limit}</span>
                </div>
                
                <div className="progress-bar">
                  <div 
                    className="progress-fill"
                    style={{ 
                      width: `${Math.min(progressPercentage, 100)}%`,
                      backgroundColor: getSubscriptionColor(user.subscription_tier)
                    }}
                  ></div>
                </div>

                {!user.can_upload_more && (
                  <div className="limit-warning">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"></circle>
                      <path d="M12 16v-4"></path>
                      <path d="M12 8h.01"></path>
                    </svg>
                    <span>Upload limit reached. Upgrade your plan for more uploads.</span>
                  </div>
                )}
              </div>
            </div>

            <div className="subscription-plans">
              <h4>Available Plans</h4>
              <div className="plans-grid">
                <div className="plan-card">
                  <h5>Free</h5>
                  <p className="plan-price">$0/month</p>
                  <ul>
                    <li>2 file uploads</li>
                    <li>Basic encryption</li>
                    <li>File sharing</li>
                  </ul>
                </div>
                <div className="plan-card featured">
                  <h5>Basic</h5>
                  <p className="plan-price">$5/month</p>
                  <ul>
                    <li>10 file uploads</li>
                    <li>Advanced encryption</li>
                    <li>Priority support</li>
                  </ul>
                </div>
                <div className="plan-card">
                  <h5>Pro</h5>
                  <p className="plan-price">$15/month</p>
                  <ul>
                    <li>100 file uploads</li>
                    <li>Enterprise encryption</li>
                    <li>24/7 support</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="profile-actions">
              <button
                className="logout-btn"
                onClick={handleLogout}
                disabled={loading}
              >
                {loading ? (
                  <div className="loading-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                ) : (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                      <polyline points="16,17 21,12 16,7"></polyline>
                      <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                    Logout
                  </>
                )}
              </button>
            </div>
          </>
        ) : (
          <div className="anonymous-user">
            <div className="avatar">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                <circle cx="12" cy="7" r="4"></circle>
              </svg>
            </div>
            <h3>Anonymous User</h3>
            <p>You're using NCryp as a guest. Create an account to save your files and get more uploads.</p>
            
            <div className="upload-stats">
              <div className="stat-item">
                <span className="stat-label">Files Uploaded</span>
                <span className="stat-value">{user?.files_uploaded_count || 0} / 2</span>
              </div>
              
              <div className="progress-bar">
                <div 
                  className="progress-fill"
                  style={{ 
                    width: `${Math.min(((user?.files_uploaded_count || 0) / 2) * 100, 100)}%`,
                    backgroundColor: getSubscriptionColor('free')
                  }}
                ></div>
              </div>
            </div>

            <div className="anonymous-actions">
              <p>Guest users can upload 2 files per session</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
} 