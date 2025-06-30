import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './AdminDashboard.css';

const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export const AdminDashboard = ({ onLogout }) => {
  const [stats, setStats] = useState(null);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const { currentUser, logout } = useAuth();

  useEffect(() => {
    if (currentUser) {
      console.log('Current user found:', currentUser.email);
      console.log('Firebase config check:', {
        apiKey: import.meta.env.VITE_FIREBASE_API_KEY ? 'Set' : 'Not set',
        authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN ? 'Set' : 'Not set',
        projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID ? 'Set' : 'Not set',
        storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET ? 'Set' : 'Not set',
        messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID ? 'Set' : 'Not set',
        appId: import.meta.env.VITE_FIREBASE_APP_ID ? 'Set' : 'Not set'
      });
      loadDashboardData();
    } else {
      console.log('No current user found');
      setLoading(false);
    }
  }, [currentUser]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Get Firebase ID token for authentication
      let idToken;
      try {
        idToken = await currentUser.getIdToken(true); // Force refresh the token
        console.log('Firebase token obtained successfully');
      } catch (tokenError) {
        console.error('Failed to get Firebase token:', tokenError);
        setError('Authentication failed. Please log in again.');
        toast.error('Authentication failed. Please log in again.');
        await logout();
        return;
      }
      
      console.log('Loading dashboard data with Firebase token...');
      
      // Load stats and files in parallel
      const [statsResponse, filesResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/api/admin/stats`, {
          headers: {
            'Authorization': `Bearer ${idToken}`,
            'Content-Type': 'application/json'
          }
        }),
        fetch(`${API_BASE_URL}/api/admin/files`, {
          headers: {
            'Authorization': `Bearer ${idToken}`,
            'Content-Type': 'application/json'
          }
        })
      ]);

      console.log('Stats response status:', statsResponse.status);
      console.log('Files response status:', filesResponse.status);

      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        setStats(statsData);
      } else {
        const errorData = await statsResponse.text();
        console.error('Stats error response:', errorData);
        
        if (statsResponse.status === 401) {
          setError('Authentication failed. Please log in again.');
          toast.error('Authentication failed. Please log in again.');
          await logout();
          return;
        } else {
          setError('Failed to load statistics');
          toast.error('Failed to load statistics');
        }
      }

      if (filesResponse.ok) {
        const filesData = await filesResponse.json();
        setFiles(filesData.files || []);
      } else {
        const errorData = await filesResponse.text();
        console.error('Files error response:', errorData);
        
        if (filesResponse.status === 401) {
          setError('Authentication failed. Please log in again.');
          toast.error('Authentication failed. Please log in again.');
          await logout();
          return;
        } else {
          setError('Failed to load files');
          toast.error('Failed to load files');
        }
      }
    } catch (error) {
      console.error('Dashboard data error:', error);
      setError('Failed to load dashboard data');
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const handleRetry = () => {
    loadDashboardData();
  };

  const handleLogout = async () => {
    try {
      await logout();
      toast.success('Logged out successfully');
      onLogout();
    } catch (error) {
      console.error('Logout error:', error);
      toast.error('Logout failed');
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="admin-dashboard">
        <div className="loading-container">
          <svg className="spinner" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 12a9 9 0 11-6.219-8.56"></path>
          </svg>
          <p>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="admin-dashboard">
        <div className="error-container">
          <div className="error-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="15" y1="9" x2="9" y2="15"></line>
              <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
          </div>
          <h2>Dashboard Error</h2>
          <p>{error}</p>
          <div className="error-actions">
            <button onClick={handleRetry} className="retry-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M1 4v6h6"></path>
                <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
              </svg>
              Retry
            </button>
            <button onClick={handleLogout} className="logout-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                <polyline points="16,17 21,12 16,7"></polyline>
                <line x1="21" y1="12" x2="9" y2="12"></line>
              </svg>
              Logout
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-dashboard">
      <div className="admin-header">
        <div className="admin-header-left">
          <h1>Admin Dashboard</h1>
          <p>Monitor your NCryp application</p>
          {currentUser && (
            <p className="admin-user-info">
              Logged in as: {currentUser.email}
            </p>
          )}
        </div>
        <div className="admin-header-actions">
          <Link to="/" className="back-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5"></path>
              <path d="M12 19l-7-7 7-7"></path>
            </svg>
            Back to Main
          </Link>
          <button onClick={handleLogout} className="logout-btn">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
              <polyline points="16,17 21,12 16,7"></polyline>
              <line x1="21" y1="12" x2="9" y2="12"></line>
            </svg>
            Logout
          </button>
        </div>
      </div>

      <div className="admin-nav">
        <button
          className={`admin-nav-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="7" height="7"></rect>
            <rect x="14" y="3" width="7" height="7"></rect>
            <rect x="14" y="14" width="7" height="7"></rect>
            <rect x="3" y="14" width="7" height="7"></rect>
          </svg>
          Overview
        </button>
        <button
          className={`admin-nav-btn ${activeTab === 'files' ? 'active' : ''}`}
          onClick={() => setActiveTab('files')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14,2 14,8 20,8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10,9 9,9 8,9"></polyline>
          </svg>
          Files
        </button>
        <button
          className={`admin-nav-btn ${activeTab === 'analytics' ? 'active' : ''}`}
          onClick={() => setActiveTab('analytics')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="20" x2="18" y2="10"></line>
            <line x1="12" y1="20" x2="12" y2="4"></line>
            <line x1="6" y1="20" x2="6" y2="14"></line>
          </svg>
          Analytics
        </button>
      </div>

      <div className="admin-content">
        {activeTab === 'overview' && (
          <div className="overview-tab">
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                    <circle cx="9" cy="7" r="4"></circle>
                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                  </svg>
                </div>
                <div className="stat-content">
                  <h3>{stats?.total_visits || 0}</h3>
                  <p>Total Visits</p>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                  </svg>
                </div>
                <div className="stat-content">
                  <h3>{stats?.unique_visitors || 0}</h3>
                  <p>Unique Visitors</p>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7,10 12,15 17,10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                </div>
                <div className="stat-content">
                  <h3>{stats?.upload_stats?.total_uploads || 0}</h3>
                  <p>Total Uploads</p>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="17,8 12,3 7,8"></polyline>
                    <line x1="12" y1="3" x2="12" y2="15"></line>
                  </svg>
                </div>
                <div className="stat-content">
                  <h3>{stats?.download_stats?.total_downloads || 0}</h3>
                  <p>Total Downloads</p>
                </div>
              </div>
            </div>

            <div className="storage-info">
              <h3>Storage Information</h3>
              <div className="storage-details">
                <div className="storage-item">
                  <span>Total Files:</span>
                  <span>{files.length}</span>
                </div>
                <div className="storage-item">
                  <span>Total Size:</span>
                  <span>{formatBytes(stats?.upload_stats?.total_size || 0)}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'files' && (
          <div className="files-tab">
            <div className="files-header">
              <h3>All Files ({files.length})</h3>
              <button onClick={loadDashboardData} className="refresh-btn">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M23 4v6h-6"></path>
                  <path d="M1 20v-6h6"></path>
                  <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path>
                </svg>
                Refresh
              </button>
            </div>

            <div className="files-table">
              <table>
                <thead>
                  <tr>
                    <th>File Name</th>
                    <th>Share ID</th>
                    <th>Size</th>
                    <th>Type</th>
                    <th>Upload Date</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {files.map((file) => (
                    <tr key={file.id}>
                      <td>{file.filename}</td>
                      <td>
                        <code className="share-id">{file.share_id || 'N/A'}</code>
                      </td>
                      <td>{formatBytes(file.size)}</td>
                      <td>{file.mime_type}</td>
                      <td>{formatDate(file.upload_date)}</td>
                      <td>
                        <span className={`status ${file.encrypted ? 'encrypted' : 'plain'}`}>
                          {file.encrypted ? 'Encrypted' : 'Plain'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {files.length === 0 && (
                <div className="no-files">
                  <p>No files uploaded yet</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="analytics-tab">
            <div className="analytics-section">
              <h3>Daily Visits (Last 7 Days)</h3>
              <div className="daily-visits">
                {Object.entries(stats?.daily_visits || {})
                  .sort(([a], [b]) => new Date(b) - new Date(a))
                  .slice(0, 7)
                  .map(([date, count]) => (
                    <div key={date} className="visit-bar">
                      <div className="bar" style={{ height: `${Math.max(count * 10, 20)}px` }}></div>
                      <span className="date">{new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
                      <span className="count">{count}</span>
                    </div>
                  ))}
              </div>
            </div>

            <div className="analytics-section">
              <h3>Page Views</h3>
              <div className="page-views">
                {Object.entries(stats?.page_views || {}).map(([page, count]) => (
                  <div key={page} className="page-view-item">
                    <span className="page">{page}</span>
                    <span className="count">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}; 