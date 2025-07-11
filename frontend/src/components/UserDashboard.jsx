import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';
import { SecureUploader } from './SecureUploader';
import { FileList } from './FileList';
import { FileSearch } from './FileSearch';
import { FileDecryptor } from './FileDecryptor';
import './UserDashboard.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

// Simple token creation for client-side auth
const createSimpleToken = (user) => {
  const payload = {
    user_id: user.uid,
    email: user.email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiry
  };
  
  // Simple base64 encoding (in production, use proper JWT)
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadEncoded = btoa(JSON.stringify(payload));
  const signature = btoa('simple-signature'); // In production, use proper signature
  
  return `${header}.${payloadEncoded}.${signature}`;
};

export const UserDashboard = ({ onLogout }) => {
  const { currentUser, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('upload');
  const [userFiles, setUserFiles] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (currentUser) {
      loadUserFiles();
    }
  }, [currentUser]);

  const loadUserFiles = async () => {
    try {
      setLoading(true);
      
      // Create simple token for authentication
      const simpleToken = createSimpleToken(currentUser);
      
      const response = await fetch(`${API_BASE_URL}/api/user/files`, {
        headers: {
          'Authorization': `Bearer ${simpleToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUserFiles(data.files || []);
      } else {
        console.error('Failed to load user files');
        toast.error('Failed to load your files');
      }
    } catch (error) {
      console.error('Error loading user files:', error);
      toast.error('Failed to load your files');
    } finally {
      setLoading(false);
    }
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

  const handleFileUploadSuccess = () => {
    loadUserFiles(); // Refresh the file list
  };

  const handleFileDelete = async (fileId) => {
    try {
      // Create simple token for authentication
      const simpleToken = createSimpleToken(currentUser);
      
      const response = await fetch(`${API_BASE_URL}/api/user/files/${fileId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${simpleToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        toast.success('File deleted successfully');
        loadUserFiles(); // Refresh the file list
      } else {
        toast.error('Failed to delete file');
      }
    } catch (error) {
      console.error('Error deleting file:', error);
      toast.error('Failed to delete file');
    }
  };

  return (
    <div className="user-dashboard">
      <div className="user-dashboard-header">
        <div className="user-info">
          <div className="user-avatar">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
              <circle cx="12" cy="7" r="4"></circle>
            </svg>
          </div>
          <div className="user-details">
            <h3>Welcome, {currentUser?.email}</h3>
            <p>Manage your secure files</p>
          </div>
        </div>
        <button onClick={handleLogout} className="logout-btn">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16,17 21,12 16,7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          Logout
        </button>
      </div>

      <div className="user-dashboard-tabs">
        <button 
          className={`tab-btn ${activeTab === 'upload' ? 'active' : ''}`}
          onClick={() => setActiveTab('upload')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7,10 12,15 17,10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
          Upload & Share
        </button>
        <button 
          className={`tab-btn ${activeTab === 'my-files' ? 'active' : ''}`}
          onClick={() => setActiveTab('my-files')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14,2 14,8 20,8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10,9 9,9 8,9"></polyline>
          </svg>
          My Files
        </button>
        <button 
          className={`tab-btn ${activeTab === 'download' ? 'active' : ''}`}
          onClick={() => setActiveTab('download')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7,10 12,15 17,10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
          Download Shared
        </button>
        <button 
          className={`tab-btn ${activeTab === 'decrypt' ? 'active' : ''}`}
          onClick={() => setActiveTab('decrypt')}
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <circle cx="12" cy="16" r="1"></circle>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          Decrypt Files
        </button>
      </div>

      <div className="user-dashboard-content">
        {activeTab === 'upload' && (
          <SecureUploader onUploadSuccess={handleFileUploadSuccess} />
        )}
        
        {activeTab === 'my-files' && (
          <div className="my-files-section">
            <div className="section-header">
              <h2>My Files</h2>
              <button onClick={loadUserFiles} className="refresh-btn" disabled={loading}>
                {loading ? (
                  <svg className="spinner" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12a9 9 0 11-6.219-8.56"></path>
                  </svg>
                ) : (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="23,4 23,10 17,10"></polyline>
                    <polyline points="1,20 1,14 7,14"></polyline>
                    <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path>
                  </svg>
                )}
              </button>
            </div>
            <FileList 
              files={userFiles} 
              onDeleteFile={handleFileDelete}
              showUserFiles={true}
            />
          </div>
        )}
        
        {activeTab === 'download' && (
          <FileSearch />
        )}
        
        {activeTab === 'decrypt' && (
          <FileDecryptor />
        )}
      </div>
    </div>
  );
}; 