import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import './FileHistory.css';

// API base URL - use environment variable or default to localhost
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export function FileHistory({ userId }) {
  const [files, setFiles] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('files'); // 'files' or 'history'
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('all'); // 'all', 'encrypted', 'recent'

  useEffect(() => {
    if (userId) {
      loadUserFiles();
      loadUserHistory();
    }
  }, [userId]);

  const loadUserFiles = async () => {
    if (!userId) return;
    
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/api/user/files`, {
        headers: {
          'X-User-ID': userId
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load files');
      }

      const data = await response.json();
      setFiles(data.files || []);
    } catch (error) {
      console.error('Error loading user files:', error);
      toast.error('Failed to load file history');
    } finally {
      setLoading(false);
    }
  };

  const loadUserHistory = async () => {
    if (!userId) return;
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/user/history?limit=100`, {
        headers: {
          'X-User-ID': userId
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load history');
      }

      const data = await response.json();
      setHistory(data.history || []);
    } catch (error) {
      console.error('Error loading user history:', error);
      // Don't show toast for history loading failure as it's less critical
    }
  };

  const handleDownload = async (fileId, filename) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/files/${fileId}`, {
        headers: {
          'X-User-ID': userId
        }
      });
      
      if (!response.ok) {
        throw new Error('Download failed');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success('File downloaded successfully!');
    } catch (error) {
      toast.error('Download failed: ' + error.message);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/files/${fileId}`, {
        method: 'DELETE',
        headers: {
          'X-User-ID': userId
        }
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Delete failed with status ${response.status}`);
      }

      // Remove from local state
      setFiles(files.filter(file => file.id !== fileId));
      toast.success('File deleted successfully!');
    } catch (error) {
      console.error('Delete error:', error);
      toast.error('Delete failed: ' + error.message);
    }
  };

  const formatFileSize = (bytes) => {
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

  const getFileIcon = (filename) => {
    const ext = filename.split('.').pop()?.toLowerCase();
    const iconMap = {
      pdf: '📄',
      doc: '📝',
      docx: '📝',
      xls: '📊',
      xlsx: '📊',
      txt: '📄',
      csv: '📊',
      jpg: '🖼️',
      jpeg: '🖼️',
      png: '🖼️',
      gif: '🖼️',
      zip: '📦',
      rar: '📦',
      encrypted: '🔒',
      enc: '🔒',
      bin: '🔒'
    };
    return iconMap[ext] || '📄';
  };

  const getActionIcon = (action) => {
    const iconMap = {
      upload: '📤',
      download: '📥',
      delete: '🗑️',
      view: '👁️'
    };
    return iconMap[action] || '📋';
  };

  const getActionColor = (action) => {
    const colorMap = {
      upload: '#4CAF50',
      download: '#2196F3',
      delete: '#F44336',
      view: '#FF9800'
    };
    return colorMap[action] || '#757575';
  };

  const filteredFiles = files.filter(file => {
    const matchesSearch = file.filename.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterType === 'all' || 
                         (filterType === 'encrypted' && file.encrypted) ||
                         (filterType === 'recent' && new Date(file.upload_date) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000));
    return matchesSearch && matchesFilter;
  });

  const filteredHistory = history.filter(entry => {
    return entry.filename?.toLowerCase().includes(searchTerm.toLowerCase()) || 
           entry.action?.toLowerCase().includes(searchTerm.toLowerCase());
  });

  if (loading) {
    return (
      <div className="file-history loading">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading your file history...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="file-history">
      <div className="history-header">
        <h2>Your File History</h2>
        <div className="tab-buttons">
          <button 
            className={`tab-btn ${activeTab === 'files' ? 'active' : ''}`}
            onClick={() => setActiveTab('files')}
          >
            📁 Files ({files.length})
          </button>
          <button 
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            📋 Activity ({history.length})
          </button>
        </div>
      </div>

      <div className="controls">
        <div className="search-box">
          <input
            type="text"
            placeholder="Search files or actions..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        
        {activeTab === 'files' && (
          <div className="filter-controls">
            <select 
              value={filterType} 
              onChange={(e) => setFilterType(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Files</option>
              <option value="encrypted">Encrypted Only</option>
              <option value="recent">Last 7 Days</option>
            </select>
          </div>
        )}
      </div>

      {activeTab === 'files' && (
        <div className="files-section">
          {filteredFiles.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📁</div>
              <h3>No files found</h3>
              <p>{searchTerm || filterType !== 'all' ? 'Try adjusting your search or filters' : 'Upload your first file to see it here'}</p>
            </div>
          ) : (
            <div className="files-grid">
              {filteredFiles.map(file => (
                <div key={file.id} className="file-card">
                  <div className="file-icon">
                    {getFileIcon(file.filename)}
                  </div>
                  
                  <div className="file-info">
                    <h4 className="file-name" title={file.filename}>
                      {file.filename.length > 25 
                        ? file.filename.substring(0, 25) + '...' 
                        : file.filename
                      }
                    </h4>
                    <p className="file-size">{formatFileSize(file.size)}</p>
                    <p className="file-date">{formatDate(file.upload_date)}</p>
                    {file.encrypted && <p className="file-status">🔒 Encrypted</p>}
                  </div>

                  <div className="file-actions">
                    <button
                      className="action-btn download-btn"
                      onClick={() => handleDownload(file.id, file.filename)}
                      title="Download file"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7,10 12,15 17,10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                      </svg>
                      <span>Download</span>
                    </button>

                    <button
                      className="action-btn delete-btn"
                      onClick={() => handleDelete(file.id)}
                      title="Delete file"
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="3,6 5,6 21,6"></polyline>
                        <path d="M19,6v14a2,2 0 0,1 -2,2H7a2,2 0 0,1 -2,-2V6m3,0V4a2,2 0 0,1 2,-2h4a2,2 0 0,1 2,2v2"></path>
                        <line x1="10" y1="11" x2="10" y2="17"></line>
                        <line x1="14" y1="11" x2="14" y2="17"></line>
                      </svg>
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'history' && (
        <div className="history-section">
          {filteredHistory.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">📋</div>
              <h3>No activity found</h3>
              <p>{searchTerm ? 'Try adjusting your search' : 'Your file activity will appear here'}</p>
            </div>
          ) : (
            <div className="history-list">
              {filteredHistory.map((entry, index) => (
                <div key={index} className="history-item">
                  <div className="history-icon" style={{ color: getActionColor(entry.action) }}>
                    {getActionIcon(entry.action)}
                  </div>
                  
                  <div className="history-info">
                    <div className="history-action">
                      <span className="action-text">{entry.action?.toUpperCase()}</span>
                      {entry.filename && (
                        <span className="filename"> - {entry.filename}</span>
                      )}
                    </div>
                    <div className="history-meta">
                      {entry.timestamp && (
                        <span className="timestamp">{formatDate(entry.timestamp)}</span>
                      )}
                      {entry.ip_address && (
                        <span className="ip-address">from {entry.ip_address}</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
} 