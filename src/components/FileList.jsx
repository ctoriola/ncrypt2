import React, { useState } from 'react';
import { toast } from 'react-toastify';
import './FileList.css';

export function FileList({ files, loading, onDelete, onRefresh }) {
  const [downloading, setDownloading] = useState(null);

  const handleDownload = async (fileId, filename) => {
    try {
      setDownloading(fileId);
      
      const response = await fetch(`/api/files/${fileId}`);
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
    } finally {
      setDownloading(null);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(`/api/files/${fileId}`, {
        method: 'DELETE'
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Delete failed with status ${response.status}`);
      }

      onDelete(fileId);
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

  // Separate files into encrypted and decrypted
  const encryptedFiles = files.filter(file => file.encrypted);
  const decryptedFiles = files.filter(file => !file.encrypted);

  if (loading) {
    return (
      <div className="file-list loading">
        <div className="loading-spinner">
          <div className="spinner"></div>
          <p>Loading files...</p>
        </div>
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="file-list empty">
        <div className="empty-state">
          <div className="empty-icon">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14,2 14,8 20,8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10,9 9,9 8,9"></polyline>
            </svg>
          </div>
          <h3>No files uploaded yet</h3>
          <p>Upload your first file to get started</p>
          <button onClick={onRefresh} className="refresh-btn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6"></path>
              <path d="M1 20v-6h6"></path>
              <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>
    );
  }

  const renderFileCard = (file) => (
    <div key={file.id} className="file-card">
      <div className="file-icon">
        {getFileIcon(file.filename)}
      </div>
      
      <div className="file-info">
        <h4 className="file-name" title={file.filename}>
          {file.filename.length > 30 
            ? file.filename.substring(0, 30) + '...' 
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
          disabled={downloading === file.id}
          title="Download file"
        >
          {downloading === file.id ? (
            <div className="loading-dots">
              <span></span>
              <span></span>
              <span></span>
            </div>
          ) : (
            <>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7,10 12,15 17,10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
              <span>Download</span>
            </>
          )}
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
  );

  return (
    <div className="file-list">
      <div className="file-list-header">
        <h3>Files ({files.length})</h3>
        <button onClick={onRefresh} className="refresh-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M23 4v6h-6"></path>
            <path d="M1 20v-6h6"></path>
            <path d="M20.49 9A9 9 0 0 0 5.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 0 1 3.51 15"></path>
          </svg>
          Refresh
        </button>
      </div>

      {/* Encrypted Files Section */}
      {encryptedFiles.length > 0 && (
        <div className="files-section">
          <h4 className="section-title">
            <span className="section-icon">🔒</span>
            Encrypted Files ({encryptedFiles.length})
          </h4>
          <div className="files-grid">
            {encryptedFiles.map(renderFileCard)}
          </div>
        </div>
      )}

      {/* Decrypted Files Section */}
      {decryptedFiles.length > 0 && (
        <div className="files-section">
          <h4 className="section-title">
            <span className="section-icon">📄</span>
            Regular Files ({decryptedFiles.length})
          </h4>
          <div className="files-grid">
            {decryptedFiles.map(renderFileCard)}
          </div>
        </div>
      )}
    </div>
  );
} 