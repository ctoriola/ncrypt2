import React, { useState } from 'react';
import { toast } from 'react-toastify';
import './FileSearch.css';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function FileSearch() {
  const [shareId, setShareId] = useState('');
  const [searching, setSearching] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [fileInfo, setFileInfo] = useState(null);
  const [error, setError] = useState('');

  const handleSearch = async (e) => {
    e.preventDefault();
    
    if (!shareId.trim()) {
      toast.error('Please enter a share ID');
      return;
    }

    // Validate share ID format (8 characters, alphanumeric) - case insensitive
    const normalizedShareId = shareId.trim().toUpperCase();
    if (!/^[A-Z0-9]{8}$/.test(normalizedShareId)) {
      toast.error('Share ID must be 8 characters long and contain only letters and numbers');
      return;
    }

    try {
      setSearching(true);
      setError('');
      setFileInfo(null);

      const response = await fetch(`${API_BASE_URL}/api/search/${normalizedShareId}`);
      
      if (!response.ok) {
        if (response.status === 404) {
          setError('File not found. Please check the share ID and try again.');
        } else {
          const errorData = await response.json().catch(() => ({}));
          setError(errorData.error || 'Search failed');
        }
        return;
      }

      const data = await response.json();
      setFileInfo(data);
      toast.success('File found!');

    } catch (error) {
      console.error('Search error:', error);
      setError('Network error. Please check your connection and try again.');
    } finally {
      setSearching(false);
    }
  };

  const handleDownload = async () => {
    if (!fileInfo) return;

    try {
      setDownloading(true);
      
      const response = await fetch(`${API_BASE_URL}/api/files/${fileInfo.share_id}`);
      if (!response.ok) {
        throw new Error('Download failed');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${fileInfo.filename}.encrypted`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success('Encrypted file downloaded successfully!');
      toast.info('Use the Decrypt Files tab to decrypt this file with the original passphrase.');
    } catch (error) {
      toast.error('Download failed: ' + error.message);
    } finally {
      setDownloading(false);
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

  return (
    <div className="file-search">
      <div className="search-container">
        <h2>Download Shared Files</h2>
        <p className="description">
          Enter a share ID to download an encrypted file shared with you.
        </p>

        <form onSubmit={handleSearch} className="search-form">
          <div className="input-group">
            <input
              type="text"
              value={shareId}
              onChange={(e) => setShareId(e.target.value)}
              placeholder="Enter 8-character share ID (e.g., ABC12345)"
              className="share-id-input"
              maxLength={8}
              pattern="[A-Z0-9]{8}"
              title="Share ID must be 8 characters long and contain only letters and numbers"
            />
            <button
              type="submit"
              className="search-btn"
              disabled={searching || !shareId.trim()}
            >
              {searching ? (
                <div className="loading-dots">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="M21 21l-4.35-4.35"></path>
                  </svg>
                  Search
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="error-message">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="15" y1="9" x2="9" y2="15"></line>
              <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
            {error}
          </div>
        )}

        {fileInfo && (
          <div className="file-info-card">
            <div className="file-header">
              <div className="file-icon">
                {getFileIcon(fileInfo.filename)}
              </div>
              <div className="file-details">
                <h3 className="file-name" title={fileInfo.filename}>
                  {fileInfo.filename.length > 30 
                    ? fileInfo.filename.substring(0, 30) + '...' 
                    : fileInfo.filename
                  }
                </h3>
                <p className="file-size">{formatFileSize(fileInfo.size)}</p>
                <p className="file-date">Shared on {formatDate(fileInfo.upload_date)}</p>
                <p className="share-id">Share ID: <code>{fileInfo.share_id}</code></p>
              </div>
            </div>

            <div className="file-actions">
              <button
                className="download-btn"
                onClick={handleDownload}
                disabled={downloading}
              >
                {downloading ? (
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
                    Download Encrypted File
                  </>
                )}
              </button>
            </div>

            <div className="decrypt-notice">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"></circle>
                <path d="M12 16v-4"></path>
                <path d="M12 8h.01"></path>
              </svg>
              <p>
                This file is encrypted. After downloading, use the <strong>Decrypt Files</strong> tab 
                to decrypt it with the original passphrase.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
} 