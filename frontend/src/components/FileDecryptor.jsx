import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'react-toastify';
import { useDropzone } from 'react-dropzone';
import './FileDecryptor.css';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL || 'https://web-production-5d61.up.railway.app';

export function FileDecryptor() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    fetchFiles();
  }, []);

  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    
    // Validate file size (100MB limit)
    if (file.size > 100 * 1024 * 1024) {
      toast.error('File size must be less than 100MB');
      return;
    }

    await handleFileUpload(file);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.encrypted', '.bin', '.enc'],
      'application/octet-stream': ['.encrypted', '.bin', '.enc']
    },
    multiple: false
  });

  const handleFileUpload = async (file) => {
    try {
      setUploading(true);
      
      // Upload the encrypted file
      const formData = new FormData();
      formData.append('file', file, file.name);

      const response = await fetch(`${API_BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
      }

      toast.success('Encrypted file uploaded successfully!');
      fetchFiles(); // Refresh the file list
      
    } catch (error) {
      toast.error(`Upload failed: ${error.message}`);
    } finally {
      setUploading(false);
    }
  };

  const fetchFiles = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/api/files`);
      if (response.ok) {
        const data = await response.json();
        // Show all files, not just encrypted ones, so users can see everything
        setFiles(data.files || []);
      } else {
        toast.error('Failed to fetch files');
      }
    } catch (error) {
      toast.error('Error fetching files');
    } finally {
      setLoading(false);
    }
  };

  const decryptFile = async (fileId, filename, passphrase) => {
    try {
      setDecrypting(true);
      
      // Download the encrypted file
      const response = await fetch(`${API_BASE_URL}/api/files/${fileId}`);
      if (!response.ok) {
        throw new Error('Failed to download file');
      }
      
      const encryptedData = await response.arrayBuffer();
      
      // Decrypt the file
      const decryptedData = await decryptFileData(encryptedData, passphrase);
      
      // Create and download the decrypted file
      const blob = new Blob([decryptedData]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename.replace('.encrypted', '').replace('.enc', '').replace('.bin', '');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast.success('File decrypted and downloaded successfully!');
      
    } catch (error) {
      toast.error(`Decryption failed: ${error.message}`);
    } finally {
      setDecrypting(false);
    }
  };

  const decryptFileData = async (encryptedData, passphrase) => {
    try {
      const data = new Uint8Array(encryptedData);
      
      // Extract salt, IV, and encrypted data
      const salt = data.slice(0, 16);
      const iv = data.slice(16, 28);
      const encrypted = data.slice(28);
      
      // Derive key from passphrase
      const baseKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );

      // Decrypt the data
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
      );

      return decrypted;
    } catch (error) {
      throw new Error('Invalid passphrase or corrupted file');
    }
  };

  const handleDecrypt = (file) => {
    const passphrase = prompt(`Enter the passphrase for "${file.filename}":`);
    if (passphrase && passphrase.length > 0) {
      decryptFile(file.id, file.filename, passphrase);
    }
  };

  const handleDelete = async (fileId) => {
    if (window.confirm('Are you sure you want to delete this file?')) {
      try {
        const response = await fetch(`${API_BASE_URL}/api/files/${fileId}`, {
          method: 'DELETE'
        });
        
        if (response.ok) {
          toast.success('File deleted successfully');
          fetchFiles(); // Refresh the list
        } else {
          toast.error('Failed to delete file');
        }
      } catch (error) {
        toast.error('Error deleting file');
      }
    }
  };

  const handleDownload = async (fileId, filename) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/files/${fileId}`);
      if (!response.ok) {
        throw new Error('Failed to download file');
      }
      
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      toast.success('File downloaded successfully!');
    } catch (error) {
      toast.error(`Download failed: ${error.message}`);
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
    return new Date(dateString).toLocaleString();
  };

  if (loading) {
    return (
      <div className="file-decryptor">
        <div className="loading">
          <div className="spinner"></div>
          <p>Loading files...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="file-decryptor">
      <div className="decryptor-header">
        <h2>Decrypt Files</h2>
        <p>Upload encrypted files or decrypt your existing files</p>
        <button 
          className="refresh-btn"
          onClick={fetchFiles}
          disabled={loading}
        >
          Refresh
        </button>
      </div>

      {/* Upload Section */}
      <div className="upload-section">
        <h3>Upload Encrypted File</h3>
        <p>Upload an encrypted file from your computer to decrypt it</p>
        
        <div
          {...getRootProps()}
          className={`dropzone ${isDragActive ? 'drag-active' : ''} ${uploading ? 'uploading' : ''}`}
        >
          <input {...getInputProps()} />
          
          {uploading ? (
            <div className="upload-progress">
              <div className="spinner"></div>
              <p>Uploading encrypted file...</p>
            </div>
          ) : (
            <div className="upload-prompt">
              <div className="upload-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="7,10 12,15 17,10"></polyline>
                  <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
              </div>
              <h4>Drop your encrypted file here</h4>
              <p>or click to browse</p>
              <div className="supported-formats">
                <small>Supported: .encrypted, .enc, .bin files</small>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Files List Section */}
      <div className="files-section">
        <h3>Your Files</h3>
        <p>All your uploaded files. Encrypted files can be decrypted, regular files can be downloaded.</p>
        
        {files.length === 0 ? (
          <div className="no-files">
            <div className="no-files-icon">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14,2 14,8 20,8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
                <polyline points="10,9 9,9 8,9"></polyline>
              </svg>
            </div>
            <h4>No files found</h4>
            <p>Upload a file above to see it here</p>
          </div>
        ) : (
          <div className="files-list">
            {files.map((file) => (
              <div key={file.id} className="file-item">
                <div className="file-info">
                  <div className="file-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                      <polyline points="14,2 14,8 20,8"></polyline>
                      <line x1="16" y1="13" x2="8" y2="13"></line>
                      <line x1="16" y1="17" x2="8" y2="17"></line>
                      <polyline points="10,9 9,9 8,9"></polyline>
                    </svg>
                  </div>
                  <div className="file-details">
                    <h4>{file.filename}</h4>
                    <p>Size: {formatFileSize(file.size)}</p>
                    <p>Uploaded: {formatDate(file.upload_date)}</p>
                    {file.encrypted && <p className="file-status">🔒 Encrypted</p>}
                  </div>
                </div>
                <div className="file-actions">
                  {file.encrypted ? (
                    <button
                      className="decrypt-btn"
                      onClick={() => handleDecrypt(file)}
                      disabled={decrypting}
                    >
                      {decrypting ? 'Decrypting...' : 'Decrypt'}
                    </button>
                  ) : (
                    <button
                      className="download-btn"
                      onClick={() => handleDownload(file.id, file.filename)}
                      disabled={decrypting}
                    >
                      Download
                    </button>
                  )}
                  <button
                    className="delete-btn"
                    onClick={() => handleDelete(file.id)}
                    disabled={decrypting}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
} 