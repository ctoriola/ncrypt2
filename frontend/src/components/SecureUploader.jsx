import React, { useState, useRef, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { toast } from 'react-toastify';
import './SecureUploader.css';

// API base URL - use environment variable or default to localhost
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export function SecureUploader({ onUploadComplete }) {
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentFile, setCurrentFile] = useState(null);
  const workerRef = useRef(null);

  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    
    // Validate file size (100MB limit)
    if (file.size > 100 * 1024 * 1024) {
      toast.error('File size must be less than 100MB');
      return;
    }

    // Get passphrase from user
    const passphrase = prompt('Enter a secure passphrase for encryption:');
    if (!passphrase || passphrase.length < 8) {
      toast.error('Passphrase must be at least 8 characters long');
      return;
    }

    await handleFileUpload(file, passphrase);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'text/plain': ['.txt'],
      'image/*': ['.jpg', '.jpeg', '.png', '.gif'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'application/vnd.ms-excel': ['.xls'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
      'text/csv': ['.csv'],
      'application/zip': ['.zip'],
      'application/x-rar-compressed': ['.rar']
    },
    multiple: false
  });

  const handleFileUpload = async (file, passphrase) => {
    try {
      setUploading(true);
      setProgress(0);
      setCurrentFile(file);

      // Encrypt file in main thread (simpler approach)
      const encryptedFile = await encryptFile(file, passphrase);
      
      // Update progress
      setProgress(50);

      // Upload encrypted file
      const formData = new FormData();
      formData.append('file', encryptedFile, file.name + '.encrypted');

      const response = await fetch(`${API_BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Upload failed');
      }

      const result = await response.json();
      
      setProgress(100);
      setUploading(false);
      setCurrentFile(null);
      toast.success('File encrypted and uploaded successfully!');
      onUploadComplete();

    } catch (error) {
      setUploading(false);
      setProgress(0);
      setCurrentFile(null);
      toast.error(`Upload failed: ${error.message}`);
    }
  };

  const encryptFile = async (file, passphrase) => {
    try {
      // Generate salt and derive key
      const salt = crypto.getRandomValues(new Uint8Array(16));
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
        ["encrypt"]
      );

      // Read file data
      const fileBuffer = await file.arrayBuffer();
      
      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt file
      const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        fileBuffer
      );

      // Combine salt + iv + encrypted data
      const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
      combined.set(salt, 0);
      combined.set(iv, salt.length);
      combined.set(new Uint8Array(encrypted), salt.length + iv.length);

      return new Blob([combined], { type: 'application/octet-stream' });
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  };

  const cancelUpload = () => {
    setUploading(false);
    setProgress(0);
    setCurrentFile(null);
    toast.info('Upload cancelled');
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="secure-uploader">
      <div
        {...getRootProps()}
        className={`dropzone ${isDragActive ? 'drag-active' : ''} ${uploading ? 'uploading' : ''}`}
      >
        <input {...getInputProps()} />
        
        {uploading ? (
          <div className="upload-progress">
            <div className="file-info">
              <h3>Uploading: {currentFile?.name}</h3>
              <p>Size: {formatFileSize(currentFile?.size)}</p>
            </div>
            
            <div className="progress-container">
              <div className="progress-bar">
                <div 
                  className="progress-fill" 
                  style={{ width: `${progress}%` }}
                ></div>
              </div>
              <span className="progress-text">{progress}%</span>
            </div>
            
            <button 
              type="button" 
              className="cancel-btn"
              onClick={(e) => {
                e.stopPropagation();
                cancelUpload();
              }}
            >
              Cancel Upload
            </button>
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
            <h3>Drop your file here</h3>
            <p>or click to browse</p>
            <div className="supported-formats">
              <small>Supported: PDF, DOC, DOCX, XLS, XLSX, TXT, CSV, Images, ZIP, RAR</small>
            </div>
          </div>
        )}
      </div>

      <div className="security-info">
        <div className="security-badge">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          <span>Client-side encryption</span>
        </div>
        <div className="security-badge">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 12l2 2 4-4"></path>
            <path d="M21 12c-1 0-2-1-2-2s1-2 2-2 2 1 2 2-1 2-2 2z"></path>
            <path d="M3 12c1 0 2-1 2-2s-1-2-2-2-2 1-2 2 1 2 2 2z"></path>
            <path d="M12 3c0 1-1 2-2 2s-2-1-2-2 1-2 2-2 2 1 2 2z"></path>
            <path d="M12 21c0-1 1-2 2-2s2 1 2 2-1 2-2 2-2-1-2-2z"></path>
          </svg>
          <span>Zero-knowledge storage</span>
        </div>
      </div>
    </div>
  );
} 