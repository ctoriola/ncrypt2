import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { toast } from 'react-toastify';
import './SecureUploader.css';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function SecureUploader({ onUploadComplete }) {
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadedFile, setUploadedFile] = useState(null);

  const onDrop = useCallback(async (acceptedFiles) => {
    if (acceptedFiles.length === 0) return;

    const file = acceptedFiles[0];
    
    // Check file size (100MB limit)
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      toast.error('File size exceeds 100MB limit');
      return;
    }

    setUploading(true);
    setUploadProgress(0);
    setUploadedFile(null);

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      // Encrypt file using Web Worker
      const encryptedData = await encryptFile(file);
      
      // Create FormData
      const formData = new FormData();
      formData.append('file', new Blob([encryptedData], { type: 'application/octet-stream' }), file.name + '.encrypted');

      // Upload to server
      const response = await fetch(`${API_BASE_URL}/api/upload`, {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });

      clearInterval(progressInterval);
      setUploadProgress(100);

      const result = await response.json();

      if (!response.ok) {
        if (result.limit_reached) {
          toast.error(result.error);
          // Show upgrade prompt
          toast.info('Upgrade your plan to upload more files!', {
            autoClose: 5000,
            onClick: () => {
              // Could trigger upgrade modal here
            }
          });
        } else {
          throw new Error(result.error || 'Upload failed');
        }
        return;
      }

      setUploadedFile({
        filename: file.name,
        shareId: result.share_id,
        size: file.size
      });

      toast.success('File uploaded successfully!');
      
      if (onUploadComplete) {
        onUploadComplete(result);
      }

    } catch (error) {
      console.error('Upload error:', error);
      toast.error(error.message || 'Upload failed');
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  }, [onUploadComplete]);

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
      'application/x-rar-compressed': ['.rar'],
      'application/octet-stream': ['.encrypted', '.enc', '.bin']
    },
    multiple: false
  });

  const encryptFile = async (file) => {
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('../workers/encryption.worker.js', import.meta.url));
      
      worker.onmessage = (event) => {
        if (event.data.error) {
          reject(new Error(event.data.error));
        } else {
          resolve(event.data.encryptedData);
        }
        worker.terminate();
      };

      worker.onerror = (error) => {
        reject(error);
        worker.terminate();
      };

      const reader = new FileReader();
      reader.onload = (e) => {
        worker.postMessage({
          data: e.target.result,
          key: crypto.getRandomValues(new Uint8Array(32))
        });
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsArrayBuffer(file);
    });
  };

  const copyShareId = async () => {
    if (!uploadedFile?.shareId) return;
    
    try {
      await navigator.clipboard.writeText(uploadedFile.shareId);
      toast.success('Share ID copied to clipboard!');
    } catch (error) {
      toast.error('Failed to copy share ID');
    }
  };

  const resetUpload = () => {
    setUploadedFile(null);
    setUploadProgress(0);
  };

  return (
    <div className="secure-uploader">
      {!uploadedFile ? (
        <div
          {...getRootProps()}
          className={`dropzone ${isDragActive ? 'active' : ''} ${uploading ? 'uploading' : ''}`}
        >
          <input {...getInputProps()} />
          
          {uploading ? (
            <div className="upload-progress">
              <div className="progress-circle">
                <svg viewBox="0 0 36 36" className="progress-ring">
                  <path
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="var(--border-color)"
                    strokeWidth="2"
                  />
                  <path
                    d="M18 2.0845
                      a 15.9155 15.9155 0 0 1 0 31.831
                      a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="var(--primary-color)"
                    strokeWidth="2"
                    strokeDasharray={`${uploadProgress}, 100`}
                    strokeLinecap="round"
                  />
                </svg>
                <span className="progress-text">{uploadProgress}%</span>
              </div>
              <p>Encrypting and uploading...</p>
            </div>
          ) : (
            <div className="upload-content">
              <div className="upload-icon">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="7,10 12,15 17,10"></polyline>
                  <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
              </div>
              <h3>Drop your file here</h3>
              <p>or click to browse</p>
              <div className="file-types">
                <span>Supports: PDF, DOC, XLS, Images, ZIP, and more</span>
                <span>Max size: 100MB</span>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="upload-success">
          <div className="success-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22,4 12,14.01 9,11.01"></polyline>
            </svg>
          </div>
          <h3>File Uploaded Successfully!</h3>
          <div className="file-info">
            <p><strong>File:</strong> {uploadedFile.filename}</p>
            <p><strong>Size:</strong> {(uploadedFile.size / 1024 / 1024).toFixed(2)} MB</p>
          </div>
          <div className="share-section">
            <p><strong>Share ID:</strong></p>
            <div className="share-id-container">
              <code className="share-id">{uploadedFile.shareId}</code>
              <button className="copy-btn" onClick={copyShareId}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
            </div>
            <p className="share-instructions">
              Share this ID with others so they can download your encrypted file
            </p>
          </div>
          <button className="upload-another-btn" onClick={resetUpload}>
            Upload Another File
          </button>
        </div>
      )}
    </div>
  );
} 