import React, { useState, useEffect } from 'react';
import { SecureUploader } from '../components/SecureUploader';
import { FileDecryptor } from '../components/FileDecryptor';
import { FileList } from '../components/FileList';
import { FileSearch } from '../components/FileSearch';
import { Header } from '../components/Header';
import { Footer } from '../components/Footer';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import './MainPage.css';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function MainPage() {
  const [darkMode, setDarkMode] = useState(false);
  const [activeTab, setActiveTab] = useState('upload'); // 'upload', 'decrypt', or 'search'
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Check for saved dark mode preference
    const savedDarkMode = localStorage.getItem('darkMode') === 'true';
    setDarkMode(savedDarkMode);
    
    // Load files on mount
    loadFiles();
  }, []);

  useEffect(() => {
    // Apply dark mode class
    document.body.classList.toggle('dark-mode', darkMode);
    localStorage.setItem('darkMode', darkMode);
  }, [darkMode]);

  const loadFiles = async () => {
    try {
      setLoading(true);
      const url = `${API_BASE_URL}/api/files`;
      console.log('Calling API URL:', url);
      console.log('API_BASE_URL:', API_BASE_URL);
      
      const response = await fetch(url);
      console.log('Response status:', response.status);
      console.log('Response headers:', response.headers);
      
      if (response.ok) {
        const data = await response.json();
        console.log('Response data:', data);
        setFiles(data.files || []);
      } else {
        const errorText = await response.text();
        console.error('Failed to load files:', response.status, response.statusText);
        console.error('Error response:', errorText);
        toast.error('Failed to load files');
      }
    } catch (error) {
      console.error('Network error while loading files:', error);
      toast.error('Network error while loading files');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUploaded = () => {
    toast.success('File uploaded successfully!');
    loadFiles(); // Refresh file list
  };

  const handleFileDeleted = (fileId) => {
    setFiles(files.filter(file => file.id !== fileId));
    toast.success('File deleted successfully!');
  };

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <div className="app">
      <Header darkMode={darkMode} onToggleDarkMode={toggleDarkMode} />
      
      <main className="main-content">
        <div className="container">
          {/* Navigation Tabs */}
          <div className="nav-tabs">
            <button
              className={`nav-tab ${activeTab === 'upload' ? 'active' : ''}`}
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
              className={`nav-tab ${activeTab === 'search' ? 'active' : ''}`}
              onClick={() => setActiveTab('search')}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"></circle>
                <path d="M21 21l-4.35-4.35"></path>
              </svg>
              Download Shared
            </button>
            <button
              className={`nav-tab ${activeTab === 'decrypt' ? 'active' : ''}`}
              onClick={() => setActiveTab('decrypt')}
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17,8 12,3 7,8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
              </svg>
              Decrypt Files
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === 'upload' && (
            <>
              <section className="upload-section">
                <h2>Secure File Upload & Sharing</h2>
                <p className="description">
                  Upload your files with client-side encryption and get a shareable ID to send to others.
                </p>
                <SecureUploader onUploadComplete={handleFileUploaded} />
              </section>

              <section className="files-section">
                <h2>Your Files</h2>
                <FileList 
                  files={files} 
                  loading={loading} 
                  onDelete={handleFileDeleted}
                  onRefresh={loadFiles}
                />
              </section>
            </>
          )}

          {activeTab === 'search' && (
            <section className="search-section">
              <FileSearch />
            </section>
          )}

          {activeTab === 'decrypt' && (
            <section className="decrypt-section">
              <FileDecryptor />
            </section>
          )}
        </div>
      </main>

      <Footer />
      
      <ToastContainer 
        position="bottom-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme={darkMode ? 'dark' : 'light'}
      />
    </div>
  );
} 