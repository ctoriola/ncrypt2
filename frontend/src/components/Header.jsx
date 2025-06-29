import React from 'react';
import './Header.css';

export function Header({ darkMode, onToggleDarkMode, user, onShowAuth, onShowProfile }) {
  return (
    <header className="header">
      <div className="container">
        <div className="header-content">
          <div className="logo">
            <div className="logo-icon">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <path d="M9 12l2 2 4-4"></path>
              </svg>
            </div>
            <h1>NCryp</h1>
            <span className="tagline">Secure File Storage</span>
          </div>

          <nav className="nav">
            <ul className="nav-list">
              <li><a href="#upload" className="nav-link">Upload</a></li>
              <li><a href="#files" className="nav-link">Files</a></li>
              <li><a href="#about" className="nav-link">About</a></li>
            </ul>
          </nav>

          <div className="header-actions">
            {/* User Authentication */}
            <div className="auth-section">
              {user ? (
                <div className="user-menu">
                  <button 
                    className="user-btn"
                    onClick={onShowProfile}
                    title="Account"
                  >
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                      <circle cx="12" cy="7" r="4"></circle>
                    </svg>
                    <span className="username">{user.username || 'User'}</span>
                    {!user.is_anonymous && (
                      <span className="upload-count">
                        {user.files_uploaded_count}/{user.upload_limit}
                      </span>
                    )}
                  </button>
                </div>
              ) : (
                <button 
                  className="auth-btn"
                  onClick={onShowAuth}
                >
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"></path>
                    <polyline points="10,17 15,12 10,7"></polyline>
                    <line x1="15" y1="12" x2="3" y2="12"></line>
                  </svg>
                  Sign In
                </button>
              )}
            </div>

            {/* Dark Mode Toggle */}
            <button 
              className="theme-toggle"
              onClick={onToggleDarkMode}
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="5"></circle>
                  <line x1="12" y1="1" x2="12" y2="3"></line>
                  <line x1="12" y1="21" x2="12" y2="23"></line>
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                  <line x1="1" y1="12" x2="3" y2="12"></line>
                  <line x1="21" y1="12" x2="23" y2="12"></line>
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
                </svg>
              ) : (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
} 