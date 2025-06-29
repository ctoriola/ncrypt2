import React from 'react';
import './Footer.css';

export function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-section">
            <h4>NCryp</h4>
            <p>Secure client-side encrypted file storage with zero-knowledge architecture.</p>
            <div className="social-links">
              <a href="#" title="GitHub">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
              </a>
              <a href="#" title="Documentation">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14,2 14,8 20,8"></polyline>
                  <line x1="16" y1="13" x2="8" y2="13"></line>
                  <line x1="16" y1="17" x2="8" y2="17"></line>
                  <polyline points="10,9 9,9 8,9"></polyline>
                </svg>
              </a>
            </div>
          </div>

          <div className="footer-section">
            <h4>Features</h4>
            <ul>
              <li>Client-side encryption</li>
              <li>Zero-knowledge storage</li>
              <li>Malware scanning</li>
              <li>Secure file sharing</li>
              <li>Cross-platform support</li>
            </ul>
          </div>

          <div className="footer-section">
            <h4>Security</h4>
            <ul>
              <li>AES-256-GCM encryption</li>
              <li>PBKDF2 key derivation</li>
              <li>Secure random generation</li>
              <li>HTTPS enforcement</li>
              <li>Content Security Policy</li>
            </ul>
          </div>

          <div className="footer-section">
            <h4>Support</h4>
            <ul>
              <li><a href="#privacy">Privacy Policy</a></li>
              <li><a href="#terms">Terms of Service</a></li>
              <li><a href="#contact">Contact Us</a></li>
              <li><a href="#help">Help Center</a></li>
            </ul>
          </div>
        </div>

        <div className="footer-bottom">
          <p>&copy; 2024 NCryp. All rights reserved. Built with security in mind.</p>
          <div className="footer-stats">
            <span>🔒 End-to-end encrypted</span>
            <span>🌐 Open source</span>
            <span>⚡ Fast & reliable</span>
          </div>
        </div>
      </div>
    </footer>
  );
} 