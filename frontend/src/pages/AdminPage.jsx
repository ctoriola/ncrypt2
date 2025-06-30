import React from 'react';
import { AdminLogin } from '../components/AdminLogin';
import { AdminDashboard } from '../components/AdminDashboard';
import { useAuth } from '../contexts/AuthContext';
import { usePageTracking } from '../hooks/usePageTracking';
import './AdminPage.css';

export function AdminPage() {
  const { currentUser } = useAuth();

  // Track page visits
  usePageTracking();

  const handleAdminLoginSuccess = () => {
    // Login success is handled by the AuthContext
    // No need to change tabs since this is a separate page
  };

  const handleAdminLogout = () => {
    // Logout is handled by the AuthContext
    // User will stay on admin page but see login form
  };

  return (
    <div className="admin-page">
      <div className="admin-page-container">
        <div className="admin-page-header">
          <h1>NCryp Admin Panel</h1>
          <p>Manage your secure file storage system</p>
        </div>

        <div className="admin-page-content">
          {currentUser ? (
            <AdminDashboard onLogout={handleAdminLogout} />
          ) : (
            <AdminLogin onLoginSuccess={handleAdminLoginSuccess} />
          )}
        </div>
      </div>
    </div>
  );
} 