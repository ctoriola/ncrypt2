import React from 'react';
import { AdminLogin } from '../components/AdminLogin';
import { AdminDashboard } from '../components/AdminDashboard';
import { useAuth } from '../contexts/AuthContext';
import './AdminPage.css';

export function AdminPage() {
  const { currentUser } = useAuth();

  const handleAdminLoginSuccess = () => {
    // Login success is handled by Firebase auth state
    console.log('Admin login successful');
  };

  const handleAdminLogout = () => {
    // Logout is handled by Firebase auth state
    console.log('Admin logout successful');
  };

  return (
    <div className="admin-page">
      <div className="admin-page-container">
        {currentUser ? (
          <AdminDashboard onLogout={handleAdminLogout} />
        ) : (
          <AdminLogin onLoginSuccess={handleAdminLoginSuccess} />
        )}
      </div>
    </div>
  );
} 