import React, { useState } from 'react';
import { UserLogin } from '../components/UserLogin';
import { UserRegistration } from '../components/UserRegistration';
import './UserAuthPage.css';

export function UserAuthPage({ onAuthSuccess }) {
  const [isLogin, setIsLogin] = useState(true);

  const handleLoginSuccess = () => {
    onAuthSuccess();
  };

  const handleRegistrationSuccess = () => {
    onAuthSuccess();
  };

  const switchToLogin = () => {
    setIsLogin(true);
  };

  const switchToRegistration = () => {
    setIsLogin(false);
  };

  return (
    <div className="user-auth-page">
      {isLogin ? (
        <UserLogin 
          onLoginSuccess={handleLoginSuccess}
          onSwitchToRegistration={switchToRegistration}
        />
      ) : (
        <UserRegistration 
          onRegistrationSuccess={handleRegistrationSuccess}
          onSwitchToLogin={switchToLogin}
        />
      )}
    </div>
  );
} 