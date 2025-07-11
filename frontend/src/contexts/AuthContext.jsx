import React, { createContext, useContext, useEffect, useState } from 'react';
import { 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword,
  signOut, 
  onAuthStateChanged
} from 'firebase/auth';
import { auth } from '../firebase';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// API base URL
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

// Track user analytics
const trackUserAnalytics = async (action, user) => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/user/${action}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: user.uid,
        email: user.email
      })
    });
    
    if (!response.ok) {
      console.warn(`Failed to track ${action}:`, response.status);
    }
  } catch (error) {
    console.warn(`Analytics tracking error for ${action}:`, error);
  }
};

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const login = async (email, password) => {
    try {
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      
      // Track login analytics
      await trackUserAnalytics('login', userCredential.user);
      
      return userCredential.user;
    } catch (error) {
      throw error;
    }
  };

  const register = async (email, password) => {
    try {
      const userCredential = await createUserWithEmailAndPassword(auth, email, password);
      
      // Track registration analytics
      await trackUserAnalytics('register', userCredential.user);
      
      return userCredential.user;
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      // Track logout analytics before signing out
      if (currentUser) {
        await trackUserAnalytics('logout', currentUser);
      }
      
      await signOut(auth);
    } catch (error) {
      throw error;
    }
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const value = {
    currentUser,
    login,
    register,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
}; 