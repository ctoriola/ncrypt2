import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function FirebaseTest() {
  const [testResults, setTestResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const { currentUser } = useAuth();

  const testFirebaseConfig = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/api/admin/test-firebase`);
      const data = await response.json();
      setTestResults({ type: 'config', data });
    } catch (error) {
      setTestResults({ type: 'config', error: error.message });
    } finally {
      setLoading(false);
    }
  };

  const testFirebaseToken = async () => {
    if (!currentUser) {
      setTestResults({ type: 'token', error: 'No user logged in' });
      return;
    }

    try {
      setLoading(true);
      const idToken = await currentUser.getIdToken(true);
      
      const response = await fetch(`${API_BASE_URL}/api/admin/test-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: idToken }),
      });
      
      const data = await response.json();
      setTestResults({ type: 'token', data });
    } catch (error) {
      setTestResults({ type: 'token', error: error.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h2>Firebase Debug Tests</h2>
      
      <div style={{ marginBottom: '20px' }}>
        <h3>Current User Info</h3>
        <p><strong>Email:</strong> {currentUser?.email || 'Not logged in'}</p>
        <p><strong>UID:</strong> {currentUser?.uid || 'N/A'}</p>
        <p><strong>Project ID:</strong> {import.meta.env.VITE_FIREBASE_PROJECT_ID || 'Not set'}</p>
        <p><strong>Auth Domain:</strong> {import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || 'Not set'}</p>
      </div>

      <div style={{ marginBottom: '20px' }}>
        <button 
          onClick={testFirebaseConfig}
          disabled={loading}
          style={{ marginRight: '10px', padding: '10px 20px' }}
        >
          Test Firebase Config
        </button>
        
        <button 
          onClick={testFirebaseToken}
          disabled={loading || !currentUser}
          style={{ padding: '10px 20px' }}
        >
          Test Firebase Token
        </button>
      </div>

      {loading && <p>Testing...</p>}

      {testResults && (
        <div style={{ marginTop: '20px' }}>
          <h3>Test Results ({testResults.type})</h3>
          <pre style={{ 
            backgroundColor: '#f5f5f5', 
            padding: '15px', 
            borderRadius: '5px',
            overflow: 'auto',
            maxHeight: '400px'
          }}>
            {JSON.stringify(testResults.data || testResults.error, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
} 