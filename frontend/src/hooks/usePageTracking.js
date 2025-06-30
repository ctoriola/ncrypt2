import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

// API base URL - use environment variable or default to Railway backend
const API_BASE_URL = import.meta.env.VITE_API_URL 
  ? (import.meta.env.VITE_API_URL.startsWith('http') ? import.meta.env.VITE_API_URL : `https://${import.meta.env.VITE_API_URL}`)
  : 'https://web-production-5d61.up.railway.app';

export function usePageTracking() {
  const location = useLocation();

  useEffect(() => {
    const trackPageVisit = async () => {
      try {
        const page = location.pathname;
        console.log('Tracking page visit:', page);
        
        await fetch(`${API_BASE_URL}/api/track-page`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ page }),
        });
      } catch (error) {
        console.error('Failed to track page visit:', error);
      }
    };

    // Track the page visit
    trackPageVisit();
  }, [location.pathname]);
} 