import React, { useState } from 'react';
import api from '../services/api';

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Login with API key
      const response = await api.post('/api/auth/login', { api_key: apiKey });
      
      // Store API key and user info
      localStorage.setItem('api_key', apiKey);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      
      // Set API key in headers for future requests
      api.defaults.headers.common['X-API-Key'] = apiKey;
      
      onLogin();
    } catch (err: any) {
      setError(err.response?.data?.detail || err.response?.data?.message || 'Invalid API key');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="bg-gray-800 p-8 rounded-lg shadow-xl w-96">
        <h1 className="text-2xl font-bold text-cyan-400 mb-6 text-center">
          dLNk Attack Platform
        </h1>
        <p className="text-gray-400 text-sm mb-6 text-center">
          Enter your API key to access the platform
        </p>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-gray-300 mb-2">API Key</label>
            <input
              type="password"
              placeholder="Enter your API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full p-3 bg-gray-700 text-white rounded focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
              required
              autoComplete="off"
            />
            <p className="text-gray-500 text-xs mt-2">
              Find your API key in workspace/ADMIN_KEY.txt
            </p>
          </div>
          {error && (
            <div className="mb-4 p-3 bg-red-500/20 border border-red-500 rounded text-red-400 text-sm">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-500 text-white p-3 rounded hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
          >
            {loading ? 'Authenticating...' : 'Login'}
          </button>
        </form>
        <div className="mt-6 text-center text-gray-500 text-xs">
          <p>No account? API keys are generated automatically.</p>
          <p className="mt-1">Contact admin for access.</p>
        </div>
      </div>
    </div>
  );
}

