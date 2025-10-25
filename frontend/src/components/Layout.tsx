import React from 'react';
import { Link } from 'react-router-dom';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-gray-900">
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-8">
              <Link to="/" className="text-cyan-400 font-bold text-xl">
                dLNk Attack Platform
              </Link>
              <Link to="/" className="text-gray-300 hover:text-white transition-colors">
                Dashboard
              </Link>
              <Link to="/attacks" className="text-gray-300 hover:text-white transition-colors">
                Attacks
              </Link>
              <Link to="/c2" className="text-gray-300 hover:text-white transition-colors">
                C2
              </Link>
              <Link to="/targets" className="text-gray-300 hover:text-white transition-colors">
                Targets
              </Link>
              <Link to="/agents" className="text-gray-300 hover:text-white transition-colors">
                Agents
              </Link>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  );
}

