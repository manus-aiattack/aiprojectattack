import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

// Lazy load components for code splitting
const Layout = lazy(() => import('./components/Layout'));
const Dashboard = lazy(() => import('./components/Dashboard'));
const AttackManager = lazy(() => import('./components/AttackManager'));
const C2Manager = lazy(() => import('./components/C2Manager'));
const TargetManager = lazy(() => import('./components/TargetManager'));
const AgentList = lazy(() => import('./components/AgentList'));
const Login = lazy(() => import('./components/Login'));

// Loading component
const LoadingSpinner = () => (
  <div className="min-h-screen bg-gray-900 flex items-center justify-center">
    <div className="text-center">
      <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500"></div>
      <p className="mt-4 text-cyan-400">Loading...</p>
    </div>
  </div>
);

function App() {
  const [isAuthenticated, setIsAuthenticated] = React.useState(false);

  React.useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('auth_token');
    setIsAuthenticated(!!token);
  }, []);

  if (!isAuthenticated) {
    return (
      <Suspense fallback={<LoadingSpinner />}>
        <Login onLogin={() => setIsAuthenticated(true)} />
      </Suspense>
    );
  }

  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingSpinner />}>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/attacks" element={<AttackManager />} />
            <Route path="/c2" element={<C2Manager />} />
            <Route path="/targets" element={<TargetManager />} />
            <Route path="/agents" element={<AgentList />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout>
      </Suspense>
    </BrowserRouter>
  );
}

export default App;

