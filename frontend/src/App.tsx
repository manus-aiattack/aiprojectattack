import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import AttackManager from './components/AttackManager';
import C2Manager from './components/C2Manager';
import TargetManager from './components/TargetManager';
import AgentList from './components/AgentList';
import Login from './components/Login';

function App() {
  const [isAuthenticated, setIsAuthenticated] = React.useState(false);

  React.useEffect(() => {
    // Check if user is authenticated
    const token = localStorage.getItem('auth_token');
    setIsAuthenticated(!!token);
  }, []);

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />;
  }

  return (
    <BrowserRouter>
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
    </BrowserRouter>
  );
}

export default App;

