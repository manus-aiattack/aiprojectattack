import React, { useEffect, useState } from 'react';
import { Activity, Target, Shield, AlertTriangle } from 'lucide-react';
import { statsAPI, attackAPI } from '../services/api';
import { wsService } from '../services/websocket';
import AttackTimeline from './AttackTimeline';
import VulnerabilityChart from './VulnerabilityChart';
import ActiveAttacks from './ActiveAttacks';

interface DashboardStats {
  active_attacks: number;
  total_vulnerabilities: number;
  success_rate: number;
  targets_scanned: number;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    active_attacks: 0,
    total_vulnerabilities: 0,
    success_rate: 0,
    targets_scanned: 0,
  });
  const [loading, setLoading] = useState(true);
  const [attacks, setAttacks] = useState<any[]>([]);

  useEffect(() => {
    loadDashboardData();

    // Connect to WebSocket for real-time updates
    wsService.connect();
    wsService.on('attack_update', handleAttackUpdate);
    wsService.on('vulnerability_found', handleVulnerabilityFound);

    return () => {
      wsService.off('attack_update', handleAttackUpdate);
      wsService.off('vulnerability_found', handleVulnerabilityFound);
    };
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load stats
      const statsData = await statsAPI.getDashboardStats();
      setStats(statsData);

      // Load active attacks
      const attacksData = await attackAPI.listAttacks({ status: 'running' });
      setAttacks(attacksData.attacks || []);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAttackUpdate = (data: any) => {
    console.log('[Dashboard] Attack update:', data);
    loadDashboardData();
  };

  const handleVulnerabilityFound = (data: any) => {
    console.log('[Dashboard] Vulnerability found:', data);
    loadDashboardData();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-gray-600">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Attack Dashboard</h1>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-gray-600">Live</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Active Attacks"
          value={stats.active_attacks}
          icon={<Activity className="w-6 h-6" />}
          color="blue"
        />
        <StatCard
          title="Vulnerabilities Found"
          value={stats.total_vulnerabilities}
          icon={<AlertTriangle className="w-6 h-6" />}
          color="red"
        />
        <StatCard
          title="Success Rate"
          value={`${stats.success_rate}%`}
          icon={<Shield className="w-6 h-6" />}
          color="green"
        />
        <StatCard
          title="Targets Scanned"
          value={stats.targets_scanned}
          icon={<Target className="w-6 h-6" />}
          color="purple"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Attack Timeline</h2>
          <AttackTimeline />
        </div>
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-xl font-semibold mb-4">Vulnerability Distribution</h2>
          <VulnerabilityChart />
        </div>
      </div>

      {/* Active Attacks */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold mb-4">Active Attacks</h2>
        <ActiveAttacks attacks={attacks} onRefresh={loadDashboardData} />
      </div>
    </div>
  );
};

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: 'blue' | 'red' | 'green' | 'purple';
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color }) => {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-600',
    red: 'bg-red-100 text-red-600',
    green: 'bg-green-100 text-green-600',
    purple: 'bg-purple-100 text-purple-600',
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
          {icon}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

