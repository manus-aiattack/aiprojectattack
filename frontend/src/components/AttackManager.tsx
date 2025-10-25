import React, { useState, useEffect } from 'react';
import { Play, Square, Trash2, Eye } from 'lucide-react';
import { attackAPI, agentAPI } from '../services/api';

interface Attack {
  id: string;
  target_url: string;
  attack_type: string;
  status: string;
  started_at: string;
  completed_at?: string;
  vulnerabilities_found: number;
}

const AttackManager: React.FC = () => {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewAttackModal, setShowNewAttackModal] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      
      const [attacksData, agentsData] = await Promise.all([
        attackAPI.listAttacks(),
        agentAPI.listAgents(),
      ]);

      setAttacks(attacksData.attacks || []);
      setAgents(agentsData.agents || []);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStopAttack = async (attackId: string) => {
    try {
      await attackAPI.stopAttack(attackId);
      await loadData();
    } catch (error) {
      console.error('Failed to stop attack:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-blue-100 text-blue-800';
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      case 'stopped':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return <div className="p-6">Loading...</div>;
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Attack Manager</h1>
        <button
          onClick={() => setShowNewAttackModal(true)}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center space-x-2"
        >
          <Play className="w-4 h-4" />
          <span>New Attack</span>
        </button>
      </div>

      {/* Attacks Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Target
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Started
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Vulnerabilities
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {attacks.map((attack) => (
              <tr key={attack.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-medium text-gray-900">
                    {attack.target_url}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">{attack.attack_type}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(attack.status)}`}>
                    {attack.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {new Date(attack.started_at).toLocaleString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-semibold text-red-600">
                    {attack.vulnerabilities_found}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="flex items-center justify-end space-x-2">
                    <button
                      onClick={() => window.location.href = `/attacks/${attack.id}`}
                      className="text-blue-600 hover:text-blue-900"
                      title="View Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    {attack.status === 'running' && (
                      <button
                        onClick={() => handleStopAttack(attack.id)}
                        className="text-red-600 hover:text-red-900"
                        title="Stop Attack"
                      >
                        <Square className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {attacks.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            No attacks found. Start a new attack to begin.
          </div>
        )}
      </div>

      {/* New Attack Modal */}
      {showNewAttackModal && (
        <NewAttackModal
          agents={agents}
          onClose={() => setShowNewAttackModal(false)}
          onSuccess={() => {
            setShowNewAttackModal(false);
            loadData();
          }}
        />
      )}
    </div>
  );
};

interface NewAttackModalProps {
  agents: any[];
  onClose: () => void;
  onSuccess: () => void;
}

const NewAttackModal: React.FC<NewAttackModalProps> = ({ agents, onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    target_url: '',
    attack_type: 'comprehensive',
    selected_agents: [] as string[],
  });
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      setSubmitting(true);
      
      await attackAPI.startAttack({
        target_url: formData.target_url,
        attack_type: formData.attack_type,
        agents: formData.selected_agents,
      });

      onSuccess();
    } catch (error) {
      console.error('Failed to start attack:', error);
      alert('Failed to start attack');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-2xl">
        <h2 className="text-2xl font-bold mb-4">Start New Attack</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Target URL
            </label>
            <input
              type="url"
              required
              value={formData.target_url}
              onChange={(e) => setFormData({ ...formData, target_url: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
              placeholder="https://example.com"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Attack Type
            </label>
            <select
              value={formData.attack_type}
              onChange={(e) => setFormData({ ...formData, attack_type: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
            >
              <option value="comprehensive">Comprehensive Scan</option>
              <option value="quick">Quick Scan</option>
              <option value="deep">Deep Scan</option>
              <option value="zero_day">Zero-Day Hunter</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Select Agents ({formData.selected_agents.length} selected)
            </label>
            <div className="border border-gray-300 rounded-lg p-3 max-h-60 overflow-y-auto">
              {agents.map((agent) => (
                <label key={agent.name} className="flex items-center space-x-2 py-2">
                  <input
                    type="checkbox"
                    checked={formData.selected_agents.includes(agent.name)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setFormData({
                          ...formData,
                          selected_agents: [...formData.selected_agents, agent.name],
                        });
                      } else {
                        setFormData({
                          ...formData,
                          selected_agents: formData.selected_agents.filter((a) => a !== agent.name),
                        });
                      }
                    }}
                    className="rounded"
                  />
                  <span className="text-sm">{agent.name}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || formData.selected_agents.length === 0}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Starting...' : 'Start Attack'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AttackManager;

