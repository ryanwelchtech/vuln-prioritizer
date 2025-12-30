'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Server, Trash2, Edit2 } from 'lucide-react';
import { assetsApi, Asset } from '@/lib/api';

export default function AssetsPage() {
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [editingAsset, setEditingAsset] = useState<Asset | null>(null);
  const [formData, setFormData] = useState({
    hostname: '',
    ip_address: '',
    asset_type: 'server',
    environment: 'production',
    criticality: 1.0,
    owner: '',
    business_unit: '',
  });

  const { data: assets, isLoading } = useQuery({
    queryKey: ['assets'],
    queryFn: () => assetsApi.list({ limit: 100 }),
  });

  const { data: stats } = useQuery({
    queryKey: ['assetStats'],
    queryFn: () => assetsApi.getStats(),
  });

  const createMutation = useMutation({
    mutationFn: (data: typeof formData) => assetsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setShowModal(false);
      resetForm();
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: typeof formData }) =>
      assetsApi.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
      setShowModal(false);
      setEditingAsset(null);
      resetForm();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => assetsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assets'] });
    },
  });

  const resetForm = () => {
    setFormData({
      hostname: '',
      ip_address: '',
      asset_type: 'server',
      environment: 'production',
      criticality: 1.0,
      owner: '',
      business_unit: '',
    });
  };

  const handleEdit = (asset: Asset) => {
    setEditingAsset(asset);
    setFormData({
      hostname: asset.hostname,
      ip_address: asset.ip_address || '',
      asset_type: asset.asset_type,
      environment: asset.environment,
      criticality: asset.criticality,
      owner: asset.owner || '',
      business_unit: asset.business_unit || '',
    });
    setShowModal(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingAsset) {
      updateMutation.mutate({ id: editingAsset.id, data: formData });
    } else {
      createMutation.mutate(formData);
    }
  };

  const getCriticalityColor = (criticality: number) => {
    if (criticality >= 1.3) return 'text-red-600 bg-red-100';
    if (criticality >= 1.0) return 'text-orange-600 bg-orange-100';
    return 'text-green-600 bg-green-100';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Asset Inventory
        </h1>
        <button
          onClick={() => {
            resetForm();
            setEditingAsset(null);
            setShowModal(true);
          }}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="h-4 w-4" />
          Add Asset
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <p className="text-sm text-gray-500">Total Assets</p>
          <p className="text-2xl font-bold">{stats?.data?.total_assets || 0}</p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500">With Critical Vulns</p>
          <p className="text-2xl font-bold text-red-600">
            {stats?.data?.assets_with_critical_vulns || 0}
          </p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500">Avg Criticality</p>
          <p className="text-2xl font-bold">
            {stats?.data?.avg_criticality?.toFixed(2) || '1.00'}
          </p>
        </div>
        <div className="card">
          <p className="text-sm text-gray-500">By Environment</p>
          <div className="flex gap-2 mt-1">
            {stats?.data?.by_environment &&
              Object.entries(stats.data.by_environment).map(([env, count]) => (
                <span key={env} className="text-xs bg-gray-100 px-2 py-1 rounded">
                  {env}: {count as number}
                </span>
              ))}
          </div>
        </div>
      </div>

      {/* Add/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-lg">
            <h3 className="text-lg font-semibold mb-4">
              {editingAsset ? 'Edit Asset' : 'Add New Asset'}
            </h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Hostname *</label>
                  <input
                    type="text"
                    required
                    value={formData.hostname}
                    onChange={(e) =>
                      setFormData({ ...formData, hostname: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">IP Address</label>
                  <input
                    type="text"
                    value={formData.ip_address}
                    onChange={(e) =>
                      setFormData({ ...formData, ip_address: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Asset Type</label>
                  <select
                    value={formData.asset_type}
                    onChange={(e) =>
                      setFormData({ ...formData, asset_type: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="server">Server</option>
                    <option value="workstation">Workstation</option>
                    <option value="network_device">Network Device</option>
                    <option value="container">Container</option>
                    <option value="cloud">Cloud Resource</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Environment</label>
                  <select
                    value={formData.environment}
                    onChange={(e) =>
                      setFormData({ ...formData, environment: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="testing">Testing</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">
                  Criticality: {formData.criticality.toFixed(1)}
                </label>
                <input
                  type="range"
                  min="0.5"
                  max="1.5"
                  step="0.1"
                  value={formData.criticality}
                  onChange={(e) =>
                    setFormData({ ...formData, criticality: parseFloat(e.target.value) })
                  }
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-gray-500">
                  <span>Low (0.5)</span>
                  <span>Normal (1.0)</span>
                  <span>Critical (1.5)</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Owner</label>
                  <input
                    type="text"
                    value={formData.owner}
                    onChange={(e) =>
                      setFormData({ ...formData, owner: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Business Unit</label>
                  <input
                    type="text"
                    value={formData.business_unit}
                    onChange={(e) =>
                      setFormData({ ...formData, business_unit: e.target.value })
                    }
                    className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 mt-6">
                <button
                  type="button"
                  onClick={() => {
                    setShowModal(false);
                    setEditingAsset(null);
                  }}
                  className="btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  {editingAsset ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assets Table */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <div className="card overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Asset
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Environment
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Criticality
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Vulnerabilities
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Owner
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {assets?.data?.map((asset: Asset) => (
                  <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                    <td className="px-4 py-3">
                      <div className="flex items-center">
                        <Server className="h-5 w-5 text-gray-400 mr-2" />
                        <div>
                          <p className="font-medium">{asset.hostname}</p>
                          {asset.ip_address && (
                            <p className="text-xs text-gray-500">{asset.ip_address}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap capitalize">
                      {asset.asset_type.replace('_', ' ')}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap capitalize">
                      {asset.environment}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-1 rounded text-sm font-medium ${getCriticalityColor(
                          asset.criticality
                        )}`}
                      >
                        {asset.criticality.toFixed(1)}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span>{asset.vulnerability_count}</span>
                        {asset.critical_vuln_count > 0 && (
                          <span className="px-1.5 py-0.5 bg-red-100 text-red-800 text-xs rounded">
                            {asset.critical_vuln_count} critical
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                      {asset.owner || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleEdit(asset)}
                          className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
                        >
                          <Edit2 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Delete this asset?')) {
                              deleteMutation.mutate(asset.id);
                            }
                          }}
                          className="p-1 hover:bg-red-100 dark:hover:bg-red-900 rounded text-red-600"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {(!assets?.data || assets.data.length === 0) && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                      No assets found. Add your first asset to get started.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
