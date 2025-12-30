'use client';

import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  AlertTriangle,
  Server,
  Scan,
  TrendingUp,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import StatsCard from '@/components/StatsCard';
import SeverityBadge from '@/components/SeverityBadge';
import { vulnerabilitiesApi, scansApi, assetsApi } from '@/lib/api';

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
};

export default function DashboardPage() {
  const { data: vulnStats, isLoading: vulnLoading } = useQuery({
    queryKey: ['vulnerabilityStats'],
    queryFn: () => vulnerabilitiesApi.getStats(),
  });

  const { data: scanStats } = useQuery({
    queryKey: ['scanStats'],
    queryFn: () => scansApi.getStats(),
  });

  const { data: assetStats } = useQuery({
    queryKey: ['assetStats'],
    queryFn: () => assetsApi.getStats(),
  });

  const { data: recentVulns } = useQuery({
    queryKey: ['recentVulnerabilities'],
    queryFn: () => vulnerabilitiesApi.list({ limit: 5, sort_by: 'risk_score', sort_order: 'desc' }),
  });

  const severityData = vulnStats?.data?.by_severity
    ? Object.entries(vulnStats.data.by_severity).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
        color: COLORS[name as keyof typeof COLORS] || '#9ca3af',
      }))
    : [];

  const statusData = vulnStats?.data?.by_status
    ? Object.entries(vulnStats.data.by_status).map(([name, value]) => ({
        name: name.replace('_', ' ').charAt(0).toUpperCase() + name.slice(1).replace('_', ' '),
        count: value,
      }))
    : [];

  if (vulnLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
        <span className="text-sm text-gray-500">
          Last updated: {new Date().toLocaleString()}
        </span>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Total Vulnerabilities"
          value={vulnStats?.data?.total || 0}
          subtitle={`${vulnStats?.data?.kev_count || 0} in CISA KEV`}
          icon={Shield}
          color="default"
        />
        <StatsCard
          title="Critical"
          value={vulnStats?.data?.by_severity?.critical || 0}
          subtitle="Immediate action required"
          icon={AlertTriangle}
          color="critical"
        />
        <StatsCard
          title="Avg Risk Score"
          value={vulnStats?.data?.avg_risk_score?.toFixed(1) || '0.0'}
          icon={TrendingUp}
          color="medium"
        />
        <StatsCard
          title="Assets at Risk"
          value={assetStats?.data?.assets_with_critical_vulns || 0}
          subtitle={`of ${assetStats?.data?.total_assets || 0} total`}
          icon={Server}
          color="high"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Status Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Status Overview</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top Vulnerabilities */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Highest Risk Vulnerabilities</h3>
          <a
            href="/vulnerabilities"
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            View all →
          </a>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead>
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  CVE ID
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  CVSS
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  EPSS
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  KEV
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {recentVulns?.data?.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="px-4 py-3 whitespace-nowrap">
                    <a
                      href={`/vulnerabilities/${vuln.id}`}
                      className="text-blue-600 hover:underline font-medium"
                    >
                      {vuln.cve_id}
                    </a>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <span className="font-bold">{vuln.risk_score?.toFixed(1) || '-'}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    <SeverityBadge severity={vuln.severity} size="sm" />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {vuln.cvss_v3_score?.toFixed(1) || '-'}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(1)}%` : '-'}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {vuln.in_kev ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                        KEV
                      </span>
                    ) : (
                      <span className="text-gray-400">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap capitalize">
                    {vuln.status}
                  </td>
                </tr>
              ))}
              {(!recentVulns?.data || recentVulns.data.length === 0) && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                    No vulnerabilities found. Upload a scan to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
