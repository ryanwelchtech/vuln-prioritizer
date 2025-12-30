'use client';

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Search, Filter, Download, RefreshCw } from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import RiskGauge from '@/components/RiskGauge';
import { vulnerabilitiesApi, Vulnerability } from '@/lib/api';

export default function VulnerabilitiesPage() {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState({
    severity: '',
    status: '',
    in_kev: '',
    search: '',
  });
  const [sortBy, setSortBy] = useState('risk_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [cveInput, setCveInput] = useState('');
  const [enrichResult, setEnrichResult] = useState<any>(null);

  const { data: vulnerabilities, isLoading, refetch } = useQuery({
    queryKey: ['vulnerabilities', filters, sortBy, sortOrder],
    queryFn: () =>
      vulnerabilitiesApi.list({
        severity: filters.severity || undefined,
        status: filters.status || undefined,
        in_kev: filters.in_kev ? filters.in_kev === 'true' : undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        limit: 100,
      }),
  });

  const enrichMutation = useMutation({
    mutationFn: (cveId: string) => vulnerabilitiesApi.enrich(cveId),
    onSuccess: (data) => {
      setEnrichResult(data.data);
    },
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      vulnerabilitiesApi.updateStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    },
  });

  const handleEnrich = () => {
    if (cveInput.trim()) {
      enrichMutation.mutate(cveInput.trim().toUpperCase());
    }
  };

  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('desc');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Vulnerabilities
        </h1>
        <button
          onClick={() => refetch()}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* CVE Lookup */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">CVE Lookup & Scoring</h3>
        <div className="flex gap-4">
          <input
            type="text"
            placeholder="Enter CVE ID (e.g., CVE-2024-1234)"
            value={cveInput}
            onChange={(e) => setCveInput(e.target.value)}
            className="flex-1 px-4 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
          />
          <button
            onClick={handleEnrich}
            disabled={enrichMutation.isPending}
            className="btn-primary"
          >
            {enrichMutation.isPending ? 'Loading...' : 'Lookup & Score'}
          </button>
        </div>

        {enrichResult && (
          <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
            <div className="flex items-start gap-6">
              <RiskGauge score={enrichResult.risk_score} size="lg" />
              <div className="flex-1">
                <h4 className="font-bold text-lg">{enrichResult.cve_id}</h4>
                <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                  {enrichResult.description?.slice(0, 200)}...
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                  <div>
                    <span className="text-xs text-gray-500">CVSS Score</span>
                    <p className="font-semibold">{enrichResult.cvss_v3_score?.toFixed(1) || 'N/A'}</p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-500">EPSS</span>
                    <p className="font-semibold">
                      {enrichResult.epss_score
                        ? `${(enrichResult.epss_score * 100).toFixed(2)}%`
                        : 'N/A'}
                    </p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-500">KEV Status</span>
                    <p className="font-semibold">
                      {enrichResult.in_kev ? (
                        <span className="text-red-600">In KEV</span>
                      ) : (
                        'Not in KEV'
                      )}
                    </p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-500">Severity</span>
                    <SeverityBadge severity={enrichResult.severity} />
                  </div>
                </div>
                <div className="mt-4">
                  <span className="text-xs text-gray-500">Score Components</span>
                  <div className="flex gap-4 mt-1">
                    <span className="text-sm">
                      CVSS: {enrichResult.components?.cvss_component?.toFixed(1)}
                    </span>
                    <span className="text-sm">
                      EPSS: {enrichResult.components?.epss_component?.toFixed(1)}
                    </span>
                    <span className="text-sm">
                      KEV: {enrichResult.components?.kev_component?.toFixed(1)}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-4">
          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            className="px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="remediated">Remediated</option>
            <option value="accepted">Accepted</option>
            <option value="false_positive">False Positive</option>
          </select>

          <select
            value={filters.in_kev}
            onChange={(e) => setFilters({ ...filters, in_kev: e.target.value })}
            className="px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
          >
            <option value="">All KEV Status</option>
            <option value="true">In KEV</option>
            <option value="false">Not in KEV</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="card overflow-hidden p-0">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800">
                <tr>
                  <th
                    onClick={() => handleSort('cve_id')}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    CVE ID
                  </th>
                  <th
                    onClick={() => handleSort('risk_score')}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    Risk Score {sortBy === 'risk_score' && (sortOrder === 'desc' ? '↓' : '↑')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Severity
                  </th>
                  <th
                    onClick={() => handleSort('cvss_v3_score')}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    CVSS {sortBy === 'cvss_v3_score' && (sortOrder === 'desc' ? '↓' : '↑')}
                  </th>
                  <th
                    onClick={() => handleSort('epss_score')}
                    className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700"
                  >
                    EPSS {sortBy === 'epss_score' && (sortOrder === 'desc' ? '↓' : '↑')}
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    KEV
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {vulnerabilities?.data?.map((vuln: Vulnerability) => (
                  <tr key={vuln.id} className="hover:bg-gray-50 dark:hover:bg-gray-800">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 hover:underline font-medium"
                      >
                        {vuln.cve_id}
                      </a>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="font-bold text-lg">
                        {vuln.risk_score?.toFixed(1) || '-'}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <SeverityBadge severity={vuln.severity} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {vuln.cvss_v3_score?.toFixed(1) || '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {vuln.epss_score
                        ? `${(vuln.epss_score * 100).toFixed(1)}%`
                        : '-'}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      {vuln.in_kev ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">
                          KEV
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <select
                        value={vuln.status}
                        onChange={(e) =>
                          updateStatusMutation.mutate({
                            id: vuln.id,
                            status: e.target.value,
                          })
                        }
                        className="text-sm border rounded px-2 py-1 dark:bg-gray-700 dark:border-gray-600"
                      >
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="remediated">Remediated</option>
                        <option value="accepted">Accepted</option>
                        <option value="false_positive">False Positive</option>
                      </select>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <a
                        href={`/vulnerabilities/${vuln.id}`}
                        className="text-blue-600 hover:underline text-sm"
                      >
                        Details
                      </a>
                    </td>
                  </tr>
                ))}
                {(!vulnerabilities?.data || vulnerabilities.data.length === 0) && (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                      No vulnerabilities found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
