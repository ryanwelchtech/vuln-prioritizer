'use client';

import { useState, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Upload, Trash2, Eye, FileText } from 'lucide-react';
import { format } from 'date-fns';
import SeverityBadge from '@/components/SeverityBadge';
import { scansApi, Scan } from '@/lib/api';

export default function ScansPage() {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploadModal, setUploadModal] = useState(false);
  const [scanType, setScanType] = useState('csv');
  const [scanName, setScanName] = useState('');

  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list({ limit: 50 }),
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => scansApi.upload(file, scanType, scanName || undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setUploadModal(false);
      setScanName('');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => scansApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
  });

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      uploadMutation.mutate(file);
    }
  };

  const getSeverityCounts = (scan: Scan) => {
    return [
      { label: 'Critical', count: scan.critical_count, color: 'bg-red-500' },
      { label: 'High', count: scan.high_count, color: 'bg-orange-500' },
      { label: 'Medium', count: scan.medium_count, color: 'bg-yellow-500' },
      { label: 'Low', count: scan.low_count, color: 'bg-green-500' },
    ];
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Scan Management
        </h1>
        <button
          onClick={() => setUploadModal(true)}
          className="btn-primary flex items-center gap-2"
        >
          <Upload className="h-4 w-4" />
          Upload Scan
        </button>
      </div>

      {/* Upload Modal */}
      {uploadModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Upload Scan Results</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Scan Name (optional)</label>
                <input
                  type="text"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  placeholder="My Scan"
                  className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Scan Type</label>
                <select
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
                >
                  <option value="csv">CSV (CVE list)</option>
                  <option value="nessus">Nessus (.nessus)</option>
                  <option value="qualys">Qualys (.xml)</option>
                  <option value="rapid7">Rapid7 (.xml)</option>
                </select>
              </div>
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed rounded-lg p-8 text-center cursor-pointer hover:border-blue-500 transition-colors"
              >
                <Upload className="h-8 w-8 mx-auto text-gray-400" />
                <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
                  Click to select a file or drag and drop
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.xml,.nessus"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </div>
              {uploadMutation.isPending && (
                <div className="flex items-center justify-center gap-2">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-600"></div>
                  <span>Processing scan...</span>
                </div>
              )}
              {uploadMutation.isError && (
                <p className="text-red-600 text-sm">
                  Error uploading scan. Please try again.
                </p>
              )}
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => setUploadModal(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scans List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <div className="grid gap-4">
          {scans?.data?.map((scan: Scan) => (
            <div key={scan.id} className="card">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <FileText className="h-5 w-5 text-gray-400" />
                    <h3 className="font-semibold text-lg">{scan.name}</h3>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                        scan.status === 'completed'
                          ? 'bg-green-100 text-green-800'
                          : scan.status === 'processing'
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </div>
                  <div className="mt-2 text-sm text-gray-500">
                    <span className="capitalize">{scan.scan_type}</span>
                    {' • '}
                    {scan.completed_at
                      ? format(new Date(scan.completed_at), 'MMM d, yyyy h:mm a')
                      : 'Processing...'}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <a
                    href={`/scans/${scan.id}`}
                    className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
                  >
                    <Eye className="h-4 w-4" />
                  </a>
                  <button
                    onClick={() => {
                      if (confirm('Delete this scan?')) {
                        deleteMutation.mutate(scan.id);
                      }
                    }}
                    className="p-2 hover:bg-red-100 dark:hover:bg-red-900 rounded-md text-red-600"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>

              {/* Vulnerability Summary */}
              <div className="mt-4 flex items-center gap-6">
                <div className="text-center">
                  <p className="text-2xl font-bold">{scan.total_vulnerabilities}</p>
                  <p className="text-xs text-gray-500">Total</p>
                </div>
                <div className="flex-1 flex gap-2">
                  {getSeverityCounts(scan).map((item) => (
                    <div key={item.label} className="flex-1">
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span>{item.label}</span>
                        <span>{item.count}</span>
                      </div>
                      <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${item.color}`}
                          style={{
                            width: `${
                              scan.total_vulnerabilities > 0
                                ? (item.count / scan.total_vulnerabilities) * 100
                                : 0
                            }%`,
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}

          {(!scans?.data || scans.data.length === 0) && (
            <div className="card text-center py-12">
              <Upload className="h-12 w-12 mx-auto text-gray-400" />
              <h3 className="mt-4 text-lg font-medium">No scans yet</h3>
              <p className="mt-2 text-gray-500">
                Upload your first scan to start prioritizing vulnerabilities
              </p>
              <button
                onClick={() => setUploadModal(true)}
                className="btn-primary mt-4"
              >
                Upload Scan
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
