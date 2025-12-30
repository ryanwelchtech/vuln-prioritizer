import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export interface Vulnerability {
  id: number;
  cve_id: string;
  description: string | null;
  cvss_v3_score: number | null;
  cvss_v3_vector: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  in_kev: boolean;
  risk_score: number | null;
  severity: string | null;
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface VulnerabilityStats {
  total: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  avg_risk_score: number;
  kev_count: number;
}

export interface Scan {
  id: number;
  name: string;
  scan_type: string;
  status: string;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface Asset {
  id: number;
  hostname: string;
  ip_address: string | null;
  asset_type: string;
  environment: string;
  criticality: number;
  owner: string | null;
  business_unit: string | null;
  tags: string[];
  vulnerability_count: number;
  critical_vuln_count: number;
  last_scan: string | null;
  created_at: string;
}

export interface EnrichResponse {
  cve_id: string;
  description: string | null;
  cvss_v3_score: number | null;
  epss_score: number | null;
  in_kev: boolean;
  kev_details: Record<string, unknown> | null;
  risk_score: number;
  severity: string;
  components: {
    cvss_component: number;
    epss_component: number;
    kev_component: number;
    context_component: number;
  };
}

// Vulnerabilities API
export const vulnerabilitiesApi = {
  list: (params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    status?: string;
    in_kev?: boolean;
    min_risk_score?: number;
    sort_by?: string;
    sort_order?: string;
  }) => api.get<Vulnerability[]>('/vulnerabilities', { params }),

  getStats: () => api.get<VulnerabilityStats>('/vulnerabilities/stats'),

  get: (id: number) => api.get<Vulnerability>(`/vulnerabilities/${id}`),

  enrich: (cveId: string, params?: {
    asset_criticality?: number;
    network_reachability?: number;
  }) => api.get<EnrichResponse>(`/vulnerabilities/enrich/${cveId}`, { params }),

  create: (data: { cve_id: string; asset_id?: number }) =>
    api.post<Vulnerability>('/vulnerabilities', data),

  updateStatus: (id: number, status: string) =>
    api.patch(`/vulnerabilities/${id}/status`, null, { params: { new_status: status } }),

  bulkScore: (data: {
    cve_ids: string[];
    asset_criticality?: number;
    network_reachability?: number;
  }) => api.post('/vulnerabilities/score/bulk', data),
};

// Scans API
export const scansApi = {
  list: (params?: {
    skip?: number;
    limit?: number;
    status?: string;
    scan_type?: string;
  }) => api.get<Scan[]>('/scans', { params }),

  getStats: () => api.get('/scans/stats'),

  get: (id: number) => api.get(`/scans/${id}`),

  create: (data: {
    name: string;
    scan_type: string;
    asset_id?: number;
    cve_ids: string[];
  }) => api.post<Scan>('/scans', data),

  upload: (file: File, scanType: string, name?: string, assetId?: number) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/scans/upload', formData, {
      params: { scan_type: scanType, name, asset_id: assetId },
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  delete: (id: number) => api.delete(`/scans/${id}`),
};

// Assets API
export const assetsApi = {
  list: (params?: {
    skip?: number;
    limit?: number;
    asset_type?: string;
    environment?: string;
    business_unit?: string;
    min_criticality?: number;
    has_critical_vulns?: boolean;
  }) => api.get<Asset[]>('/assets', { params }),

  getStats: () => api.get('/assets/stats'),

  get: (id: number) => api.get(`/assets/${id}`),

  create: (data: {
    hostname: string;
    ip_address?: string;
    asset_type?: string;
    environment?: string;
    criticality?: number;
    owner?: string;
    business_unit?: string;
    tags?: string[];
  }) => api.post<Asset>('/assets', data),

  update: (id: number, data: Partial<Asset>) =>
    api.put<Asset>(`/assets/${id}`, data),

  delete: (id: number) => api.delete(`/assets/${id}`),

  recalculateRisk: (id: number) =>
    api.post(`/assets/${id}/recalculate-risk`),
};

// Auth API
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),

  register: (data: { email: string; password: string; full_name?: string }) =>
    api.post('/auth/register', data),

  me: () => api.get('/auth/me'),
};

export default api;
