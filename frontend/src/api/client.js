const API_BASE = import.meta.env.VITE_API_URL || ''

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Error en la solicitud')
  }
  return res.json()
}

export const api = {
  health: () => request('/api/health'),
  info: () => request('/api/info'),
  scan: (body) =>
    request('/api/scan', { method: 'POST', body: JSON.stringify(body) }),
  listScans: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/scans${q ? `?${q}` : ''}`)
  },
  getScan: (id) => request(`/api/scans/${id}`),
  getHistory: (id) => request(`/api/scans/${id}/history`),
  deleteScan: (id) => request(`/api/scans/${id}`, { method: 'DELETE' }),
  exportJson: (id) => `${API_BASE}/api/reports/${id}/json`,
  exportCsv: (id) => `${API_BASE}/api/reports/${id}/csv`,
  exportPdf: (id) => `${API_BASE}/api/reports/${id}/pdf`,
}
