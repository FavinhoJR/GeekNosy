const API_BASE = import.meta.env.VITE_API_URL || ''
const getApiKey = () => sessionStorage.getItem('datagobs_api_key') || ''

async function request(path, options = {}) {
  const apiKey = getApiKey()
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { 'X-API-Key': apiKey } : {}),
      ...options.headers,
    },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || 'Error en la solicitud')
  }
  return res.json()
}

export const api = {
  setApiKey: (value) => {
    if (value) sessionStorage.setItem('datagobs_api_key', value)
    else sessionStorage.removeItem('datagobs_api_key')
  },
  hasApiKey: () => Boolean(getApiKey()),
  health: () => request('/api/health'),
  info: () => request('/api/info'),
  scan: (body) =>
    request('/api/scan', { method: 'POST', body: JSON.stringify(body) }),
  createJob: (scanRequest) =>
    request('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({ request: scanRequest }),
    }),
  listJobs: () => request('/api/jobs'),
  getJob: (id) => request(`/api/jobs/${id}`),
  cancelJob: (id) => request(`/api/jobs/${id}/cancel`, { method: 'POST' }),
  retryJob: (id) => request(`/api/jobs/${id}/retry`, { method: 'POST' }),
  deleteJob: (id) => request(`/api/jobs/${id}`, { method: 'DELETE' }),
  createSchedule: (body) =>
    request('/api/schedules', { method: 'POST', body: JSON.stringify(body) }),
  listSchedules: () => request('/api/schedules'),
  updateSchedule: (id, enabled) =>
    request(`/api/schedules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    }),
  deleteSchedule: (id) => request(`/api/schedules/${id}`, { method: 'DELETE' }),
  listFindings: (scanId) => request(`/api/scans/${scanId}/findings`),
  updateFinding: (scanId, fingerprint, body) =>
    request(`/api/scans/${scanId}/findings/${fingerprint}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
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
  async downloadReport(id, format) {
    const apiKey = getApiKey()
    const res = await fetch(`${API_BASE}/api/reports/${id}/${format}`, {
      headers: apiKey ? { 'X-API-Key': apiKey } : {},
    })
    if (!res.ok) throw new Error('No se pudo exportar el reporte')
    const blob = await res.blob()
    const disposition = res.headers.get('content-disposition') || ''
    const match = disposition.match(/filename="([^"]+)"/)
    const filename = match?.[1] || `datagobs-${id}.${format}`
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
  },
}
