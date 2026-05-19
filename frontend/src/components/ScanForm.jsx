import { useState } from 'react'
import { api } from '../api/client'

const DEFAULT_PATHS = [
  '/',
  '/web/',
  '/administrator/',
  '/web/administrator/',
  '/component/users',
  '/web/component/users',
  '/web/index.php/component/users',
]

export default function ScanForm({ onScanComplete }) {
  const [domains, setDomains] = useState('')
  const [institution, setInstitution] = useState('')
  const [mode, setMode] = useState('standard')
  const [customPaths, setCustomPaths] = useState('')
  const [includeDefault, setIncludeDefault] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError(null)
    const domainList = domains
      .split(/[\n,;]+/)
      .map((d) => d.trim())
      .filter(Boolean)
    if (!domainList.length) {
      setError('Ingrese al menos un dominio')
      return
    }
    const paths = customPaths
      .split('\n')
      .map((p) => p.trim())
      .filter(Boolean)
      setLoading(true)
    try {
      const results = await api.scan({
        domains: domainList,
        institution: institution || null,
        mode,
        custom_paths: paths,
        include_default_paths: includeDefault,
      })
      onScanComplete?.(results)
      setDomains('')
      setCustomPaths('')
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-xl shadow-sm border border-slate-200 p-6 space-y-4">
      <h2 className="text-lg font-semibold text-gobs-700">Nuevo escaneo</h2>
      <p className="text-sm text-slate-500">
        Evaluación defensiva no intrusiva. Solo dominios autorizados.
      </p>

      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">
          Institución (opcional)
        </label>
        <input
          type="text"
          value={institution}
          onChange={(e) => setInstitution(e.target.value)}
          placeholder="Ej: Ministerio de Ejemplo"
          className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-gobs-500 focus:border-gobs-500"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">
          Dominios o URLs (uno por línea o separados por coma)
        </label>
        <textarea
          value={domains}
          onChange={(e) => setDomains(e.target.value)}
          rows={3}
          placeholder="ejemplo.gob.mx&#10;https://otro.ejemplo.gob.mx"
          className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono focus:ring-2 focus:ring-gobs-500"
          required
        />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Modo de puntuación</label>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="standard">Estándar (SSL 45% + Headers 55%)</option>
            <option value="advanced">Avanzado (SSL 30% + Headers 40% + Cookies 10% + DNS 10% + Consistencia 10%)</option>
          </select>
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeDefault}
              onChange={(e) => setIncludeDefault(e.target.checked)}
              className="rounded border-slate-300 text-gobs-600"
            />
            Incluir rutas por defecto
          </label>
        </div>
      </div>

      <details className="text-sm">
        <summary className="cursor-pointer text-gobs-600 font-medium">Rutas por defecto y personalizadas</summary>
        <div className="mt-2 p-3 bg-slate-50 rounded-lg">
          <p className="text-slate-600 mb-2">Rutas evaluadas por defecto:</p>
          <ul className="font-mono text-xs text-slate-500 space-y-1 mb-3">
            {DEFAULT_PATHS.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
          <label className="block text-sm font-medium text-slate-700 mb-1">
            Rutas personalizadas (una por línea)
          </label>
          <textarea
            value={customPaths}
            onChange={(e) => setCustomPaths(e.target.value)}
            rows={2}
            placeholder="/api/public&#10;/portal/"
            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono"
          />
        </div>
      </details>

      {error && (
        <p className="text-red-600 text-sm bg-red-50 p-2 rounded">{error}</p>
      )}

      <button
        type="submit"
        disabled={loading}
        className="w-full sm:w-auto px-6 py-2.5 bg-gobs-600 hover:bg-gobs-700 disabled:opacity-50 text-white font-medium rounded-lg transition"
      >
        {loading ? 'Escaneando…' : 'Iniciar escaneo'}
      </button>
    </form>
  )
}
