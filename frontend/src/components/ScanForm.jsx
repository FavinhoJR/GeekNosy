import { useEffect, useState } from 'react'
import { api } from '../api/client'

export default function ScanForm({ onScanComplete }) {
  const [domains, setDomains] = useState('')
  const [institution, setInstitution] = useState('')
  const [mode, setMode] = useState('standard')
  const [routeProfile, setRouteProfile] = useState('auto')
  const [includeExposure, setIncludeExposure] = useState(false)
  const [maxPaths, setMaxPaths] = useState(40)
  const [customPaths, setCustomPaths] = useState('')
  const [includeDefault, setIncludeDefault] = useState(true)
  const [routeInfo, setRouteInfo] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.info().then(setRouteInfo).catch(() => {})
  }, [])

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
        route_profile: routeProfile,
        include_default_paths: includeDefault,
        include_exposure_checks: includeExposure,
        max_paths_per_domain: Number(maxPaths) || 40,
        custom_paths: paths,
      })
      onScanComplete?.(results)
      setDomains('')
      setCustomPaths('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left Side: Domains & Institution */}
        <div className="space-y-5">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Institución (Opcional)
            </label>
            <input
              type="text"
              value={institution}
              onChange={(e) => setInstitution(e.target.value)}
              placeholder="Ej. Ministerio de Tecnología"
              className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none transition-all"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Dominios o URLs a evaluar
            </label>
            <textarea
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              rows={4}
              placeholder="example.com&#10;seguridad.gob.ar&#10;https://api.site.org"
              className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none transition-all font-mono leading-relaxed"
              required
            />
            <span className="text-[11px] text-slate-500 mt-1 block">
              Soporta múltiples líneas, separados por coma o punto y coma.
            </span>
          </div>
        </div>

        {/* Right Side: Options */}
        <div className="space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Modo de puntuación
              </label>
              <select
                value={mode}
                onChange={(e) => setMode(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none transition-all cursor-pointer"
              >
                <option value="standard" className="bg-slate-900">Estándar</option>
                <option value="advanced" className="bg-slate-900">Avanzado</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Perfil de rutas
              </label>
              <select
                value={routeProfile}
                onChange={(e) => setRouteProfile(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none transition-all cursor-pointer"
              >
                <option value="auto" className="bg-slate-900">Auto (Tecnología detectada)</option>
                <option value="minimal" className="bg-slate-900">Minimal (Solo Core)</option>
                <option value="standard" className="bg-slate-900">Standard (Core + Tech)</option>
                <option value="advanced" className="bg-slate-900">Advanced (Completo + API)</option>
                <option value="all" className="bg-slate-900">All (Todo sin restricción)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Máx. rutas por dominio
              </label>
              <input
                type="number"
                min={1}
                max={120}
                value={maxPaths}
                onChange={(e) => setMaxPaths(e.target.value)}
                className="w-full bg-slate-950/60 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none transition-all"
              />
            </div>
            <div className="flex flex-col justify-end gap-2.5 py-1">
              <label className="flex items-center gap-2.5 text-xs text-slate-350 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeDefault}
                  onChange={(e) => setIncludeDefault(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-800 bg-slate-950 text-blue-600 focus:ring-blue-500/20 focus:ring-offset-0 focus:ring-2"
                />
                Usar perfiles de rutas inteligente
              </label>
              <label className="flex items-center gap-2.5 text-xs text-amber-500/90 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={includeExposure}
                  onChange={(e) => setIncludeExposure(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-800 bg-slate-950 text-blue-600 focus:ring-blue-500/20 focus:ring-offset-0 focus:ring-2"
                />
                Checks de exposición sensible (.env, .git)
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Accordion detail for custom paths */}
      <details className="group border border-slate-800/80 bg-slate-950/30 rounded-xl overflow-hidden transition-all duration-300">
        <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-slate-400 hover:text-white uppercase tracking-wider select-none flex items-center justify-between">
          <span>Rutas personalizadas adicionales</span>
          <span className="transition-transform group-open:rotate-180 text-slate-500">▼</span>
        </summary>
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/50 space-y-3">
          {routeInfo?.route_profiles?.auto_mode && (
            <p className="text-slate-400 text-xs leading-relaxed">{routeInfo.route_profiles.auto_mode}</p>
          )}
          <textarea
            value={customPaths}
            onChange={(e) => setCustomPaths(e.target.value)}
            rows={3}
            placeholder="Escribe una ruta por línea. Ej:&#10;/admin-portal/&#10;/wp-content/uploads/&#10;/custom-api/v1/"
            className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/10 focus:outline-none font-mono"
          />
        </div>
      </details>

      {error && (
        <div className="text-red-400 text-xs bg-red-950/40 border border-red-900/60 p-3.5 rounded-xl">
          {error}
        </div>
      )}

      <div className="flex justify-end">
        <button
          type="submit"
          disabled={loading}
          className="w-full sm:w-auto px-8 py-3.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 active:scale-[0.98] disabled:opacity-50 text-white font-semibold rounded-xl transition-all shadow-lg shadow-blue-500/10 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Escaneando y evaluando...
            </>
          ) : (
            'Iniciar escaneo'
          )}
        </button>
      </div>
    </form>
  )
}
