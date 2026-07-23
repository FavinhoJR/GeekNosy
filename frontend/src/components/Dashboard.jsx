import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { formatDate } from '../utils'
import GradeBadge from './GradeBadge'
import HeaderCheck from './HeaderCheck'

const HEADER_KEYS = [
  { key: 'strict-transport-security', short: 'HSTS', points: 15 },
  { key: 'content-security-policy', short: 'CSP', points: 15 },
  { key: 'x-frame-options', short: 'XFO', points: 10 },
  { key: 'x-content-type-options', short: 'XCT', points: 10 },
  { key: 'referrer-policy', short: 'RP', points: 5 },
  { key: 'permissions-policy', short: 'PP', points: 5 },
]

export default function Dashboard({ refreshKey }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [search, setSearch] = useState('')
  const [gradeFilter, setGradeFilter] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const params = {}
      if (search) params.search = search
      if (gradeFilter) params.grade = gradeFilter
      const data = await api.listScans(params)
      setScans(data)
    } catch (err) {
      setScans([])
      setLoadError(err.message || 'No se pudieron cargar los escaneos')
    } finally {
      setLoading(false)
    }
  }, [search, gradeFilter, refreshKey])

  useEffect(() => {
    load()
  }, [load])

  const handleDelete = async (id) => {
    if (!window.confirm('¿Está seguro de que desea eliminar este escaneo?')) {
      return
    }
    try {
      await api.deleteScan(id)
      load()
    } catch (err) {
      alert(err.message || 'No se pudo eliminar el escaneo')
    }
  }

  return (
    <div className="space-y-6">
      {/* Filters Bar */}
      <div className="flex flex-wrap gap-4 items-end bg-slate-950/40 p-4 rounded-2xl border border-slate-800/80">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Buscar institución/dominio
          </label>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Ej. Gob, domain.com..."
            className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-100 placeholder-slate-600 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/10 transition-all"
          />
        </div>
        <div>
          <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
            Nota Mínima
          </label>
          <select
            value={gradeFilter}
            onChange={(e) => setGradeFilter(e.target.value)}
            className="bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/10 transition-all cursor-pointer"
          >
            <option value="" className="bg-slate-900">Todas</option>
            {[10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map((g) => (
              <option key={g} value={g} className="bg-slate-900">{g}</option>
            ))}
          </select>
        </div>
        <button
          onClick={load}
          className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-semibold rounded-xl transition-all cursor-pointer active:scale-[0.97]"
        >
          Actualizar
        </button>
      </div>

      {/* Scans Table Container */}
      <div className="bg-slate-950/20 rounded-2xl border border-slate-800/80 overflow-hidden shadow-inner">
        {loadError && (
          <div className="p-4 m-4 text-red-400 bg-red-950/30 border border-red-900/40 rounded-xl text-sm">
            {loadError}
          </div>
        )}
        {loading ? (
          <div className="py-16 text-center text-slate-500 text-sm flex flex-col items-center justify-center gap-3">
            <svg className="animate-spin h-6 w-6 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span>Cargando escaneos realizados...</span>
          </div>
        ) : scans.length === 0 ? (
          <div className="py-16 text-center text-slate-500 text-sm">
            No hay escaneos realizados. Inicie un nuevo análisis arriba.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="bg-slate-950/60 border-b border-slate-800 text-slate-400 text-left text-xs uppercase tracking-wider">
                  <th className="px-4 py-3 font-semibold">Institución</th>
                  <th className="px-4 py-3 font-semibold">Dominio</th>
                  <th className="px-4 py-3 font-semibold">Intensidad</th>
                  <th className="px-4 py-3 font-semibold">URL nota</th>
                  <th className="px-4 py-3 font-semibold text-center">HTTP</th>
                  <th className="px-4 py-3 font-semibold">Nota</th>
                  {HEADER_KEYS.map((h) => (
                    <th key={h.key} className="px-2 py-3 font-semibold text-center text-[10px]" title={h.short}>
                      {h.short}
                    </th>
                  ))}
                  <th className="px-2 py-3 font-semibold text-center">Cookies</th>
                  <th className="px-2 py-3 font-semibold text-center">TLS</th>
                  <th className="px-4 py-3 font-semibold text-right">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {scans.map((scan) => {
                  const checks = scan.header_checks || {}
                  return (
                    <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="px-4 py-3.5 text-slate-350">{scan.institution || '—'}</td>
                      <td className="px-4 py-3.5 font-bold text-white tracking-tight">{scan.domain}</td>
                      <td className="px-4 py-3.5 text-xs text-cyan-400 font-semibold">{scan.intensity || 'standard'}</td>
                      <td className="px-4 py-3.5 max-w-[180px] truncate font-mono text-xs text-slate-400" title={scan.scoring_url}>
                        {scan.scoring_url ? new URL(scan.scoring_url).pathname || '/' : '—'}
                      </td>
                      <td className="px-4 py-3.5 text-center font-mono text-xs text-slate-400">
                        {scan.scoring_http_code ?? '—'}
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-2">
                          <GradeBadge grade={scan.overall_grade} size="sm" />
                          <span className="text-white font-semibold">{scan.overall_score.toFixed(1)}</span>
                        </div>
                      </td>
                      {HEADER_KEYS.map((h) => (
                        <td key={h.key} className="px-2 py-3.5 text-center">
                          <HeaderCheck present={checks[h.key]} label={h.short} points={h.points} />
                        </td>
                      ))}
                      <td className="px-2 py-3.5 text-center">
                        {scan.cookies_ok === null ? (
                          <span className="text-slate-600">—</span>
                        ) : scan.cookies_ok ? (
                          <span className="text-emerald-500 font-bold">✓</span>
                        ) : (
                          <span className="w-1.5 h-1.5 inline-block rounded-full bg-slate-700" />
                        )}
                      </td>
                      <td className="px-2 py-3.5 text-center">
                        {scan.tls_ok ? (
                          <span className="text-emerald-500 font-bold">✓</span>
                        ) : (
                          <span className="w-1.5 h-1.5 inline-block rounded-full bg-slate-700" />
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-right">
                        <div className="flex items-center justify-end gap-4">
                          <Link
                            to={`/scan/${scan.id}`}
                            className="text-blue-400 hover:text-blue-300 font-semibold text-xs hover:underline"
                          >
                            Detalle
                          </Link>
                          <button
                            onClick={() => handleDelete(scan.id)}
                            className="text-red-400 hover:text-red-300 font-semibold text-xs hover:underline cursor-pointer"
                          >
                            Borrar
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-[11px] text-slate-500 text-center leading-relaxed">
        La nota se calcula exclusivamente a partir del sitio principal (respuesta 200). Las rutas 403 y 404 se auditan y reportan individualmente.
      </p>
    </div>
  )
}
