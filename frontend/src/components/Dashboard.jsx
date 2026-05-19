import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { STATUS_LABELS, formatDate, formatDelta } from '../utils'
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
  const [statusFilter, setStatusFilter] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const params = {}
      if (search) params.search = search
      if (gradeFilter) params.grade = gradeFilter
      if (statusFilter) params.comparison_status = statusFilter
      const data = await api.listScans(params)
      setScans(data)
    } catch (err) {
      setScans([])
      setLoadError(err.message || 'No se pudieron cargar los escaneos')
    } finally {
      setLoading(false)
    }
  }, [search, gradeFilter, statusFilter, refreshKey])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end bg-white p-4 rounded-xl border border-slate-200">
        <div className="flex-1 min-w-[200px]">
          <label className="block text-xs font-medium text-slate-500 mb-1">Buscar institución/dominio</label>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar…"
            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1">Nota</label>
          <select
            value={gradeFilter}
            onChange={(e) => setGradeFilter(e.target.value)}
            className="border border-slate-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">Todas</option>
            {[10, 9, 8, 7, 6, 5, 4, 3, 2, 1].map((g) => (
              <option key={g} value={g}>{g}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1">Estado</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="border border-slate-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">Todos</option>
            <option value="greater">Mayor</option>
            <option value="less">Menor</option>
            <option value="equal">Igual</option>
          </select>
        </div>
        <button
          onClick={load}
          className="px-4 py-2 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg"
        >
          Actualizar
        </button>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-x-auto">
        {loadError && (
          <p className="p-4 m-4 text-red-600 bg-red-50 rounded-lg text-sm">{loadError}</p>
        )}
        {loading ? (
          <p className="p-8 text-center text-slate-500">Cargando escaneos…</p>
        ) : scans.length === 0 ? (
          <p className="p-8 text-center text-slate-500">No hay escaneos. Inicie uno nuevo.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gobs-700 text-white text-left">
                <th className="px-3 py-2 font-medium">Institución</th>
                <th className="px-3 py-2 font-medium">Dominio</th>
                <th className="px-3 py-2 font-medium">URL nota</th>
                <th className="px-3 py-2 font-medium">HTTP</th>
                <th className="px-3 py-2 font-medium">Ant.</th>
                <th className="px-3 py-2 font-medium">Actual</th>
                <th className="px-3 py-2 font-medium">Delta</th>
                {HEADER_KEYS.map((h) => (
                  <th key={h.key} className="px-2 py-2 font-medium text-center" title={h.short}>{h.short}</th>
                ))}
                <th className="px-2 py-2 font-medium text-center">Cookies</th>
                <th className="px-2 py-2 font-medium text-center">TLS</th>
                <th className="px-3 py-2 font-medium">Estado</th>
                <th className="px-3 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const status = STATUS_LABELS[scan.comparison_status]
                const checks = scan.header_checks || {}
                return (
                  <tr key={scan.id} className="border-t border-slate-100 hover:bg-slate-50">
                    <td className="px-3 py-2">{scan.institution || '—'}</td>
                    <td className="px-3 py-2 font-medium">{scan.domain}</td>
                    <td className="px-3 py-2 max-w-[180px] truncate font-mono text-xs" title={scan.scoring_url}>
                      {scan.scoring_url ? new URL(scan.scoring_url).pathname || '/' : '—'}
                    </td>
                    <td className="px-3 py-2 text-center">{scan.scoring_http_code ?? '—'}</td>
                    <td className="px-3 py-2 text-center">
                      {scan.previous_score != null ? scan.previous_score.toFixed(1) : '—'}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <GradeBadge grade={scan.overall_grade} size="sm" />
                        <span>{scan.overall_score.toFixed(1)}</span>
                      </div>
                    </td>
                    <td className={`px-3 py-2 text-center font-medium ${
                      scan.comparison_status === 'greater' ? 'text-emerald-600' :
                      scan.comparison_status === 'less' ? 'text-red-600' : ''
                    }`}>
                      {formatDelta(scan.score_delta)}
                    </td>
                    {HEADER_KEYS.map((h) => (
                      <td key={h.key} className="px-2 py-2 text-center">
                        <HeaderCheck present={checks[h.key]} label={h.short} points={h.points} />
                      </td>
                    ))}
                    <td className="px-2 py-2 text-center">
                      {scan.cookies_ok === null ? (
                        <span className="text-slate-300">—</span>
                      ) : scan.cookies_ok ? (
                        <span className="text-emerald-600">✓</span>
                      ) : (
                        <span className="w-2 h-2 inline-block rounded-full bg-slate-300" />
                      )}
                    </td>
                    <td className="px-2 py-2 text-center">
                      {scan.tls_ok ? (
                        <span className="text-emerald-600">✓</span>
                      ) : (
                        <span className="w-2 h-2 inline-block rounded-full bg-slate-300" />
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {status ? (
                        <span className={`text-xs px-2 py-0.5 rounded-full ${status.class}`}>
                          {status.label}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-xs">Primer escaneo</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <Link
                        to={`/scan/${scan.id}`}
                        className="text-gobs-600 hover:underline text-xs font-medium"
                      >
                        Detalle
                      </Link>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-slate-400 text-center">
        La nota se calcula solo con la URL marcada como fuente (sitio principal). Rutas 403/404 se evalúan por separado.
      </p>
    </div>
  )
}
