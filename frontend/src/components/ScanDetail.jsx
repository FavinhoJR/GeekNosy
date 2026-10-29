import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { RESPONSE_TYPE_LABELS, formatDate } from '../utils'
import GradeBadge from './GradeBadge'
import HeaderCheck from './HeaderCheck'

const HEADER_LIST = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
]

export default function ScanDetail() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [history, setHistory] = useState([])
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [exportError, setExportError] = useState(null)

  const handleExport = async (format) => {
    setExportError(null)
    try {
      await api.downloadReport(id, format)
    } catch (error) {
      setExportError(error.message)
    }
  }

  useEffect(() => {
    async function load() {
      setLoading(true)
      try {
        const [s, h, f] = await Promise.all([
          api.getScan(id),
          api.getHistory(id),
          api.listFindings(id),
        ])
        setScan(s)
        setHistory(h)
        setFindings(f)
      } catch {
        setScan(null)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  if (loading) {
    return (
      <div className="py-24 text-center text-slate-600 text-sm flex flex-col items-center justify-center gap-3">
        <svg className="animate-spin h-6 w-6 text-blue-500" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span>Cargando detalle del escaneo...</span>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="py-16 text-center text-red-400 bg-red-950/20 border border-red-900/40 rounded-xl max-w-xl mx-auto p-6">
        <p className="font-bold text-lg mb-1">Escaneo no encontrado</p>
        <p className="text-sm text-slate-600 mb-4">El análisis solicitado no existe o fue eliminado.</p>
        <Link to="/" className="text-orange-700 hover:text-blue-800 font-semibold text-sm hover:underline">
          Volver al dashboard
        </Link>
      </div>
    )
  }

  const scoringResult = scan.results?.find((r) => r.is_scoring_source)

  const updateTriage = async (fingerprint, status) => {
    const updated = await api.updateFinding(scan.id, fingerprint, { status, notes: null })
    setFindings((items) => items.map((item) => (
      item.fingerprint === fingerprint ? updated : item
    )))
  }

  return (
    <div className="scan-detail space-y-8 max-w-5xl mx-auto py-2">
      <Link to="/" className="inline-flex items-center gap-1.5 text-orange-700 hover:text-orange-900 text-sm font-semibold hover:underline">
        <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="m14 6-6 6 6 6" /></svg>
        Volver al panel
      </Link>

      {/* Main Score Card */}
      <div className="bg-white border border-stone-300 rounded-xl p-6 sm:p-8 space-y-6 relative overflow-hidden">

        <div className="flex flex-wrap items-start justify-between gap-6 relative">
          <div className="space-y-1">
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-950 tracking-tight">{scan.domain}</h1>
            {scan.institution && <p className="text-slate-600 text-sm">{scan.institution}</p>}
            <p className="text-xs text-slate-600">{formatDate(scan.created_at)} · Modo de puntuación: {scan.mode}</p>
          </div>
          <div className="flex items-center gap-4 bg-stone-100 p-4 rounded-xl border border-stone-200">
            <GradeBadge grade={scan.overall_grade} size="lg" />
            <div>
              <p className="text-2xl sm:text-3xl font-black text-slate-950">{scan.overall_score.toFixed(1)}</p>
              <p className="text-[11px] text-slate-600 uppercase tracking-wider font-semibold">Puntuación / 100</p>
            </div>
          </div>
        </div>

        {/* Scoring Source Details */}
        <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl text-xs sm:text-sm text-blue-800 font-mono">
          <strong>URL de calificación:</strong>{' '}
          <code className="text-orange-700 font-bold">{scan.scoring_url}</code>
          {' '}(HTTP <strong>{scan.scoring_http_code}</strong>
          {scoringResult && ` — ${RESPONSE_TYPE_LABELS[scoringResult.response_type] || scoringResult.response_type}`})
        </div>

        {scan.score_explanation && (
          <p className="text-sm text-slate-600 leading-relaxed border border-stone-300 bg-stone-50 p-4">
            {scan.score_explanation}
          </p>
        )}

        {/* Actions bar */}
        <div className="flex flex-wrap gap-2.5 pt-2 border-t border-stone-300/80">
          {['json', 'csv', 'pdf', 'jsonl', 'sarif', 'sbom', 'markdown', 'html'].map((format) => (
            <button
              key={format}
              onClick={() => handleExport(format)}
              className="px-4 py-2 text-xs font-semibold uppercase bg-stone-100 hover:bg-slate-800 hover:text-white border border-stone-400/30 text-slate-900 rounded-lg transition-all"
            >
              {format}
            </button>
          ))}
        </div>
        {exportError && <p className="text-xs text-red-400">{exportError}</p>}

        {/* Sub-Scores Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 pt-2 text-center">
          {[
            ['TLS/SSL', scan.tls_score],
            ['Headers', scan.headers_score],
            ['Cookies', scan.cookies_score],
            ['DNS', scan.dns_score],
            ['Consistencia', scan.consistency_score],
          ].map(([label, score]) => (
            <div key={label} className="bg-stone-100 border border-stone-200 rounded-xl p-3.5">
              <p className="text-slate-600 text-[10px] uppercase font-semibold tracking-wider mb-1">{label}</p>
              <p className="text-lg font-bold text-slate-950">{score?.toFixed(1)}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tech Detection & Route selection */}
      {(scan.tech_detection || scan.route_selection) && (
        <div className="grid sm:grid-cols-2 gap-6">
          <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
            <h3 className="font-bold text-slate-950 text-base">Tecnología Detectada</h3>
            <div className="space-y-2">
              <p className="text-slate-700 text-sm">
                {scan.tech_detection?.technologies?.length
                  ? scan.tech_detection.technologies.join(', ')
                  : 'Ninguna tecnología detectada. Usando perfiles básicos.'}
              </p>
              <p className="text-xs text-slate-600">
                La detección ajusta inteligentemente las rutas de escaneo según el servidor web detectado.
              </p>
            </div>
          </div>

          <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
            <h3 className="font-bold text-slate-950 text-base">Perfil de Rutas</h3>
            <div className="space-y-1 text-sm text-slate-700">
              <p>
                Perfil configurado: <strong className="text-slate-950">{scan.route_profile || scan.route_selection?.route_profile}</strong>
              </p>
              <p>
                Efectivo: <span className="text-slate-950">{scan.route_selection?.effective_profile}</span>
              </p>
              <p className="text-xs text-slate-600 pt-1 leading-relaxed">
                Rutas seleccionadas: {scan.route_selection?.selected_profiles?.join(', ')} (Total: {scan.route_selection?.total_selected} rutas evaluadas)
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Historical logs without comparison status */}
      {history.length > 1 && (
        <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
          <h2 className="font-bold text-slate-950 text-lg">Historial de Análisis</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="text-slate-600 border-b border-stone-300 text-left text-xs uppercase tracking-wider">
                  <th className="py-2.5 font-semibold">Fecha de escaneo</th>
                  <th className="py-2.5 font-semibold">Calificación</th>
                  <th className="py-2.5 font-semibold">Nota</th>
                  <th className="py-2.5 font-semibold">URL calificada</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {history.map((h) => (
                  <tr key={h.id} className={`hover:bg-stone-100 ${h.id === scan.id ? 'bg-blue-50' : ''}`}>
                    <td className="py-3 text-slate-800">{formatDate(h.created_at)}</td>
                    <td className="py-3 font-bold text-slate-950">{h.overall_score.toFixed(1)}</td>
                    <td className="py-3"><GradeBadge grade={h.overall_grade} size="sm" /></td>
                    <td className="py-3 font-mono text-xs text-slate-600 truncate max-w-[280px]" title={h.scoring_url}>
                      {h.scoring_url}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Detailed Routes Evaluated */}
      <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
        <h2 className="font-bold text-slate-950 text-lg">Detalle de Rutas Evaluadas</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-600 border-b border-stone-300 text-left text-xs uppercase tracking-wider">
                <th className="py-3 pr-2 font-semibold">Ruta / URL</th>
                <th className="py-3 font-semibold">Perfil</th>
                <th className="py-3 font-semibold">HTTP</th>
                <th className="py-3 font-semibold">Tipo</th>
                <th className="py-3 font-semibold">Severidad</th>
                <th className="py-3 font-semibold">Nota</th>
                <th className="py-3 font-semibold">Headers</th>
                <th className="py-3 font-semibold">Hallazgo</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40">
              {scan.results?.map((r) => (
                <tr
                  key={r.id}
                  className={`text-xs hover:bg-stone-100 ${r.is_scoring_source ? 'bg-emerald-950/20' : ''}`}
                >
                  <td className="py-3.5 pr-3 font-mono max-w-[200px] truncate text-slate-900" title={r.url_evaluated}>
                    {r.path || r.url_evaluated}
                    {r.is_scoring_source && (
                      <span className="ml-2 bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider">
                        Nota
                      </span>
                    )}
                  </td>
                  <td className="py-3.5 text-slate-600 font-semibold">{r.profile}</td>
                  <td className="py-3.5 text-slate-800 font-mono">{r.http_code}</td>
                  <td className="py-3.5">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                      r.response_type === 'blocked' ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400' :
                      r.response_type === 'not_found' ? 'bg-slate-800 text-slate-600' :
                      r.response_type === 'redirect' ? 'bg-blue-500/10 border border-blue-500/20 text-orange-700' :
                      'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                    }`}>
                      {RESPONSE_TYPE_LABELS[r.response_type] || r.response_type}
                    </span>
                  </td>
                  <td className="py-3.5">
                    {r.severity ? (
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                        r.severity === 'critical' ? 'bg-red-500/10 border border-red-500/20 text-red-400' :
                        r.severity === 'high' ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400' :
                        r.severity === 'medium' ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400' :
                        'bg-slate-800 text-slate-600'
                      }`}>{r.severity}</span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="py-3.5 text-slate-600">{r.is_scoring_source ? 'Sí' : 'No'}</td>
                  <td className="py-3.5">
                    <div className="flex gap-1.5">
                      {HEADER_LIST.slice(0, 4).map((h) => (
                        <HeaderCheck key={h} present={h in (r.headers || {})} label={h} />
                      ))}
                    </div>
                  </td>
                  <td className="py-3.5 text-amber-400 max-w-[160px] truncate" title={r.recommendation?.title}>
                    {r.recommendation?.title || r.notes || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recommendations */}
      {findings.length > 0 && (
        <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
          <h2 className="font-bold text-slate-950 text-lg">Triage de Hallazgos</h2>
          <div className="space-y-3">
            {findings.map((finding) => (
              <div key={finding.fingerprint} className="grid gap-3 rounded-xl border border-stone-300 bg-stone-100/30 p-4 sm:grid-cols-[1fr_170px] sm:items-center">
                <div>
                  <p className="font-semibold text-slate-950">{finding.title}</p>
                  <p className="text-xs text-slate-600">
                    {finding.severity} · confianza {finding.confidence} · {finding.id}
                  </p>
                </div>
                <select
                  value={finding.status}
                  onChange={(event) => updateTriage(finding.fingerprint, event.target.value)}
                  className="rounded-lg border border-stone-400 bg-stone-100 px-3 py-2 text-xs text-slate-900"
                >
                  <option value="new">Nuevo</option>
                  <option value="confirmed">Confirmado</option>
                  <option value="false_positive">Falso positivo</option>
                  <option value="accepted">Riesgo aceptado</option>
                  <option value="resolved">Resuelto</option>
                </select>
              </div>
            ))}
          </div>
        </div>
      )}

      {scan.recommendations?.length > 0 && (
        <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-4">
          <h2 className="font-bold text-slate-950 text-lg">Recomendaciones de Seguridad</h2>
          <ul className="space-y-4">
            {scan.recommendations.map((rec) => (
              <li key={rec.id} className="border border-stone-300 bg-stone-50 p-4 rounded-xl space-y-1.5">
                <p className="font-bold text-slate-950 text-sm sm:text-base">{rec.title}</p>
                <p className="text-xs sm:text-sm text-slate-600 leading-relaxed">{rec.recommendation}</p>
                <span className={`text-[10px] font-bold uppercase tracking-wider inline-block px-2.5 py-0.5 rounded-full ${
                  rec.severity === 'critical' ? 'bg-red-500/10 border border-red-500/20 text-red-400' :
                  rec.severity === 'high' ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400' :
                  'bg-slate-800 text-slate-600'
                }`}>{rec.severity}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* TLS Raw Evidence */}
      {scan.tls_evidence && (
        <div className="bg-white border border-stone-300 rounded-xl p-6 space-y-3">
          <h2 className="font-bold text-slate-950 text-lg">Evidencia SSL/TLS Recibida</h2>
          <pre className="text-xs bg-stone-100 border border-stone-200 p-4 rounded-xl overflow-x-auto font-mono text-slate-700 leading-relaxed">
            {JSON.stringify(scan.tls_evidence, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
