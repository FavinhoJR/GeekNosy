import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { RESPONSE_TYPE_LABELS, STATUS_LABELS, formatDate, formatDelta } from '../utils'
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
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      setLoading(true)
      try {
        const [s, h] = await Promise.all([api.getScan(id), api.getHistory(id)])
        setScan(s)
        setHistory(h)
      } catch {
        setScan(null)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  if (loading) return <p className="text-center py-12 text-slate-500">Cargando…</p>
  if (!scan) return <p className="text-center py-12 text-red-500">Escaneo no encontrado</p>

  const status = STATUS_LABELS[scan.comparison_status]
  const scoringResult = scan.results?.find((r) => r.is_scoring_source)

  return (
    <div className="space-y-6">
      <Link to="/" className="text-gobs-600 hover:underline text-sm">← Volver al dashboard</Link>

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-gobs-800">{scan.domain}</h1>
            {scan.institution && <p className="text-slate-600">{scan.institution}</p>}
            <p className="text-sm text-slate-500 mt-1">{formatDate(scan.created_at)} · Modo {scan.mode}</p>
          </div>
          <div className="flex items-center gap-4">
            <GradeBadge grade={scan.overall_grade} size="lg" />
            <div>
              <p className="text-3xl font-bold">{scan.overall_score.toFixed(1)}</p>
              <p className="text-sm text-slate-500">{scan.overall_score.toFixed(1)} / 100 · escala 1-10</p>
            </div>
          </div>
        </div>

        <div className="mt-4 p-4 bg-blue-50 border border-blue-100 rounded-lg text-sm">
          <strong>URL usada para la nota:</strong>{' '}
          <code className="text-gobs-700">{scan.scoring_url}</code>
          {' '}(HTTP <strong>{scan.scoring_http_code}</strong>
          {scoringResult && ` — ${RESPONSE_TYPE_LABELS[scoringResult.response_type] || scoringResult.response_type}`})
        </div>

        {status && (
          <div className={`mt-3 inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm ${status.class}`}>
            {status.label} · Delta {formatDelta(scan.score_delta)}
            {scan.previous_score != null && ` (antes: ${scan.previous_score.toFixed(1)})`}
          </div>
        )}

        {scan.score_explanation && (
          <p className="mt-3 text-sm text-slate-600">{scan.score_explanation}</p>
        )}

        <div className="mt-4 flex flex-wrap gap-2">
          <a href={api.exportJson(scan.id)} className="px-3 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg">JSON</a>
          <a href={api.exportCsv(scan.id)} className="px-3 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg">CSV</a>
          <a href={api.exportPdf(scan.id)} className="px-3 py-1.5 text-sm bg-slate-100 hover:bg-slate-200 rounded-lg">PDF</a>
        </div>

        <div className="mt-6 grid grid-cols-2 sm:grid-cols-5 gap-3 text-center text-sm">
          {[
            ['TLS', scan.tls_score],
            ['Headers', scan.headers_score],
            ['Cookies', scan.cookies_score],
            ['DNS', scan.dns_score],
            ['Consistencia', scan.consistency_score],
          ].map(([label, score]) => (
            <div key={label} className="bg-slate-50 rounded-lg p-3">
              <p className="text-slate-500 text-xs">{label}</p>
              <p className="text-lg font-semibold">{score?.toFixed(1)}</p>
            </div>
          ))}
        </div>
      </div>

      {history.length > 1 && (
        <div className="bg-white rounded-xl border border-slate-200 p-6">
          <h2 className="font-semibold text-gobs-700 mb-3">Historial comparativo</h2>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-500 border-b">
                <th className="text-left py-2">Fecha</th>
                <th className="text-left py-2">Puntaje</th>
                <th className="text-left py-2">Nota</th>
                <th className="text-left py-2">URL nota</th>
                <th className="text-left py-2">Estado</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h) => (
                <tr key={h.id} className={`border-b border-slate-50 ${h.id === scan.id ? 'bg-blue-50' : ''}`}>
                  <td className="py-2">{formatDate(h.created_at)}</td>
                  <td className="py-2 font-medium">{h.overall_score.toFixed(1)}</td>
                  <td className="py-2"><GradeBadge grade={h.overall_grade} size="sm" /></td>
                  <td className="py-2 font-mono text-xs truncate max-w-[200px]">{h.scoring_url}</td>
                  <td className="py-2">
                    {STATUS_LABELS[h.comparison_status]?.label || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <h2 className="font-semibold text-gobs-700 mb-3">Rutas evaluadas</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-500 border-b text-left">
                <th className="py-2 pr-4">URL</th>
                <th className="py-2">HTTP</th>
                <th className="py-2">Tipo</th>
                <th className="py-2">Nota fuente</th>
                <th className="py-2">Headers</th>
                <th className="py-2">Notas</th>
              </tr>
            </thead>
            <tbody>
              {scan.results?.map((r) => (
                <tr
                  key={r.id}
                  className={`border-b border-slate-50 ${r.is_scoring_source ? 'bg-emerald-50/50' : ''}`}
                >
                  <td className="py-2 pr-4 font-mono text-xs max-w-[280px] truncate" title={r.url_evaluated}>
                    {r.url_evaluated}
                    {r.is_scoring_source && (
                      <span className="ml-1 text-xs bg-emerald-100 text-emerald-700 px-1 rounded">NOTA</span>
                    )}
                  </td>
                  <td className="py-2">{r.http_code}</td>
                  <td className="py-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      r.response_type === 'blocked' ? 'bg-amber-100 text-amber-800' :
                      r.response_type === 'not_found' ? 'bg-slate-100 text-slate-600' :
                      r.response_type === 'redirect' ? 'bg-blue-100 text-blue-700' :
                      'bg-emerald-100 text-emerald-700'
                    }`}>
                      {RESPONSE_TYPE_LABELS[r.response_type] || r.response_type}
                    </span>
                  </td>
                  <td className="py-2">{r.is_scoring_source ? 'Sí' : '—'}</td>
                  <td className="py-2">
                    <div className="flex gap-1 flex-wrap">
                      {HEADER_LIST.slice(0, 6).map((h) => (
                        <HeaderCheck key={h} present={h in (r.headers || {})} label={h} />
                      ))}
                    </div>
                  </td>
                  <td className="py-2 text-xs text-amber-700 max-w-[200px]">{r.notes || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {scan.recommendations?.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-6">
          <h2 className="font-semibold text-gobs-700 mb-3">Recomendaciones</h2>
          <ul className="space-y-3">
            {scan.recommendations.map((rec) => (
              <li key={rec.id} className="border-l-4 border-gobs-500 pl-4">
                <p className="font-medium text-slate-800">{rec.title}</p>
                <p className="text-sm text-slate-600 mt-1">{rec.recommendation}</p>
                <span className={`text-xs mt-1 inline-block px-2 py-0.5 rounded ${
                  rec.severity === 'critical' ? 'bg-red-100 text-red-700' :
                  rec.severity === 'high' ? 'bg-orange-100 text-orange-700' :
                  'bg-slate-100 text-slate-600'
                }`}>{rec.severity}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {scan.tls_evidence && (
        <div className="bg-white rounded-xl border border-slate-200 p-6">
          <h2 className="font-semibold text-gobs-700 mb-3">Evidencia TLS</h2>
          <pre className="text-xs bg-slate-50 p-4 rounded-lg overflow-x-auto">
            {JSON.stringify(scan.tls_evidence, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
