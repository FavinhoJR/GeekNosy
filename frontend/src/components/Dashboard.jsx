import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { formatDate } from '../utils'

function Score({ value }) {
  const score = Number(value || 0)
  const tone = score >= 80 ? 'good' : score >= 55 ? 'watch' : 'risk'
  return <span className={`score-label is-${tone}`}><strong>{score.toFixed(0)}</strong><small>/100</small></span>
}

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
      if (search.trim()) params.search = search.trim()
      if (gradeFilter) params.grade = gradeFilter
      setScans(await api.listScans(params))
    } catch (error) {
      setScans([])
      setLoadError(error.message || 'No se pudo recuperar el historial.')
    } finally {
      setLoading(false)
    }
  }, [search, gradeFilter, refreshKey])

  useEffect(() => { load() }, [load])

  const handleDelete = async (scan) => {
    if (!window.confirm(`Eliminar el análisis de ${scan.domain}? Esta acción no se puede deshacer.`)) return
    try { await api.deleteScan(scan.id); load() } catch (error) { setLoadError(error.message) }
  }

  return (
    <div className="scan-history">
      <div className="history-toolbar">
        <div className="field-group"><label htmlFor="history-search">Buscar</label><input id="history-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Dominio, cliente o programa" /></div>
        <div className="field-group"><label htmlFor="history-grade">Nota</label><select id="history-grade" value={gradeFilter} onChange={(event) => setGradeFilter(event.target.value)}><option value="">Todas</option>{[10,9,8,7,6,5,4,3,2,1].map((grade) => <option key={grade} value={grade}>{grade}</option>)}</select></div>
        <button type="button" className="secondary-action" onClick={load}>Actualizar lista</button>
      </div>

      {loadError && <div className="form-error" role="alert">{loadError}</div>}
      {loading ? (
        <div className="history-state" role="status"><span className="loading-line" />Recuperando evaluaciones…</div>
      ) : scans.length === 0 ? (
        <div className="history-state"><strong>Aún no hay evidencia almacenada.</strong><span>Cree un análisis arriba; los resultados aparecerán aquí al finalizar.</span></div>
      ) : (
        <div className="history-table-wrap">
          <table className="history-table">
            <thead><tr><th>Objetivo</th><th>Perfil</th><th>Fecha</th><th>Estado HTTP</th><th>Puntuación</th><th><span className="sr-only">Acciones</span></th></tr></thead>
            <tbody>{scans.map((scan) => (
              <tr key={scan.id}>
                <td><strong>{scan.domain}</strong><span>{scan.institution || 'Sin cliente asociado'}</span></td>
                <td><span className="table-tag">{scan.intensity || 'standard'}</span><small>{scan.route_profile || 'auto'}</small></td>
                <td><time dateTime={scan.created_at}>{formatDate(scan.created_at)}</time></td>
                <td><span className={`http-state ${scan.scoring_http_code === 200 ? 'is-ok' : ''}`}>{scan.scoring_http_code || '—'}</span></td>
                <td><Score value={scan.overall_score} /></td>
                <td><div className="table-actions"><Link to={`/scan/${scan.id}`}>Ver evidencia</Link><button type="button" onClick={() => handleDelete(scan)}>Eliminar</button></div></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <p className="history-note">La puntuación principal usa la respuesta raíz; las rutas bloqueadas o ausentes se conservan como evidencia separada.</p>
    </div>
  )
}
