import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/client'

const INTENSITIES = {
  passive: { label: 'Pasivo', paths: 8 },
  fast: { label: 'Rápido', paths: 15 },
  standard: { label: 'Estándar', paths: 40 },
  bug_bounty: { label: 'Bug bounty', paths: 80 },
  deep: { label: 'Profundo', paths: 120 },
  custom: { label: 'Personalizado', paths: 120 },
}

const ACTIVE_CHECKS = [
  { id: 'reflection', label: 'Reflexión de entrada', help: 'Marcador único, sin payload ejecutable.' },
  { id: 'open_redirect', label: 'Redirección abierta', help: 'Destino reservado example.invalid.' },
  { id: 'sql_error', label: 'Errores SQL visibles', help: 'Comilla aislada; no intenta extraer datos.' },
  { id: 'dangerous_methods', label: 'Métodos HTTP', help: 'Consulta OPTIONS; no ejecuta PUT/DELETE.' },
  { id: 'cors', label: 'Reflexión CORS', help: 'Origen reservado example.invalid.' },
  { id: 'crlf', label: 'Inyección CRLF', help: 'Marcador propio en una cabecera de respuesta.' },
]

export default function ScanForm({ onScanComplete }) {
  const [domains, setDomains] = useState('')
  const [institution, setInstitution] = useState('')
  const [scoreMode, setScoreMode] = useState('advanced')
  const [intensity, setIntensity] = useState('standard')
  const [routeProfile, setRouteProfile] = useState('auto')
  const [includeExposure, setIncludeExposure] = useState(false)
  const [maxPaths, setMaxPaths] = useState(40)
  const [customPaths, setCustomPaths] = useState('')
  const [includeDefault, setIncludeDefault] = useState(true)
  const [executionMode, setExecutionMode] = useState('passive')
  const [authorizationReference, setAuthorizationReference] = useState('')
  const [credentialProfile, setCredentialProfile] = useState('')
  const [activeChecks, setActiveChecks] = useState([])
  const [authorized, setAuthorized] = useState(false)
  const [activeAuthorized, setActiveAuthorized] = useState(false)
  const [requestsPerSecond, setRequestsPerSecond] = useState(2)
  const [scheduleEnabled, setScheduleEnabled] = useState(false)
  const [scheduleHours, setScheduleHours] = useState(24)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [job, setJob] = useState(null)
  const errorRef = useRef(null)

  useEffect(() => {
    const cap = INTENSITIES[intensity]?.paths || 40
    setMaxPaths((current) => Math.min(Number(current) || cap, cap))
  }, [intensity])

  useEffect(() => {
    if (error) errorRef.current?.focus()
  }, [error])

  const domainList = useMemo(() => domains.split(/[\n,;]+/).map((value) => value.trim()).filter(Boolean), [domains])
  const stage = job ? 3 : authorized ? 2 : domainList.length ? 1 : 0

  const toggleActiveCheck = (id) => {
    setActiveChecks((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  }

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError(null)
    if (!domainList.length) return setError('Indique al menos un dominio o URL recuperable.')
    if (!authorized) return setError('Confirme que cuenta con autorización para este alcance.')
    if (executionMode === 'authorized' && !authorizationReference.trim()) return setError('El modo autorizado requiere una referencia de alcance o ticket.')
    if (executionMode === 'authorized' && !activeAuthorized) return setError('Confirme por separado las comprobaciones autorizadas.')

    const scanRequest = {
      domains: domainList,
      institution: institution.trim() || null,
      mode: scoreMode,
      intensity,
      route_profile: routeProfile,
      include_default_paths: includeDefault,
      include_exposure_checks: includeExposure,
      max_paths_per_domain: Number(maxPaths) || 40,
      custom_paths: customPaths.split('\n').map((value) => value.trim()).filter(Boolean),
      requests_per_second: Number(requestsPerSecond) || 2,
      authorization_confirmed: true,
      execution_mode: executionMode,
      active_authorization_confirmed: executionMode === 'authorized' && activeAuthorized,
      authorization_reference: executionMode === 'authorized' ? authorizationReference.trim() : null,
      active_checks: executionMode === 'authorized' ? activeChecks : [],
      credential_profile: executionMode === 'authorized' && credentialProfile.trim() ? credentialProfile.trim() : null,
    }

    setLoading(true)
    try {
      const created = await api.createJob(scanRequest)
      if (scheduleEnabled) {
        await api.createSchedule({
          name: `${institution.trim() || domainList[0]} · ${INTENSITIES[intensity].label}`,
          interval_minutes: Math.max(5, Number(scheduleHours) * 60),
          request: scanRequest,
        })
      }
      setJob(created)
      let current = created
      while (!['completed', 'failed', 'cancelled'].includes(current.status)) {
        await new Promise((resolve) => setTimeout(resolve, 1000))
        current = await api.getJob(created.id)
        setJob(current)
      }
      if (current.status === 'completed') {
        onScanComplete?.(current)
        setDomains('')
        setCustomPaths('')
      } else if (current.status === 'failed') {
        throw new Error(current.error || 'El worker no pudo completar el análisis.')
      } else {
        setError('El trabajo fue cancelado sin modificar el objetivo.')
      }
    } catch (requestError) {
      setError(requestError.message || 'No se pudo crear el trabajo. Revise la API y vuelva a intentar.')
    } finally {
      setLoading(false)
    }
  }

  const cancelCurrentJob = async () => {
    if (!job?.id) return
    try { setJob(await api.cancelJob(job.id)) } catch (requestError) { setError(requestError.message) }
  }

  return (
    <form onSubmit={handleSubmit} className="scan-form" noValidate>
      <div className="authorization-rail" aria-label="Estado del permiso de evaluación">
        <div className={`rail-step ${stage >= 1 ? 'is-complete' : 'is-current'}`}><b>1</b><div><strong>Alcance</strong><span>{domainList.length ? `${domainList.length} objetivo${domainList.length > 1 ? 's' : ''}` : 'Pendiente'}</span></div></div>
        <div className={`rail-step ${stage >= 2 ? 'is-complete' : stage === 1 ? 'is-current' : ''}`}><b>2</b><div><strong>Autorización</strong><span>{authorized ? 'Confirmada' : 'Pendiente'}</span></div></div>
        <div className={`rail-step ${stage >= 3 ? 'is-complete' : stage === 2 ? 'is-current' : ''}`}><b>3</b><div><strong>Trabajo</strong><span>{job?.status || 'Sin enviar'}</span></div></div>
      </div>

      <div className="form-grid">
        <div className="field-group">
          <label htmlFor="scan-domains">Dominios o URLs</label>
          <textarea id="scan-domains" value={domains} onChange={(event) => setDomains(event.target.value)} placeholder={'example.com\napp.example.org\nhttps://api.example.net'} aria-describedby="domains-help" required />
          <small id="domains-help">Una línea por objetivo. Se bloquean destinos privados, locales, reservados y link-local por defecto.</small>
        </div>
        <div className="field-group">
          <label htmlFor="scan-institution">Cliente o programa</label>
          <input id="scan-institution" value={institution} onChange={(event) => setInstitution(event.target.value)} placeholder="Programa de bug bounty o institución" />

          <span className="field-label">Tipo de ejecución</span>
          <div className="mode-switch" role="group" aria-label="Tipo de ejecución">
            <button type="button" className={executionMode === 'passive' ? 'is-selected' : ''} onClick={() => setExecutionMode('passive')} aria-pressed={executionMode === 'passive'}><strong>Pasiva</strong><span>Stack predeterminado</span></button>
            <button type="button" className={executionMode === 'authorized' ? 'is-selected' : ''} onClick={() => setExecutionMode('authorized')} aria-pressed={executionMode === 'authorized'}><strong>Autorizada</strong><span>Worker aislado</span></button>
          </div>
        </div>
      </div>

      <div className="field-row">
        <div className="field-group"><label htmlFor="scan-intensity">Intensidad</label><select id="scan-intensity" value={intensity} onChange={(event) => { setIntensity(event.target.value); setMaxPaths(INTENSITIES[event.target.value].paths) }}>{Object.entries(INTENSITIES).map(([value, item]) => <option key={value} value={value}>{item.label} · hasta {item.paths} rutas</option>)}</select></div>
        <div className="field-group"><label htmlFor="scan-score-mode">Puntuación</label><select id="scan-score-mode" value={scoreMode} onChange={(event) => setScoreMode(event.target.value)}><option value="standard">Estándar · TLS + headers</option><option value="advanced">Avanzada · señal completa</option></select></div>
      </div>

      {executionMode === 'authorized' && (
        <section className="authorized-block" aria-labelledby="authorized-title">
          <div><h3 id="authorized-title">Perfil autorizado aislado</h3><p>La API solo encola este trabajo. Únicamente el worker iniciado con <code>docker compose --profile authorized up -d</code> puede reclamarlo.</p></div>
          <div className="field-row">
            <div className="field-group"><label htmlFor="authorization-reference">Referencia de autorización</label><input id="authorization-reference" value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} placeholder="Ticket, contrato o scope ID" required /></div>
            <div className="field-group"><label htmlFor="credential-profile">Perfil de credenciales</label><input id="credential-profile" value={credentialProfile} onChange={(event) => setCredentialProfile(event.target.value)} placeholder="staging-readonly" /><small>Nombre configurado en el worker; nunca pegue un token aquí.</small></div>
          </div>
          <fieldset className="field-group"><legend className="field-label">Comprobaciones de bajo impacto</legend><div className="active-grid">{ACTIVE_CHECKS.map((check) => <label className="check-row" key={check.id}><input type="checkbox" checked={activeChecks.includes(check.id)} onChange={() => toggleActiveCheck(check.id)} /><span><strong>{check.label}</strong><br /><small>{check.help}</small></span></label>)}</div></fieldset>
          <label className="check-row"><input type="checkbox" checked={activeAuthorized} onChange={(event) => setActiveAuthorized(event.target.checked)} /><span><strong>Confirmo este modo reforzado</strong><br /><small>El alcance autoriza credenciales nombradas y las comprobaciones seleccionadas.</small></span></label>
        </section>
      )}

      <details className="advanced-block">
        <summary><span>Ajustes avanzados</span><span>Rutas, límites y agenda</span></summary>
        <div className="advanced-content">
          <div className="field-row">
            <div className="field-group"><label htmlFor="route-profile">Perfil de rutas</label><select id="route-profile" value={routeProfile} onChange={(event) => setRouteProfile(event.target.value)}><option value="auto">Automático por tecnología</option><option value="minimal">Mínimo</option><option value="standard">Estándar</option><option value="advanced">Avanzado + APIs</option><option value="all">Todos los perfiles</option></select></div>
            <div className="field-group"><label htmlFor="max-paths">Máximo de rutas</label><input id="max-paths" type="number" min="1" max={INTENSITIES[intensity].paths} value={maxPaths} onChange={(event) => setMaxPaths(event.target.value)} /></div>
          </div>
          <div className="field-row">
            <div className="field-group"><label htmlFor="custom-paths">Rutas personalizadas</label><textarea id="custom-paths" value={customPaths} onChange={(event) => setCustomPaths(event.target.value)} placeholder={'/portal/\n/api/health'} /></div>
            <div className="field-group"><label htmlFor="request-rate">Solicitudes por segundo</label><input id="request-rate" type="number" min="0.2" max="4" step="0.2" value={requestsPerSecond} onChange={(event) => setRequestsPerSecond(event.target.value)} /><div className="check-list"><label className="check-row"><input type="checkbox" checked={includeDefault} onChange={(event) => setIncludeDefault(event.target.checked)} /><span>Usar rutas inteligentes</span></label><label className="check-row"><input type="checkbox" checked={includeExposure} onChange={(event) => setIncludeExposure(event.target.checked)} /><span>Consultar exposiciones con HEAD</span></label></div></div>
          </div>
          <div className="field-row"><label className="check-row"><input type="checkbox" checked={scheduleEnabled} onChange={(event) => setScheduleEnabled(event.target.checked)} /><span>Programar este trabajo de forma recurrente</span></label><div className="field-group"><label htmlFor="schedule-hours">Intervalo en horas</label><input id="schedule-hours" type="number" min="1" max="8760" disabled={!scheduleEnabled} value={scheduleHours} onChange={(event) => setScheduleHours(event.target.value)} /></div></div>
        </div>
      </details>

      {error && <div className="form-error" role="alert" tabIndex="-1" ref={errorRef}><strong>No se pudo continuar.</strong> {error}</div>}
      {job && loading && <div className="job-progress" role="status" aria-live="polite"><div className="job-progress-header"><span>{job.phase || job.status}</span><span>{Number(job.progress || 0).toFixed(1)}%</span></div><div className="progress-track"><span style={{ width: `${Math.max(1, job.progress || 0)}%` }} /></div><button type="button" className="secondary-action" onClick={cancelCurrentJob}>Cancelar trabajo</button></div>}

      <div className="form-actions">
        <label className="check-row attestation"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span><strong>Confirmo que puedo evaluar estos objetivos.</strong><br /><small>Dispongo de autorización verificable y respetaré el alcance y los límites de velocidad definidos.</small></span></label>
        <button type="submit" className="primary-action" disabled={loading}>{loading ? 'Procesando trabajo…' : `Crear análisis ${executionMode === 'authorized' ? 'autorizado' : 'pasivo'}`}</button>
      </div>
    </form>
  )
}
