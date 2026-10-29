import { useEffect, useState } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import { api } from './api/client'
import Dashboard from './components/Dashboard'
import ScanDetail from './components/ScanDetail'
import ScanForm from './components/ScanForm'

function Mark() {
  return (
    <svg aria-hidden="true" viewBox="0 0 40 40" className="brand-mark">
      <path d="M20 3 34 9v10c0 9-5.8 15.4-14 18C11.8 34.4 6 28 6 19V9l14-6Z" fill="currentColor" opacity=".14" />
      <path d="M20 5.5 31.5 10v9c0 7.2-4.3 12.5-11.5 15.2C12.8 31.5 8.5 26.2 8.5 19v-9L20 5.5Z" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M14 20.5 18.2 25 27 15.7" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="square" />
    </svg>
  )
}

function Layout({ children }) {
  const [health, setHealth] = useState(null)

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: 'offline' }))
  }, [])

  const online = health?.status === 'ok'
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Saltar al contenido principal</a>
      <aside className="side-rail">
        <Link to="/" className="brand-lockup" aria-label="GeekNosy, inicio">
          <Mark />
          <span><strong>GeekNosy</strong><small>Web posture lab</small></span>
        </Link>

        <nav aria-label="Navegación principal" className="primary-nav">
          <a href="/#new-scan" className="nav-item is-active">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v18M3 12h18" /></svg>
            Nuevo análisis
          </a>
          <a href="/#history" className="nav-item">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10" /></svg>
            Historial
          </a>
          <a href="https://github.com/FavinhoJR/GeekNosy/tree/main/docs" target="_blank" rel="noreferrer" className="nav-item">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 4h12v16H6zM9 8h6M9 12h6M9 16h4" /></svg>
            Documentación
          </a>
        </nav>

        <div className="rail-status" role="status" aria-live="polite">
          <div className="rail-status-row">
            <span className={`status-dot ${online ? 'is-online' : ''}`} />
            <span>{health ? (online ? 'Servicios operativos' : 'API no disponible') : 'Verificando servicios'}</span>
          </div>
          <p>Perfil base · pasivo</p>
        </div>

        <div className="creator-card">
          <span>Creado por</span>
          <a href="https://github.com/FavinhoJR" target="_blank" rel="noreferrer">Favio Urrea · @FavinhoJR</a>
        </div>
      </aside>

      <div className="app-stage">
        <header className="mobile-header">
          <Link to="/" className="brand-lockup"><Mark /><strong>GeekNosy</strong></Link>
          <span className={`status-dot ${online ? 'is-online' : ''}`} aria-label={online ? 'API operativa' : 'API no disponible'} />
        </header>
        <main id="main-content" tabIndex="-1">{children}</main>
        <footer className="site-footer">
          <p>Solo activos propios o expresamente autorizados. Los hallazgos requieren validación humana.</p>
          <span>GeekNosy 2.0 · MIT</span>
        </footer>
      </div>
    </div>
  )
}

function BoundaryPanel() {
  const [apiKey, setApiKey] = useState('')
  const [keySaved, setKeySaved] = useState(() => api.hasApiKey())

  const saveApiKey = (event) => {
    event.preventDefault()
    api.setApiKey(apiKey.trim())
    setKeySaved(Boolean(apiKey.trim()))
    setApiKey('')
  }

  return (
    <aside className="boundary-panel" aria-labelledby="boundary-title">
      <div className="boundary-header">
        <h2 id="boundary-title">Límite operativo</h2>
        <span className="mode-chip">Base segura</span>
      </div>
      <p>El stack predeterminado solo procesa evidencia pública y mantiene bloqueadas las redes privadas.</p>
      <dl className="boundary-list">
        <div><dt>Objetivos privados</dt><dd>Bloqueados</dd></div>
        <div><dt>Redirecciones</dt><dd>Mismo host</dd></div>
        <div><dt>Credenciales</dt><dd>Solo perfil aislado</dd></div>
        <div><dt>Resultados</dt><dd>Con evidencia</dd></div>
      </dl>
      <div className="authorized-note">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 4.5 6v5.2c0 4.8 3 8.5 7.5 9.8 4.5-1.3 7.5-5 7.5-9.8V6L12 3Zm0 5v4m0 3.5v.2" /></svg>
        <div><strong>Trabajo autenticado o activo</strong><span>Requiere el perfil Docker <code>authorized</code>, referencia de alcance y segunda confirmación.</span></div>
      </div>
      <form className="api-key-form" onSubmit={saveApiKey}>
        <label htmlFor="api-key">Clave API {keySaved ? 'guardada en esta sesión' : 'opcional'}</label>
        <div><input id="api-key" type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} autoComplete="off" placeholder={keySaved ? 'Reemplazar clave' : 'Solo si el servidor la exige'} /><button type="submit">{apiKey ? 'Guardar' : keySaved ? 'Quitar' : 'Aplicar'}</button></div>
        <small>Permanece únicamente en sessionStorage del navegador.</small>
      </form>
      <a className="text-link" href="https://github.com/FavinhoJR/GeekNosy/blob/main/docs/SECURITY.md" target="_blank" rel="noreferrer">Revisar política de seguridad</a>
    </aside>
  )
}

function HomePage() {
  const [refreshKey, setRefreshKey] = useState(0)
  return (
    <Layout>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <h1 id="page-title">Audita primero. Profundiza con intención.</h1>
          <p>Configura el alcance, conserva la evidencia y separa cada acción que exige autorización reforzada.</p>
        </div>
        <a className="github-link" href="https://github.com/FavinhoJR/GeekNosy" target="_blank" rel="noreferrer">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 19c-4 1.2-4-2-5-2m10 4v-3.1c0-.9.3-1.7.9-2.3 3-.3 6.1-1.5 6.1-6.6A5.1 5.1 0 0 0 19.6 5 4.7 4.7 0 0 0 19.5 2S18.4 1.7 16 3.4a10.4 10.4 0 0 0-7 0C6.6 1.7 5.5 2 5.5 2A4.7 4.7 0 0 0 5.4 5 5.1 5.1 0 0 0 4 9c0 5.1 3.1 6.3 6.1 6.6A3.2 3.2 0 0 0 9 17.9V21" /></svg>
          Ver repositorio
        </a>
      </section>

      <section id="new-scan" className="workbench" aria-label="Nuevo análisis">
        <div className="permit-panel">
          <div className="panel-heading">
            <div><h2>Nuevo análisis</h2><p>Define un trabajo reproducible sobre uno o varios dominios.</p></div>
            <span className="permit-id">PERMIT / WEB</span>
          </div>
          <ScanForm onScanComplete={() => setRefreshKey((key) => key + 1)} />
        </div>
        <BoundaryPanel />
      </section>

      <section id="history" className="history-section" aria-labelledby="history-title">
        <div className="section-heading"><div><h2 id="history-title">Historial de evaluaciones</h2><p>Resultados comparables, exportables y listos para triage.</p></div></div>
        <Dashboard refreshKey={refreshKey} />
      </section>
    </Layout>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/scan/:id" element={<Layout><ScanDetail /></Layout>} />
    </Routes>
  )
}
