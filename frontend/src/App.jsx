import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import ScanDetail from './components/ScanDetail'
import ScanForm from './components/ScanForm'

function Layout({ children }) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col">
      <header className="bg-slate-900/90 backdrop-blur-md border-b border-slate-800/80 sticky top-0 z-40 shadow-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4 flex items-center gap-3">
          <img src="/shield.svg" alt="" className="w-8 h-8 brightness-0 invert opacity-90" />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              GeekNosy
            </h1>
            <p className="text-slate-400 text-xs">Evaluación defensiva de seguridad web pública</p>
          </div>
          <div className="ml-auto text-xs text-slate-400 bg-slate-800/50 px-3 py-1 rounded-full border border-slate-700/55">
            v1.0 · Favio Urrea · Uso abierto
          </div>
        </div>
      </header>
      
      <main className="max-w-7xl mx-auto w-full px-4 sm:px-6 py-8 flex-1">{children}</main>
      
      <footer className="text-center text-xs text-slate-500 py-8 border-t border-slate-900 mt-12 bg-slate-900/30 space-y-2">
        <div className="max-w-3xl mx-auto px-4">
          GeekNosy — Solo evalúa configuración HTTP/HTTPS/DNS pública visible. Sin explotación ni pruebas intrusivas.
        </div>
        <div className="text-slate-400 font-medium">v1.0 · Favio Urrea · Uso abierto</div>
      </footer>
    </div>
  )
}

function HomePage() {
  const [refreshKey, setRefreshKey] = useState(0)

  return (
    <Layout>
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Form panel container */}
        <div className="bg-slate-900/80 border border-slate-800/90 rounded-2xl p-6 sm:p-8 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
          <div className="absolute bottom-0 left-0 w-80 h-80 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none"></div>
          
          <div className="relative space-y-6">
            <div className="space-y-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse"></span>
                Herramienta de Auditoría Web
              </span>
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">Nuevo Escaneo</h2>
              <p className="text-slate-400 text-sm max-w-xl">
                Configure los parámetros para evaluar la seguridad de los dominios especificados de manera completamente pasiva.
              </p>
            </div>
            
            <ScanForm onScanComplete={() => setRefreshKey((k) => k + 1)} />
          </div>
        </div>

        {/* Dashboard / Mini panel below the form */}
        <div className="bg-slate-900/80 border border-slate-800/90 rounded-2xl p-6 sm:p-8 shadow-xl relative overflow-hidden">
          <div className="mb-6">
            <h3 className="text-xl font-bold text-white">Escaneos Realizados</h3>
            <p className="text-sm text-slate-400">Historial completo y reporte de análisis de seguridad.</p>
          </div>
          <Dashboard refreshKey={refreshKey} />
        </div>
      </div>
    </Layout>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route
        path="/scan/:id"
        element={
          <Layout>
            <ScanDetail />
          </Layout>
        }
      />
    </Routes>
  )
}
