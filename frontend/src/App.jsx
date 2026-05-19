import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import ScanDetail from './components/ScanDetail'
import ScanForm from './components/ScanForm'

function Layout({ children }) {
  return (
    <div className="min-h-screen">
      <header className="bg-gobs-800 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center gap-3">
          <img src="/shield.svg" alt="" className="w-8 h-8 brightness-0 invert" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">DataGobs</h1>
            <p className="text-gobs-100 text-xs">Evaluación defensiva de seguridad web pública</p>
          </div>
          <div className="ml-auto text-xs text-gobs-200">
            v1.0 · Favio Urrea · Uso abierto
          </div>
        </div>
      </header>
      <main className="max-w-7xl mx-auto px-4 py-6">{children}</main>
      <footer className="text-center text-xs text-slate-400 py-6 border-t border-slate-200 mt-8">
        DataGobs — Solo evalúa configuración HTTP/HTTPS/DNS pública visible. Sin explotación ni pruebas intrusivas.
      </footer>
    </div>
  )
}

function HomePage() {
  const [refreshKey, setRefreshKey] = useState(0)

  return (
    <Layout>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <ScanForm onScanComplete={() => setRefreshKey((k) => k + 1)} />
        </div>
        <div className="lg:col-span-2">
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
