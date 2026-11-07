import { Routes, Route } from 'react-router-dom'
import Navbar from './components/Navbar'
import Home from './pages/Home'
import Scanner from './pages/Scanner'
import InvestigationReport from './pages/InvestigationReport'
import QrScanner from './pages/QrScanner'
import ThreatGraph from './pages/ThreatGraph'
import CommunityIntel from './pages/CommunityIntel'
import History from './pages/History'
import Analytics from './pages/Analytics'
import './App.css'

function App() {
  return (
    <div className="app">
      <Navbar />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/scanner" element={<Scanner />} />
        <Route path="/investigation/:id" element={<InvestigationReport />} />
        <Route path="/investigation" element={<InvestigationReport />} />
        <Route path="/qr-scanner" element={<QrScanner />} />
        <Route path="/threat-graph" element={<ThreatGraph />} />
        <Route path="/community" element={<CommunityIntel />} />
        <Route path="/history" element={<History />} />
        <Route path="/analytics" element={<Analytics />} />
      </Routes>
      <footer className="footer">
        <div className="container">
          <p>© 2026 TRUSTX AI — Intelligent Web Security & Threat Intelligence Platform</p>
          <p className="footer-sub">Multi-Model AI · RDAP/DNS Intelligence · SSL/TLS Handshake Audit · Trust Score Engine</p>
        </div>
      </footer>
    </div>
  )
}

export default App
