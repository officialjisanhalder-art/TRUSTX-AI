import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Search, QrCode, Share2, Users, Clock, BarChart3, Menu, X, Radio } from 'lucide-react'
import './Navbar.css'

const navLinks = [
  { path: '/', label: 'Overview', icon: Shield },
  { path: '/scanner', label: 'Scanner', icon: Search },
  { path: '/qr-scanner', label: 'QR Studio', icon: QrCode },
  { path: '/threat-graph', label: 'Threat Graph', icon: Share2 },
  { path: '/community', label: 'Threat Intel', icon: Radio },
  { path: '/history', label: 'History', icon: Clock },
  { path: '/analytics', label: 'Analytics', icon: BarChart3 },
]

export default function Navbar() {
  const location = useLocation()
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    setMobileOpen(false)
  }, [location])

  return (
    <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
      <div className="navbar-inner container">
        {/* Logo */}
        <Link to="/" className="nav-logo" title="TRUSTX AI Home">
          <img src="/favicon.svg" alt="TRUSTX AI Logo" className="nav-logo-img" />
          <div className="nav-logo-text">
            <span className="nav-brand">TRUST<span className="nav-brand-x">X</span></span>
            <span className="nav-brand-ai">AI</span>
          </div>
        </Link>

        {/* Desktop Navigation */}
        <div className={`nav-links ${mobileOpen ? 'open' : ''}`}>
          {navLinks.map(({ path, label, icon: Icon }) => (
            <Link
              key={path}
              to={path}
              className={`nav-link ${location.pathname === path ? 'active' : ''}`}
            >
              <Icon size={15} />
              <span>{label}</span>
            </Link>
          ))}
        </div>

        {/* Chrome Extension Download */}
        <a
          href="/trustx-extension.zip"
          download="trustx-extension.zip"
          className="nav-extension-btn"
          title="Download Chrome Extension (ZIP)"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '6px 12px',
            background: '#111726',
            border: '1px solid #1e293b',
            borderRadius: '6px',
            color: '#38bdf8',
            fontSize: '12px',
            fontWeight: '600',
            textDecoration: 'none',
            whiteSpace: 'nowrap',
            marginLeft: '8px'
          }}
        >
          <span>🧩 Extension (.zip)</span>
        </a>

        {/* API Status Indicator */}
        <div className="nav-status">
          <div className="status-indicator" title="TRUSTX Core Engine Online">
            <span className="status-dot pulse"></span>
            <span className="status-label">Engine Active</span>
          </div>
        </div>

        {/* Mobile Toggle */}
        <button
          className="mobile-toggle"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
        >
          {mobileOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
      </div>
    </nav>
  )
}
