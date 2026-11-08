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

  // Prevent background scrolling when mobile menu is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => {
      document.body.style.overflow = ''
    }
  }, [mobileOpen])

  return (
    <>
      <nav className={`navbar ${scrolled ? 'scrolled' : ''}`}>
        <div className="navbar-inner container">
          {/* Logo */}
          <Link to="/" className="nav-logo" title="TRUSTX AI Home" onClick={() => setMobileOpen(false)}>
            <img src="/favicon.svg" alt="TRUSTX AI Logo" className="nav-logo-img" />
            <div className="nav-logo-text">
              <span className="nav-brand">TRUST<span className="nav-brand-x">X</span></span>
              <span className="nav-brand-ai">AI</span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <div className="nav-links desktop-only">
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

          {/* Desktop Actions */}
          <div className="nav-actions desktop-only">
            <a
              href="/trustx-extension.zip"
              download="trustx-extension.zip"
              className="nav-extension-btn"
              title="Download Chrome Extension (ZIP)"
            >
              <span>🧩 Extension (.zip)</span>
            </a>

            <div className="nav-status">
              <div className="status-indicator" title="TRUSTX Core Engine Online">
                <span className="status-dot pulse"></span>
                <span className="status-label">Engine Active</span>
              </div>
            </div>
          </div>

          {/* Mobile Right Controls */}
          <div className="mobile-right">
            <div className="status-indicator compact" title="Engine Active">
              <span className="status-dot pulse"></span>
            </div>
            <button
              className="mobile-toggle"
              onClick={() => setMobileOpen(!mobileOpen)}
              aria-label={mobileOpen ? "Close menu" : "Open menu"}
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? <X size={22} /> : <Menu size={22} />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Drawer */}
        <div className={`mobile-drawer ${mobileOpen ? 'open' : ''}`}>
          <div className="mobile-drawer-inner">
            <div className="mobile-nav-list">
              {navLinks.map(({ path, label, icon: Icon }) => (
                <Link
                  key={path}
                  to={path}
                  className={`mobile-nav-link ${location.pathname === path ? 'active' : ''}`}
                  onClick={() => setMobileOpen(false)}
                >
                  <Icon size={18} />
                  <span>{label}</span>
                </Link>
              ))}
            </div>

            <div className="mobile-drawer-footer">
              <a
                href="/trustx-extension.zip"
                download="trustx-extension.zip"
                className="mobile-extension-btn"
                onClick={() => setMobileOpen(false)}
              >
                <span>🧩 Download Chrome Extension (.zip)</span>
              </a>

              <div className="mobile-status-row">
                <span className="status-dot pulse"></span>
                <span className="mobile-status-text">TRUSTX AI Threat Engine Online</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          className="mobile-backdrop"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}
    </>
  )
}
