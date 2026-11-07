import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Shield, Search, Brain, Globe2, BarChart3, Lock, Zap, Globe, QrCode, Share2, Radio, Server, CheckCircle2 } from 'lucide-react'
import './Home.css'

const features = [
  {
    icon: Brain,
    title: 'Multi-Model Phishing Defense',
    desc: 'Combines ML models with Shannon entropy, typosquatting edit distance, and obfuscation detection.',
    color: '#38bdf8',
  },
  {
    icon: Globe,
    title: 'Domain & DNS Intelligence',
    desc: 'Authoritative DNS resolution (A, AAAA, MX, NS, TXT) and RDAP domain provenance auditing.',
    color: '#818cf8',
  },
  {
    icon: Lock,
    title: 'SSL/TLS & CT Log Verification',
    desc: 'Live TLS handshake audits, certificate chain validation, and crt.sh Certificate Transparency checks.',
    color: '#34d399',
  },
  {
    icon: Server,
    title: 'Website Security Assessment',
    desc: 'Non-invasive audits of HSTS, CSP, X-Frame-Options, cookie security flags, and redirect chains.',
    color: '#f59e0b',
  },
  {
    icon: QrCode,
    title: 'QR Code Phishing Scanner',
    desc: 'Decodes QR payloads with computer vision, unshortens destination URLs, and evaluates threat posture.',
    color: '#f43f5e',
  },
  {
    icon: Share2,
    title: 'Threat Relationship Graph',
    desc: 'Visualizes shared infrastructure clusters linking domains by common IPs, nameservers, and cert issuers.',
    color: '#a855f7',
  },
]

const stats = [
  { value: '0 - 100', label: 'Explainable Trust Score' },
  { value: '10-Step', label: 'Investigation Pipeline' },
  { value: '36', label: 'Extracted Features' },
  { value: 'Real-Time', label: 'Browser Protection' },
]

export default function Home() {
  return (
    <div className="home-page">
      {/* Hero Section */}
      <section className="hero">
        <div className="container hero-content">
          <motion.div
            className="hero-badge"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
          >
            <Zap size={14} />
            <span>TRUSTX AI — Intelligent Web Security & Collaborative Threat Platform</span>
          </motion.div>

          <motion.h1
            className="hero-title"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.6 }}
          >
            Intelligent Threat Intelligence
            <br />
            <span className="hero-title-highlight">& Explainable Web Security</span>
          </motion.h1>

          <motion.p
            className="hero-desc"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25, duration: 0.5 }}
          >
            TRUSTX AI goes beyond basic binary classification. It investigates domain provenance,
            cryptographic certificates, security header postures, brand impersonation, and shared
            infrastructure to generate a deterministic <strong>0–100 Trust Score</strong> with actionable recommendations.
          </motion.p>

          <motion.div
            className="hero-actions"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.5 }}
          >
            <Link to="/scanner" className="btn btn-primary btn-lg">
              <Search size={18} />
              Open Deep Scanner
            </Link>
            <Link to="/qr-scanner" className="btn btn-outline btn-lg">
              <QrCode size={18} />
              QR Code Studio
            </Link>
            <Link to="/threat-graph" className="btn btn-outline btn-lg">
              <Share2 size={18} />
              Threat Graph
            </Link>
          </motion.div>

          {/* Stats */}
          <motion.div
            className="hero-stats"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.55, duration: 0.5 }}
          >
            {stats.map((stat) => (
              <div key={stat.label} className="hero-stat">
                <div className="hero-stat-value">{stat.value}</div>
                <div className="hero-stat-label">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="features-section">
        <div className="container">
          <div className="section-header">
            <h2 className="section-title">Integrated Cybersecurity Engines</h2>
            <p className="section-desc">
              Six synchronized intelligence layers working in parallel to detect sophisticated attacks.
            </p>
          </div>

          <div className="features-grid">
            {features.map((feat, index) => {
              const Icon = feat.icon
              return (
                <div key={feat.title} className="feature-card">
                  <div
                    className="feature-icon-wrapper"
                    style={{ background: `${feat.color}15`, color: feat.color }}
                  >
                    <Icon size={24} />
                  </div>
                  <h3 className="feature-title">{feat.title}</h3>
                  <p className="feature-desc">{feat.desc}</p>
                </div>
              )
            })}
          </div>
        </div>
      </section>
    </div>
  )
}
