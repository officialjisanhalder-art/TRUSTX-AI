import { useState, useEffect } from 'react'
import { useParams, useLocation, Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, AlertTriangle, XCircle, CheckCircle, ExternalLink, ArrowLeft,
  Lock, Globe, Server, FileText, Cpu, AlertOctagon, Share2, RefreshCw, Layers
} from 'lucide-react'
import TrustGauge from '../components/TrustGauge'
import SecurityBadge from '../components/SecurityBadge'
import { getInvestigation, investigateUrl } from '../services/api'
import './InvestigationReport.css'

export default function InvestigationReport() {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()

  const [report, setReport] = useState(location.state?.report || null)
  const [loading, setLoading] = useState(!report && Boolean(id))
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    if (!report && id) {
      setLoading(true)
      getInvestigation(id)
        .then((data) => {
          setReport(data)
          setLoading(false)
        })
        .catch((err) => {
          setError(err.message || 'Report not found.')
          setLoading(false)
        })
    } else if (!report && !id) {
      setLoading(false)
    }
  }, [id, report])

  if (loading) {
    return (
      <div className="page-wrapper">
        <div className="container investigation-loading">
          <div className="loading-spinner" />
          <h2>Synthesizing Threat Intelligence...</h2>
          <p>Correlating ML inference, DNS records, SSL certificates, and security headers.</p>
        </div>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="page-wrapper">
        <div className="container investigation-error">
          <AlertOctagon size={48} color="#ef4444" />
          <h2>Investigation Not Found</h2>
          <p>{error || 'No active investigation data available.'}</p>
          <button className="cyber-btn" onClick={() => navigate('/scanner')}>
            <ArrowLeft size={16} /> Return to Scanner
          </button>
        </div>
      </div>
    )
  }

  const {
    investigation_id, target_url, domain, investigated_at, duration_ms,
    trust_score, risk_level, risk_label, confidence, summary,
    ai_explanation, risks_faced, actionable_recommendations, modules
  } = report

  const modPhish = modules?.module_a_phishing || {}
  const modDns = modules?.module_b_domain_dns || {}
  const modSsl = modules?.module_c_ssl_tls || {}
  const modSec = modules?.module_d_security_audit || {}
  const modIntel = modules?.module_f_threat_intel || {}
  const penalties = modules?.trust_engine_breakdown?.penalties || []
  const bonuses = modules?.trust_engine_breakdown?.bonuses || []

  return (
    <div className="page-wrapper">
      <div className="container report-page">
        {/* Top Navigation Bar */}
        <div className="report-top-bar">
          <Link to="/scanner" className="back-link">
            <ArrowLeft size={16} /> Back to Scanner
          </Link>
          <div className="report-id-pill">
            <span>ID: {investigation_id}</span>
            <span className="dot-divider">•</span>
            <span>{duration_ms} ms</span>
          </div>
        </div>

        {/* Master Hero Card */}
        <motion.div
          className="report-hero-card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="hero-left">
            <div className="domain-header">
              <h1 className="report-domain">{domain}</h1>
              <a
                href={target_url}
                target="_blank"
                rel="noopener noreferrer"
                className="target-link"
                title="View destination URL"
              >
                <span>{target_url}</span>
                <ExternalLink size={14} />
              </a>
            </div>

            <div className="hero-summary-box">
              <p className="summary-text">{summary}</p>
              <div className="hero-tags">
                <SecurityBadge level={risk_level} text={risk_label} />
                <span className="hero-tag">Confidence: {confidence}%</span>
                <span className="hero-tag">TLS {modSsl?.certificate?.tls_version || 'N/A'}</span>
                {modDns?.domain_age_days >= 0 && (
                  <span className="hero-tag">Age: {modDns.domain_age_days} days</span>
                )}
              </div>
            </div>
          </div>

          <div className="hero-right">
            <TrustGauge
              score={trust_score}
              riskLevel={risk_level}
              riskLabel={risk_label}
              confidence={confidence}
              size={180}
            />
          </div>
        </motion.div>

        {/* AI Security Verdict & Recommendations */}
        <div className="ai-verdict-grid">
          <div className="cyber-card ai-explanation-card">
            <div className="card-header">
              <Cpu size={18} className="card-icon text-cyan" />
              <h3>AI Security Investigation Verdict</h3>
            </div>
            <p className="explanation-paragraph">{ai_explanation}</p>

            <div className="risks-block">
              <h4>Risks User Faces:</h4>
              <ul>
                {risks_faced?.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="cyber-card actions-card">
            <div className="card-header">
              <Shield size={18} className="card-icon text-green" />
              <h3>Actionable Guidance</h3>
            </div>
            <div className="recommendations-list">
              {actionable_recommendations?.map((act, i) => (
                <div key={i} className="action-step">
                  <span className="step-num">{i + 1}</span>
                  <span className="step-text">{act}</span>
                </div>
              ))}
            </div>

            <div className="card-quick-actions">
              <Link to={`/threat-graph?domain=${encodeURIComponent(domain)}`} className="btn-graph-view">
                <Share2 size={15} /> Explore Threat Graph
              </Link>
            </div>
          </div>
        </div>

        {/* Multi-Module Intelligence Tabs */}
        <div className="intel-tabs-container">
          <div className="intel-tab-headers">
            <button
              className={`intel-tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              <Layers size={16} /> Trust Engine Breakdown
            </button>
            <button
              className={`intel-tab-btn ${activeTab === 'dns' ? 'active' : ''}`}
              onClick={() => setActiveTab('dns')}
            >
              <Globe size={16} /> Domain & DNS Intel
            </button>
            <button
              className={`intel-tab-btn ${activeTab === 'ssl' ? 'active' : ''}`}
              onClick={() => setActiveTab('ssl')}
            >
              <Lock size={16} /> SSL / TLS Certificate
            </button>
            <button
              className={`intel-tab-btn ${activeTab === 'security' ? 'active' : ''}`}
              onClick={() => setActiveTab('security')}
            >
              <Server size={16} /> Website Security Headers
            </button>
          </div>

          <div className="intel-tab-body">
            {/* Tab 1: Overview & Penalties */}
            {activeTab === 'overview' && (
              <div className="tab-pane">
                <div className="score-breakdown-grid">
                  <div className="breakdown-card">
                    <h4>Identified Penalties ({penalties.length})</h4>
                    {penalties.length === 0 ? (
                      <p className="clean-state">No security penalties incurred.</p>
                    ) : (
                      <div className="penalty-list">
                        {penalties.map((p, i) => (
                          <div key={i} className="penalty-row">
                            <span className="penalty-points">{p.points}</span>
                            <span className="penalty-reason">{p.reason}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="breakdown-card">
                    <h4>Trust Bonuses ({bonuses.length})</h4>
                    {bonuses.length === 0 ? (
                      <p className="clean-state">No trust bonuses applied.</p>
                    ) : (
                      <div className="bonus-list">
                        {bonuses.map((b, i) => (
                          <div key={i} className="bonus-row">
                            <span className="bonus-points">+{b.points}</span>
                            <span className="bonus-reason">{b.reason}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* SHAP Indicators if available */}
                {modPhish?.ml_prediction?.shap_explanation?.top_features && (
                  <div className="shap-section">
                    <h4>AI Model Feature Impacts (SHAP)</h4>
                    <div className="shap-pills">
                      {modPhish.ml_prediction.shap_explanation.top_features.map((feat, i) => (
                        <div key={i} className={`shap-pill ${feat.impact}`}>
                          <span className="shap-feat-name">{feat.description || feat.feature}</span>
                          <span className="shap-feat-impact">
                            {feat.impact === 'increases_phishing' ? '▲ Risk' : '▼ Safe'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tab 2: Domain & DNS */}
            {activeTab === 'dns' && (
              <div className="tab-pane">
                <div className="dns-grid">
                  <div className="dns-card">
                    <h4>Registration Provenance (RDAP)</h4>
                    <div className="dns-field-group">
                      <div className="dns-row">
                        <span className="lbl">Registrar:</span>
                        <span className="val">{modDns?.rdap?.registrar || 'Not Disclosed'}</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Creation Date:</span>
                        <span className="val">{modDns?.rdap?.creation_date || 'Unknown'}</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Domain Age:</span>
                        <span className="val">
                          {modDns?.rdap?.domain_age_days >= 0 ? `${modDns.rdap.domain_age_days} days` : 'Indeterminate'}
                        </span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Expiration:</span>
                        <span className="val">{modDns?.rdap?.expiration_date || 'Unknown'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="dns-card">
                    <h4>DNS Infrastructure Records</h4>
                    <div className="dns-field-group">
                      <div className="dns-row">
                        <span className="lbl">A Records (IPv4):</span>
                        <span className="val">{modDns?.dns?.a_records?.join(', ') || 'None'}</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Nameservers:</span>
                        <span className="val">{modDns?.dns?.ns_records?.join(', ') || 'None'}</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Mail Servers (MX):</span>
                        <span className="val">
                          {modDns?.dns?.mx_records?.map((m) => m.exchange).join(', ') || 'None (No mail records)'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 3: SSL / TLS */}
            {activeTab === 'ssl' && (
              <div className="tab-pane">
                <div className="ssl-grid">
                  <div className="ssl-card">
                    <h4>Certificate Identity</h4>
                    <div className="dns-field-group">
                      <div className="dns-row">
                        <span className="lbl">Issuer:</span>
                        <span className="val">
                          {modSsl?.certificate?.issuer?.organizationName ||
                            modSsl?.certificate?.issuer?.commonName ||
                            'Unknown Issuer'}
                        </span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Protocol Version:</span>
                        <span className="val">{modSsl?.certificate?.tls_version || 'None'}</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Valid Window:</span>
                        <span className="val">
                          {modSsl?.certificate?.valid_from?.substring(0, 10)} to{' '}
                          {modSsl?.certificate?.valid_to?.substring(0, 10)}
                        </span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Days Remaining:</span>
                        <span className="val">{modSsl?.certificate?.days_remaining} days</span>
                      </div>
                      <div className="dns-row">
                        <span className="lbl">Hostname Match:</span>
                        <span className="val">
                          {modSsl?.certificate?.hostname_matches ? '✅ Matched' : '❌ Mismatch'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="ssl-card">
                    <h4>Certificate Transparency & Compliance</h4>
                    <p className="takeaway-note">{modSsl?.important_takeaway}</p>
                    <div className="ct-meta">
                      <span>Logged in CT logs: <strong>{modSsl?.certificate_transparency?.logged_certs_count || 0} certificates</strong></span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 4: Security Headers */}
            {activeTab === 'security' && (
              <div className="tab-pane">
                <div className="headers-grid">
                  <div className="headers-card">
                    <h4>Active Security Headers ({modSec?.headers_audit?.present?.length || 0})</h4>
                    <div className="header-list">
                      {modSec?.headers_audit?.present?.map((h, i) => (
                        <div key={i} className="header-pill present">
                          <CheckCircle size={14} color="#4ade80" />
                          <span>{h.header}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="headers-card">
                    <h4>Missing Foundational Headers ({modSec?.headers_audit?.missing?.length || 0})</h4>
                    <div className="header-list">
                      {modSec?.headers_audit?.missing?.map((h, i) => (
                        <div key={i} className="header-pill missing">
                          <AlertTriangle size={14} color="#f97316" />
                          <span>{h.name}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
