import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Radio, Users, ThumbsUp, ThumbsDown, Shield, AlertTriangle, Send, RefreshCw, ArrowRight } from 'lucide-react'
import { getThreatSummary, reportUrl, voteThreatReport } from '../services/api'
import './CommunityIntel.css'

export default function CommunityIntel() {
  const navigate = useNavigate()

  const [intel, setIntel] = useState(null)
  const [loading, setLoading] = useState(true)
  const [reporting, setReporting] = useState(false)
  const [formUrl, setFormUrl] = useState('')
  const [formType, setFormType] = useState('phishing')
  const [formDesc, setFormDesc] = useState('')
  const [votedHashes, setVotedHashes] = useState({})
  const [toast, setToast] = useState(null)

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3000)
  }

  const fetchIntel = async () => {
    setLoading(true)
    try {
      const data = await getThreatSummary()
      setIntel(data)
    } catch (err) {
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIntel()
  }, [])

  const handleReportSubmit = async (e) => {
    e.preventDefault()
    if (!formUrl.trim()) return

    setReporting(true)
    try {
      await reportUrl({
        url: formUrl.trim(),
        report_type: formType,
        description: formDesc.trim() || `Community report submitted as ${formType}`,
      })
      showToast('Threat reported successfully! Thank you for protecting the community.')
      setFormUrl('')
      setFormDesc('')
      fetchIntel()
    } catch {
      showToast('Failed to submit report. Please try again.', 'error')
    } finally {
      setReporting(false)
    }
  }

  const handleVote = async (url, voteType) => {
    try {
      // Simple pseudo hash
      const hash = btoa(url).substring(0, 16)
      await voteThreatReport(hash, voteType)
      setVotedHashes((prev) => ({ ...prev, [url]: voteType }))
      showToast(`Vote recorded (${voteType}).`)
    } catch {
      showToast('Failed to record vote.', 'error')
    }
  }

  return (
    <div className="page-wrapper">
      <div className="container community-page">
        {/* Toast */}
        <AnimatePresence>
          {toast && (
            <motion.div
              className={`community-toast toast-${toast.type}`}
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
            >
              {toast.msg}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Header */}
        <div className="community-header">
          <div className="community-badge">
            <Radio size={16} /> MODULE F: THREAT INTELLIGENCE
          </div>
          <h1 className="page-title">Collaborative Threat Intelligence Hub</h1>
          <p className="page-desc">
            Crowdsourced, verified telemetry powering real-time protection.
            Submit suspicious URLs, validate community submissions, and access early warning feeds.
          </p>
        </div>

        {/* KPI Row */}
        <div className="intel-kpis">
          <div className="kpi-box">
            <span className="kpi-num">{intel?.total_threat_reports || 0}</span>
            <span className="kpi-label">Total Community Reports</span>
          </div>
          <div className="kpi-box text-red">
            <span className="kpi-num">{intel?.phishing_reports || 0}</span>
            <span className="kpi-label">Flagged Phishing Sites</span>
          </div>
          <div className="kpi-box text-green">
            <span className="kpi-num">{intel?.false_positive_reports || 0}</span>
            <span className="kpi-label">Reviewed Safe Submissions</span>
          </div>
        </div>

        {/* Form & Feed Grid */}
        <div className="community-grid">
          {/* Submit Report Form */}
          <div className="report-submission-card">
            <h3>Submit a Threat Report</h3>
            <p className="sub-desc">Help protect others by flagging fraudulent portals, payment scams, or lookalike links.</p>

            <form onSubmit={handleReportSubmit} className="report-form">
              <div className="form-group">
                <label>Suspicious URL</label>
                <input
                  type="text"
                  placeholder="https://example-phishing-login.com"
                  value={formUrl}
                  onChange={(e) => setFormUrl(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label>Threat Category</label>
                <select value={formType} onChange={(e) => setFormType(e.target.value)}>
                  <option value="phishing">Phishing / Credential Harvesting</option>
                  <option value="fake_payment">Fraudulent Payment Portal</option>
                  <option value="brand_impersonation">Brand Lookalike / Impersonation</option>
                  <option value="malware">Malware / Suspicious Executable</option>
                  <option value="false_positive">False Positive (Site is Benign)</option>
                </select>
              </div>

              <div className="form-group">
                <label>Details / Observed Behavior (Optional)</label>
                <textarea
                  placeholder="Describe suspicious elements, cloned login forms, or scam emails..."
                  rows={3}
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                />
              </div>

              <button type="submit" className="submit-threat-btn" disabled={reporting}>
                {reporting ? <RefreshCw size={16} className="animate-spin" /> : <Send size={16} />}
                Submit Threat Report
              </button>
            </form>
          </div>

          {/* Recent Threat Stream */}
          <div className="threat-feed-card">
            <div className="feed-header">
              <h3>Community Threat Feed</h3>
              <button className="btn-refresh" onClick={fetchIntel} title="Refresh Feed">
                <RefreshCw size={14} />
              </button>
            </div>

            {loading ? (
              <div className="feed-loading">
                <div className="loading-spinner" />
                <p>Loading threat feed...</p>
              </div>
            ) : intel?.recent_reports?.length === 0 ? (
              <div className="feed-empty">
                <Shield size={36} className="text-muted" />
                <p>No reports submitted yet. Be the first to flag a suspicious URL!</p>
              </div>
            ) : (
              <div className="feed-list">
                {intel?.recent_reports?.map((item) => (
                  <div key={item.id} className="feed-item">
                    <div className="feed-top">
                      <span className={`feed-type-pill ${item.type}`}>
                        {item.type.replace('_', ' ')}
                      </span>
                      <span className="feed-time">{item.reported_at?.substring(0, 10)}</span>
                    </div>

                    <p className="feed-url" title={item.url}>{item.url}</p>
                    {item.description && <p className="feed-desc">{item.description}</p>}

                    <div className="feed-actions">
                      <button
                        className="btn-deep-inspect"
                        onClick={() => navigate(`/scanner?target=${encodeURIComponent(item.url)}`)}
                      >
                        Deep Inspect <ArrowRight size={13} />
                      </button>

                      <div className="vote-buttons">
                        <button
                          className={`vote-btn ${votedHashes[item.url] === 'upvote' ? 'voted-up' : ''}`}
                          onClick={() => handleVote(item.url, 'upvote')}
                          title="Confirm threat"
                        >
                          <ThumbsUp size={13} /> Confirm
                        </button>
                        <button
                          className={`vote-btn ${votedHashes[item.url] === 'downvote' ? 'voted-down' : ''}`}
                          onClick={() => handleVote(item.url, 'downvote')}
                          title="Dispute threat"
                        >
                          <ThumbsDown size={13} /> Dispute
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
