import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { QrCode, Upload, ArrowRight, Shield, AlertTriangle, CheckCircle, ExternalLink, RefreshCw } from 'lucide-react'
import TrustGauge from '../components/TrustGauge'
import { scanQrCode } from '../services/api'
import './QrScanner.css'

export default function QrScanner() {
  const navigate = useNavigate()
  const fileInputRef = useRef(null)

  const [selectedFile, setSelectedFile] = useState(null)
  const [previewUrl, setPreviewUrl] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleFileChange = (file) => {
    if (!file) return
    setSelectedFile(file)
    setError(null)
    setResult(null)

    // Generate local preview URL
    const reader = new FileReader()
    reader.onload = () => setPreviewUrl(reader.result)
    reader.readAsDataURL(file)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0])
    }
  }

  const handleScan = async () => {
    if (!selectedFile) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await scanQrCode(selectedFile)
      if (!data.success) {
        setError(data.error || 'Failed to decode QR code. Please provide a clear QR code image.')
      } else {
        setResult(data)
      }
    } catch (err) {
      setError(err.message || 'QR code scan failed.')
    } finally {
      setLoading(false)
    }
  }

  const qrData = result?.qr_data
  const investigation = result?.investigation

  return (
    <div className="page-wrapper">
      <div className="container qr-page">
        {/* Header */}
        <div className="qr-header">
          <div className="qr-badge">
            <QrCode size={16} /> MODULE H: COMPUTER VISION
          </div>
          <h1 className="page-title">QR Code Phishing Scanner</h1>
          <p className="page-desc">
            Upload any suspicious QR code image. TRUSTX AI decodes the payload, detects shortened URL redirects,
            and inspects destination safety before you navigate.
          </p>
        </div>

        {/* Upload Zone */}
        <div className="qr-workspace-grid">
          <div className="qr-upload-card">
            <div
              className={`dropzone ${previewUrl ? 'has-preview' : ''}`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                style={{ display: 'none' }}
                accept="image/*"
                onChange={(e) => handleFileChange(e.target.files[0])}
              />

              {previewUrl ? (
                <div className="preview-container">
                  <img src={previewUrl} alt="QR Preview" className="qr-preview-img" />
                  <span className="change-img-text">Click to choose a different image</span>
                </div>
              ) : (
                <div className="dropzone-empty">
                  <div className="upload-icon-circle">
                    <Upload size={28} />
                  </div>
                  <h3>Drag & Drop QR Image Here</h3>
                  <p>PNG, JPG, or WEBP up to 10MB</p>
                  <button type="button" className="browse-btn">Browse Files</button>
                </div>
              )}
            </div>

            {selectedFile && (
              <button
                className="scan-qr-btn"
                onClick={handleScan}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <RefreshCw size={18} className="animate-spin" /> Decoding & Investigating...
                  </>
                ) : (
                  <>
                    <QrCode size={18} /> Decode & Investigate QR
                  </>
                )}
              </button>
            )}

            {error && (
              <div className="qr-error-box">
                <AlertTriangle size={18} />
                <span>{error}</span>
              </div>
            )}
          </div>

          {/* Results Display */}
          <div className="qr-results-card">
            {!result && !loading && (
              <div className="results-placeholder">
                <Shield size={48} className="text-muted" />
                <h3>No QR Code Analyzed Yet</h3>
                <p>Upload a QR code on the left to reveal its embedded destination, redirect hops, and AI Trust Score.</p>
              </div>
            )}

            {loading && (
              <div className="results-placeholder">
                <div className="loading-spinner" />
                <h3>Decoding QR & Correlating Threat Intel...</h3>
                <p>Inspecting redirect hops and running multi-module verification.</p>
              </div>
            )}

            {result && qrData && (
              <motion.div
                className="qr-decoded-content"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <div className="decoded-header">
                  <h3>Decoded QR Payload</h3>
                  <span className={`payload-type-badge ${qrData.is_url ? 'is-url' : 'is-text'}`}>
                    {qrData.is_url ? 'WEB URL' : 'PLAIN TEXT'}
                  </span>
                </div>

                <div className="decoded-url-box">
                  <span className="box-label">Embedded Payload:</span>
                  <p className="extracted-text">{qrData.extracted_url || qrData.raw_text}</p>
                </div>

                {qrData.final_destination && qrData.final_destination !== qrData.extracted_url && (
                  <div className="redirect-trace-box">
                    <span className="box-label">⚠️ Unshortened Final Destination:</span>
                    <p className="final-url">{qrData.final_destination}</p>
                  </div>
                )}

                {/* Embedded Investigation Snapshot */}
                {investigation && (
                  <div className="investigation-snapshot">
                    <div className="snap-top">
                      <div>
                        <h4>TRUSTX Security Assessment</h4>
                        <p className="snap-summary">{investigation.summary}</p>
                      </div>
                      <TrustGauge
                        score={investigation.trust_score}
                        riskLevel={investigation.risk_level}
                        riskLabel={investigation.risk_label}
                        confidence={investigation.confidence}
                        size={130}
                      />
                    </div>

                    <div className="snap-actions">
                      <button
                        className="btn-full-report"
                        onClick={() => navigate(`/investigation/${investigation.investigation_id}`, { state: { report: investigation } })}
                      >
                        View Full Investigation Report <ArrowRight size={16} />
                      </button>
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
