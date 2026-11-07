import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Share2, Search, RefreshCw, Shield, Server, Globe, Lock, AlertTriangle, Layers, Info } from 'lucide-react'
import { getThreatGraph } from '../services/api'
import './ThreatGraph.css'

export default function ThreatGraph() {
  const location = useLocation()
  const queryParams = new URLSearchParams(location.search)
  const initialDomain = queryParams.get('domain') || 'google.com'

  const [domain, setDomain] = useState(initialDomain)
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)

  const fetchGraph = async (dom) => {
    if (!dom.trim()) return
    setLoading(true)
    setError(null)
    setSelectedNode(null)
    try {
      const data = await getThreatGraph(dom.trim())
      setGraphData(data)
      if (data.nodes && data.nodes.length > 0) {
        setSelectedNode(data.nodes[0]) // Select target domain by default
      }
    } catch (err) {
      setError(err.message || 'Failed to load threat graph.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchGraph(initialDomain)
  }, [initialDomain])

  const handleSearch = (e) => {
    e.preventDefault()
    fetchGraph(domain)
  }

  // Calculate coordinates in a radial layout around the target domain center
  const nodes = graphData?.nodes || []
  const edges = graphData?.edges || []
  const width = 760
  const height = 480
  const centerX = width / 2
  const centerY = height / 2

  // Position nodes
  const positionedNodes = nodes.map((node, index) => {
    if (index === 0) {
      return { ...node, x: centerX, y: centerY }
    }
    const angle = ((index - 1) / Math.max(1, nodes.length - 1)) * 2 * Math.PI
    // Vary radius slightly based on node type
    let r = 160
    if (node.type === 'ip_address') r = 140
    if (node.type === 'nameserver') r = 190
    if (node.type === 'cert_issuer') r = 160
    if (node.type === 'related_domain') r = 210

    return {
      ...node,
      x: centerX + r * Math.cos(angle),
      y: centerY + r * Math.sin(angle),
    }
  })

  // Node color helper
  const getNodeColor = (type, risk) => {
    if (type === 'target_domain') return '#38bdf8' // Cyan
    if (type === 'ip_address') return '#818cf8'    // Indigo
    if (type === 'nameserver') return '#a78bfa'    // Purple
    if (type === 'cert_issuer') return '#34d399'   // Emerald
    if (type === 'related_domain') return risk === 'critical' ? '#f87171' : '#fb923c' // Red/Orange
    return '#94a3b8'
  }

  const getNodeIcon = (type) => {
    switch (type) {
      case 'target_domain': return <Globe size={16} />
      case 'ip_address': return <Server size={16} />
      case 'nameserver': return <Layers size={16} />
      case 'cert_issuer': return <Lock size={16} />
      default: return <AlertTriangle size={16} />
    }
  }

  return (
    <div className="page-wrapper">
      <div className="container graph-page">
        {/* Header */}
        <div className="graph-header">
          <div className="graph-badge">
            <Share2 size={16} /> MODULE I: THREAT RELATIONSHIP GRAPH
          </div>
          <h1 className="page-title">Threat Relationship Visualizer</h1>
          <p className="page-desc">
            Maps shared hosting infrastructure, nameservers, mail exchanges, certificate issuers,
            and discovered lookalike phishing clusters.
          </p>

          {/* Search bar */}
          <form className="graph-search-form" onSubmit={handleSearch}>
            <div className="search-input-wrap">
              <Search size={18} className="search-icon" />
              <input
                type="text"
                placeholder="Enter domain (e.g. google.com, paypal-verify.com)..."
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="graph-input"
              />
            </div>
            <button type="submit" className="graph-submit-btn" disabled={loading}>
              {loading ? <RefreshCw size={16} className="animate-spin" /> : 'Inspect Graph'}
            </button>
          </form>
        </div>

        {/* Visualizer & Inspector Workspace */}
        <div className="graph-workspace">
          {/* Interactive SVG Canvas */}
          <div className="graph-canvas-card">
            {loading && (
              <div className="graph-loading-overlay">
                <div className="loading-spinner" />
                <p>Mapping infrastructure relationships...</p>
              </div>
            )}

            {error && (
              <div className="graph-error-overlay">
                <AlertTriangle size={32} color="#f87171" />
                <p>{error}</p>
              </div>
            )}

            {!loading && !error && graphData && (
              <svg width="100%" height="480" viewBox={`0 0 ${width} ${height}`} className="graph-svg">
                {/* Edges */}
                {edges.map((edge) => {
                  const srcNode = positionedNodes.find((n) => n.id === edge.source)
                  const tgtNode = positionedNodes.find((n) => n.id === edge.target)
                  if (!srcNode || !tgtNode) return null

                  return (
                    <g key={edge.id} className="graph-edge-group">
                      <line
                        x1={srcNode.x}
                        y1={srcNode.y}
                        x2={tgtNode.x}
                        y2={tgtNode.y}
                        stroke="rgba(255, 255, 255, 0.18)"
                        strokeWidth="1.5"
                        strokeDasharray={edge.relationship === 'SIMILAR_PATTERN' ? '4,4' : 'none'}
                      />
                    </g>
                  )
                })}

                {/* Nodes */}
                {positionedNodes.map((n) => {
                  const isSelected = selectedNode?.id === n.id
                  const nodeColor = getNodeColor(n.type, n.risk)

                  return (
                    <g
                      key={n.id}
                      className="graph-node-group"
                      onClick={() => setSelectedNode(n)}
                      style={{ cursor: 'pointer' }}
                    >
                      {/* Selection Glow Halo */}
                      {isSelected && (
                        <circle
                          cx={n.x}
                          cy={n.y}
                          r={n.type === 'target_domain' ? 28 : 22}
                          fill="transparent"
                          stroke={nodeColor}
                          strokeWidth="2"
                          strokeOpacity="0.6"
                          className="pulse-halo"
                        />
                      )}

                      {/* Main Node Circle */}
                      <circle
                        cx={n.x}
                        cy={n.y}
                        r={n.type === 'target_domain' ? 20 : 14}
                        fill="#0f172a"
                        stroke={nodeColor}
                        strokeWidth={isSelected ? 3 : 2}
                      />

                      {/* Inner Dot */}
                      <circle
                        cx={n.x}
                        cy={n.y}
                        r={n.type === 'target_domain' ? 6 : 4}
                        fill={nodeColor}
                      />

                      {/* Node Label Text */}
                      <text
                        x={n.x}
                        y={n.y + (n.type === 'target_domain' ? 32 : 24)}
                        textAnchor="middle"
                        fill="#cbd5e1"
                        fontSize={n.type === 'target_domain' ? '12px' : '10px'}
                        fontWeight={n.type === 'target_domain' ? '700' : '500'}
                        fontFamily="monospace"
                        className="node-svg-label"
                      >
                        {n.label.length > 22 ? n.label.substring(0, 20) + '...' : n.label}
                      </text>
                    </g>
                  )
                })}
              </svg>
            )}

            {graphData && (
              <div className="canvas-footer-legend">
                <span className="legend-item"><span className="legend-dot" style={{ background: '#38bdf8' }} /> Target Domain</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: '#818cf8' }} /> Host IP</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: '#a78bfa' }} /> Nameserver</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: '#34d399' }} /> SSL Authority</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: '#f87171' }} /> Threat Lookalike</span>
              </div>
            )}
          </div>

          {/* Node Inspector Card */}
          <div className="graph-inspector-card">
            <h3>Infrastructure Node Inspector</h3>
            {selectedNode ? (
              <div className="inspector-content">
                <div className="inspector-badge-row">
                  <span className="node-type-tag">{selectedNode.type.replace('_', ' ').toUpperCase()}</span>
                  <span className={`node-risk-tag risk-${selectedNode.risk}`}>{selectedNode.risk}</span>
                </div>

                <div className="inspector-field">
                  <span className="field-lbl">Entity Identity</span>
                  <p className="field-val">{selectedNode.label}</p>
                </div>

                <div className="inspector-field">
                  <span className="field-lbl">Connected Relationships</span>
                  <div className="connected-edges-list">
                    {edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((e) => (
                        <div key={e.id} className="edge-chip">
                          <span className="edge-rel">{e.relationship}</span>
                          <span className="edge-conf">{Math.round(e.confidence * 100)}% Conf.</span>
                        </div>
                      ))}
                  </div>
                </div>

                <div className="inspector-field">
                  <span className="field-lbl">Analysis Note</span>
                  <p className="field-note">
                    {selectedNode.type === 'target_domain' &&
                      'Central investigated entity. Linked to infrastructure assets and discovered clusters.'}
                    {selectedNode.type === 'ip_address' &&
                      'Resolved IPv4 address. Shared by domains on the same server.'}
                    {selectedNode.type === 'nameserver' &&
                      'Authoritative nameserver hosting DNS zones for this target.'}
                    {selectedNode.type === 'cert_issuer' &&
                      'Certificate Authority that validated and issued active public keys.'}
                    {selectedNode.type === 'related_domain' &&
                      'Discovered lookalike domain exhibiting high lexical or infrastructure correlation.'}
                  </p>
                </div>
              </div>
            ) : (
              <div className="inspector-empty">
                <Info size={32} className="text-muted" />
                <p>Click any node in the graph to inspect its properties and infrastructure ties.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
