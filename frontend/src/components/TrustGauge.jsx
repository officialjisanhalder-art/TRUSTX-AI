import React from 'react'
import './TrustGauge.css'

export default function TrustGauge({ score = 0, riskLevel = 'safe', riskLabel = '', confidence = 0, size = 180 }) {
  // Score is between 0 and 100
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)))
  
  // SVG circular gauge geometry
  const strokeWidth = 14
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (clampedScore / 100) * circumference

  // Color mapping
  const getColor = (s) => {
    if (s >= 80) return '#22c55e' // Green
    if (s >= 50) return '#eab308' // Amber / Yellow
    if (s >= 25) return '#f97316' // Orange
    return '#ef4444'             // Red
  }

  const scoreColor = getColor(clampedScore)

  return (
    <div className="trust-gauge-container">
      <div className="gauge-svg-wrapper" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="gauge-svg">
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated Value Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={scoreColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: 'stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
              transform: 'rotate(-90deg)',
              transformOrigin: '50% 50%',
            }}
          />
        </svg>

        {/* Central Display */}
        <div className="gauge-center-content">
          <span className="gauge-number" style={{ color: scoreColor }}>
            {clampedScore}
          </span>
          <span className="gauge-max">/ 100</span>
          <span className="gauge-sublabel">TRUST SCORE</span>
        </div>
      </div>

      {/* Risk Badge and Confidence */}
      <div className="gauge-meta">
        <div className={`gauge-badge badge-${riskLevel}`}>
          {riskLabel || riskLevel.toUpperCase()}
        </div>
        {confidence > 0 && (
          <div className="gauge-confidence">
            <span>Confidence: <strong>{confidence}%</strong></span>
          </div>
        )}
      </div>
    </div>
  )
}
