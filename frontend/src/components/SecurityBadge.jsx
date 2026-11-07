import React from 'react'

export default function SecurityBadge({ level = 'safe', text = '', style = {} }) {
  const getStyle = () => {
    switch (level.toLowerCase()) {
      case 'safe':
        return { bg: 'rgba(34, 197, 94, 0.15)', text: '#4ade80', border: 'rgba(34, 197, 94, 0.4)' }
      case 'medium':
        return { bg: 'rgba(234, 179, 8, 0.15)', text: '#facc15', border: 'rgba(234, 179, 8, 0.4)' }
      case 'high':
        return { bg: 'rgba(249, 115, 22, 0.15)', text: '#fb923c', border: 'rgba(249, 115, 22, 0.4)' }
      case 'critical':
        return { bg: 'rgba(239, 68, 68, 0.18)', text: '#f87171', border: 'rgba(239, 68, 68, 0.4)' }
      default:
        return { bg: 'rgba(148, 163, 184, 0.12)', text: '#94a3b8', border: 'rgba(148, 163, 184, 0.3)' }
    }
  }

  const s = getStyle()

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '3px 10px',
        borderRadius: '12px',
        fontSize: '0.75rem',
        fontWeight: '700',
        letterSpacing: '0.4px',
        textTransform: 'uppercase',
        backgroundColor: s.bg,
        color: s.text,
        border: `1px solid ${s.border}`,
        ...style,
      }}
    >
      {text || level}
    </span>
  )
}
