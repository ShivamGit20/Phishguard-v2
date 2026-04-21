import React from 'react';
import { motion } from 'framer-motion';

export default function ThreatTimeline({ findings }) {
  if (!findings || findings.length === 0) return null;

  const sorted = [...findings].sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
  });

  const typeIcons = { header: '📨', url: '🔗', content: '📝', attachment: '📎' };
  const sevClass = { critical: 'tl-danger', high: 'tl-danger', medium: 'tl-warning', low: 'tl-success' };

  return (
    <motion.div className="card analysis-full" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📈</span> Threat Timeline</div>
        <span className="badge badge-info">{findings.length} events</span>
      </div>

      <div className="timeline">
        {sorted.map((f, i) => (
          <motion.div
            key={i}
            className={`timeline-item ${sevClass[f.severity] || ''}`}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.05 * i }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span>{typeIcons[f.type] || '📌'}</span>
              <span className={`badge badge-${f.severity === 'critical' || f.severity === 'high' ? 'fail' : f.severity === 'medium' ? 'warn' : 'pass'}`}>
                {f.severity.toUpperCase()}
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{f.type}</span>
            </div>
            <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>{f.title}</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{f.description}</div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
