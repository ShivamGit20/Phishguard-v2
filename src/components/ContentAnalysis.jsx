import React from 'react';
import { motion } from 'framer-motion';

export default function ContentAnalysis({ result }) {
  if (!result) return null;
  const { findings, urgencyScore, socialScore } = result;

  return (
    <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📝</span> Content Analysis</div>
        <span className="badge badge-info">{findings.length} findings</span>
      </div>

      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px' }}>
        <div style={{ flex: 1, padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Urgency Score</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: urgencyScore >= 8 ? 'var(--danger)' : urgencyScore >= 4 ? 'var(--warning)' : 'var(--success)' }}>{urgencyScore}</div>
        </div>
        <div style={{ flex: 1, padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', textAlign: 'center' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Social Engineering</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: socialScore >= 10 ? 'var(--danger)' : socialScore >= 5 ? 'var(--warning)' : 'var(--success)' }}>{socialScore}</div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state" style={{ padding: '20px' }}>
          <div className="empty-title">No suspicious content patterns detected</div>
        </div>
      ) : (
        findings.map((f, i) => (
          <div key={i} className={`finding finding-${f.severity}`}>
            <span className="finding-icon">{f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🟢'}</span>
            <div>
              <div className="finding-title">{f.title}</div>
              <div className="finding-desc">{f.description}</div>
            </div>
          </div>
        ))
      )}
    </motion.div>
  );
}
