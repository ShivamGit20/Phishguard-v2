import React from 'react';
import { motion } from 'framer-motion';

export default function AttachmentAnalysis({ result }) {
  if (!result) return null;
  const { findings, analyzed } = result;

  const riskColors = { critical: 'var(--danger)', high: '#ff6b6b', medium: 'var(--warning)', low: 'var(--success)', none: 'var(--text-muted)' };
  const riskIcons = { critical: '💀', high: '⚠️', medium: '⚡', low: '✅', none: '📎' };

  return (
    <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📎</span> Attachment Analysis</div>
        <span className="badge badge-info">{analyzed.length} attachments</span>
      </div>

      {analyzed.length === 0 ? (
        <div className="empty-state" style={{ padding: '20px' }}>
          <div className="empty-title">No attachments found</div>
        </div>
      ) : (
        <>
          {analyzed.map((att, i) => (
            <div key={i} style={{ marginBottom: '12px', padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', borderLeft: `3px solid ${riskColors[att.riskLevel]}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '1.2rem' }}>{riskIcons[att.riskLevel]}</span>
                  <div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600 }}>{att.filename}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{att.extension} • {att.contentType || 'unknown type'}</div>
                  </div>
                </div>
                <span className={`badge ${att.riskLevel === 'critical' || att.riskLevel === 'high' ? 'badge-fail' : att.riskLevel === 'medium' ? 'badge-warn' : 'badge-pass'}`}>
                  Risk: {att.riskScore}
                </span>
              </div>
            </div>
          ))}

          {findings.map((f, i) => (
            <div key={i} className={`finding finding-${f.severity}`}>
              <span className="finding-icon">{f.severity === 'critical' ? '🔴' : '🟠'}</span>
              <div>
                <div className="finding-title">{f.title}</div>
                <div className="finding-desc">{f.description}</div>
              </div>
            </div>
          ))}
        </>
      )}
    </motion.div>
  );
}
