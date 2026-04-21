import React from 'react';
import { motion } from 'framer-motion';

export default function URLAnalysis({ result }) {
  if (!result) return null;
  const { findings, urls } = result;

  return (
    <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">🔗</span> URL Analysis</div>
        <span className="badge badge-info">{urls.length} URLs found</span>
      </div>

      {urls.length === 0 ? (
        <div className="empty-state" style={{ padding: '30px' }}>
          <div className="empty-title">No URLs detected</div>
        </div>
      ) : (
        <>
          {urls.map((u, i) => (
            <div key={i} style={{ marginBottom: '12px', padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', borderLeft: `3px solid ${u.riskScore >= 50 ? 'var(--danger)' : u.riskScore >= 20 ? 'var(--warning)' : 'var(--success)'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)', wordBreak: 'break-all', flex: 1 }}>
                  {u.url.length > 80 ? u.url.substring(0, 80) + '...' : u.url}
                </span>
                <span className={`badge ${u.riskScore >= 50 ? 'badge-fail' : u.riskScore >= 20 ? 'badge-warn' : 'badge-pass'}`} style={{ marginLeft: '8px', whiteSpace: 'nowrap' }}>
                  Risk: {u.riskScore}
                </span>
              </div>
              {u.isShortener && <span className="badge badge-warn" style={{ marginRight: '4px' }}>🔗 Shortener</span>}
              {u.hostname && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Host: {u.hostname}</span>}
            </div>
          ))}

          {findings.length > 0 && (
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '10px', color: 'var(--text-muted)' }}>Findings</h4>
              {findings.map((f, i) => (
                <div key={i} className={`finding finding-${f.severity}`}>
                  <span className="finding-icon">{f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : '🟡'}</span>
                  <div>
                    <div className="finding-title">{f.title}</div>
                    <div className="finding-desc">{f.description}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </motion.div>
  );
}
