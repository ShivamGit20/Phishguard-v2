import React from 'react';
import { motion } from 'framer-motion';

export default function HeaderAnalysis({ result }) {
  if (!result) return null;
  const { spf, dkim, dmarc, receivedChain, from, replyTo, returnPath, subject, findings } = result;

  const VerdictBadge = ({ proto }) => {
    const cls = proto.result === 'pass' ? 'badge-pass' : proto.result === 'fail' || proto.result === 'softfail' ? 'badge-fail' : 'badge-warn';
    const icon = proto.result === 'pass' ? '✅' : proto.result === 'fail' || proto.result === 'softfail' ? '❌' : '⚠️';
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px', flex: 1, padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)' }}>
        <span style={{ fontSize: '1.5rem' }}>{icon}</span>
        <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>{proto.protocol}</span>
        <span className={`badge ${cls}`}>{proto.result || 'none'}</span>
      </div>
    );
  };

  return (
    <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📨</span> Header Analysis</div>
        <span className="badge badge-info">{findings.length} findings</span>
      </div>

      {/* Auth Verdicts */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '20px' }}>
        <VerdictBadge proto={spf} />
        <VerdictBadge proto={dkim} />
        <VerdictBadge proto={dmarc} />
      </div>

      {/* Key headers */}
      <div style={{ marginBottom: '16px' }}>
        <table className="data-table">
          <tbody>
            <tr><td style={{ fontWeight: 600, width: '120px', color: 'var(--text-muted)' }}>Subject</td><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{subject}</td></tr>
            <tr><td style={{ fontWeight: 600, color: 'var(--text-muted)' }}>From</td><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{from}</td></tr>
            {replyTo && <tr><td style={{ fontWeight: 600, color: 'var(--text-muted)' }}>Reply-To</td><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{replyTo}</td></tr>}
            {returnPath && <tr><td style={{ fontWeight: 600, color: 'var(--text-muted)' }}>Return-Path</td><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{returnPath}</td></tr>}
          </tbody>
        </table>
      </div>

      {/* Received chain */}
      {receivedChain.length > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 600, marginBottom: '10px', color: 'var(--text-muted)' }}>📡 Email Routing ({receivedChain.length} hops)</h4>
          {receivedChain.map((hop, i) => (
            <div key={i} style={{ display: 'flex', gap: '8px', padding: '8px 12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', marginBottom: '4px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
              <span className="badge badge-neutral" style={{ minWidth: '50px' }}>Hop {hop.hop}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{hop.from} → {hop.by}</span>
              {hop.fromIP && <span className="badge badge-warn">{hop.fromIP}</span>}
            </div>
          ))}
        </div>
      )}

      {/* Findings */}
      {findings.map((f, i) => (
        <div key={i} className={`finding finding-${f.severity}`}>
          <span className="finding-icon">{f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🟢'}</span>
          <div>
            <div className="finding-title">{f.title}</div>
            <div className="finding-desc">{f.description}</div>
          </div>
        </div>
      ))}
    </motion.div>
  );
}
