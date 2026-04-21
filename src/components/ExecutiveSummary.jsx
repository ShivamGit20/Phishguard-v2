import React from 'react';
import { motion } from 'framer-motion';

export default function ExecutiveSummary({ threatResult, segResult, sandboxResult, mitreResult, headerResult }) {
  if (!threatResult) return null;

  const score = threatResult.score;
  const seg = segResult || {};
  const sandbox = sandboxResult || {};
  const mitre = mitreResult || {};

  const overallVerdict = score >= 75 ? 'CRITICAL THREAT' : score >= 50 ? 'HIGH RISK' : score >= 25 ? 'MODERATE RISK' : score >= 10 ? 'LOW RISK' : 'CLEAN';
  const verdictColor = score >= 75 ? '#ff3b5c' : score >= 50 ? '#ff6b6b' : score >= 25 ? '#ffab00' : score >= 10 ? '#00e676' : '#525c72';
  const verdictBg = score >= 75 ? 'rgba(255,59,92,0.08)' : score >= 50 ? 'rgba(255,107,107,0.08)' : score >= 25 ? 'rgba(255,171,0,0.08)' : 'rgba(0,230,118,0.08)';

  // Build incident response recommendations
  const recommendations = [];
  if (seg.quarantine?.action === 'reject' || seg.quarantine?.action === 'quarantine') {
    recommendations.push({ priority: 'high', text: 'Do NOT interact with this email. Report to security team immediately.' });
  }
  if (seg.threatClass?.primary === 'phishing') {
    recommendations.push({ priority: 'high', text: 'Do not click any links or download attachments from this email.' });
    recommendations.push({ priority: 'medium', text: 'Check if any users have already clicked links — reset credentials if so.' });
  }
  if (seg.threatClass?.primary === 'malware' || sandbox?.verdict === 'malicious') {
    recommendations.push({ priority: 'critical', text: 'Quarantine any systems that opened the attachment. Run full malware scan.' });
    recommendations.push({ priority: 'high', text: 'Block sender domain and related IOCs at the network perimeter.' });
  }
  if (seg.becResult?.isBEC) {
    recommendations.push({ priority: 'critical', text: 'Verify any financial requests via out-of-band communication (phone call).' });
    recommendations.push({ priority: 'high', text: 'Alert finance team about potential BEC attack.' });
  }
  if (score >= 25) {
    recommendations.push({ priority: 'medium', text: 'Add sender domain to watchlist for monitoring.' });
    recommendations.push({ priority: 'low', text: 'Update user awareness training with this example.' });
  }
  if (recommendations.length === 0) {
    recommendations.push({ priority: 'low', text: 'No immediate action required. Email appears safe.' });
  }

  const priorityColors = { critical: 'var(--danger)', high: '#ff6b6b', medium: 'var(--warning)', low: 'var(--success)' };

  return (
    <motion.div className="card analysis-full" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}
      style={{ background: verdictBg, borderColor: `${verdictColor}30` }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">📋</span> Executive Summary</div>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{new Date().toLocaleString()}</span>
      </div>

      {/* Verdict Banner */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '20px', padding: '20px', background: 'var(--bg-card)', borderRadius: 'var(--radius-md)', border: `1px solid ${verdictColor}30` }}>
        <div style={{ textAlign: 'center', minWidth: '90px' }}>
          <div style={{ fontSize: '2.8rem', fontWeight: 900, color: verdictColor, lineHeight: 1 }}>{score}</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>THREAT SCORE</div>
        </div>
        <div style={{ width: '1px', height: '60px', background: 'var(--border-color)' }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: verdictColor, marginBottom: '6px' }}>{overallVerdict}</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
            {seg.quarantine?.action === 'reject' && 'This email has been classified as malicious and should be rejected at the gateway. '}
            {seg.quarantine?.action === 'quarantine' && 'This email has been flagged and should be quarantined for further review. '}
            {seg.threatClass?.primary !== 'clean' && `Classified as ${seg.threatClass?.primary} with ${seg.threatClass?.confidence}% confidence. `}
            {sandbox?.verdict === 'malicious' && `Sandbox analysis detected malicious behavior (score: ${sandbox.overallScore}/100). `}
            {mitre?.totalTechniques > 0 && `Mapped to ${mitre.totalTechniques} MITRE ATT&CK techniques across ${mitre.totalTactics} tactics.`}
          </div>
        </div>
      </div>

      {/* Key Indicators */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '8px', marginBottom: '20px' }}>
        {[
          { label: 'Gateway', value: seg.quarantine?.action?.toUpperCase() || 'N/A', color: seg.quarantine?.action === 'reject' ? 'var(--danger)' : seg.quarantine?.action === 'quarantine' ? 'var(--warning)' : 'var(--success)' },
          { label: 'Category', value: seg.threatClass?.primary?.toUpperCase() || 'N/A', color: seg.threatClass?.primary === 'clean' ? 'var(--success)' : 'var(--danger)' },
          { label: 'Spam Score', value: `${seg.spamResult?.score || 0}/10`, color: (seg.spamResult?.score || 0) >= 7 ? 'var(--danger)' : 'var(--success)' },
          { label: 'Sandbox', value: sandbox?.verdict?.toUpperCase() || 'N/A', color: sandbox?.verdict === 'malicious' ? 'var(--danger)' : sandbox?.verdict === 'suspicious' ? 'var(--warning)' : 'var(--success)' },
          { label: 'ATT&CK', value: `${mitre?.totalTechniques || 0} techniques`, color: (mitre?.totalTechniques || 0) > 3 ? 'var(--danger)' : 'var(--text-secondary)' },
          { label: 'Findings', value: threatResult.totalFindings, color: threatResult.totalFindings > 5 ? 'var(--danger)' : 'var(--text-secondary)' },
        ].map((item, i) => (
          <div key={i} style={{ padding: '10px', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)', textAlign: 'center', border: '1px solid var(--border-color)' }}>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>{item.label}</div>
            <div style={{ fontSize: '0.95rem', fontWeight: 800, color: item.color }}>{item.value}</div>
          </div>
        ))}
      </div>

      {/* Incident Response */}
      <div>
        <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '10px', color: 'var(--text-muted)' }}>🚨 Incident Response Recommendations</h4>
        {recommendations.map((r, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '8px 12px', marginBottom: '4px', borderLeft: `3px solid ${priorityColors[r.priority]}`, background: 'var(--bg-card)', borderRadius: '0 var(--radius-sm) var(--radius-sm) 0' }}>
            <span className={`badge ${r.priority === 'critical' ? 'badge-fail' : r.priority === 'high' ? 'badge-warn' : r.priority === 'medium' ? 'badge-info' : 'badge-pass'}`} style={{ fontSize: '0.6rem', whiteSpace: 'nowrap' }}>
              {r.priority.toUpperCase()}
            </span>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{r.text}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
