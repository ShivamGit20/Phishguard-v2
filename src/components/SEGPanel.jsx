import React from 'react';
import { motion } from 'framer-motion';

export default function SEGPanel({ result }) {
  if (!result) return null;
  const { spamResult, threatClass, urlDefense, becResult, policyResult, quarantine } = result;

  const actionColors = { reject: 'var(--danger)', quarantine: 'var(--warning)', deliver: 'var(--success)' };
  const actionIcons = { reject: '🚫', quarantine: '⚠️', deliver: '✅' };
  const actionLabels = { reject: 'REJECT', quarantine: 'QUARANTINE', deliver: 'DELIVER' };

  const categoryColors = { phishing: '#ff3b5c', malware: '#ff6b6b', bec: '#ffab00', spam: '#7c6aff', clean: '#00e676' };
  const categoryIcons = { phishing: '🎣', malware: '🦠', bec: '💼', spam: '📧', clean: '✅' };

  return (
    <motion.div className="card analysis-full" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">🏢</span> Secure Email Gateway</div>
        <span className="badge badge-neutral">Proofpoint-Style</span>
      </div>

      {/* Gateway Verdict */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '20px' }}>
        {/* Quarantine Decision */}
        <div className="seg-verdict-card" style={{ padding: '20px', borderRadius: 'var(--radius-md)', background: 'var(--bg-input)', borderLeft: `4px solid ${actionColors[quarantine.action]}`, textAlign: 'center' }}>
          <div style={{ fontSize: '2rem', marginBottom: '6px' }}>{actionIcons[quarantine.action]}</div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: actionColors[quarantine.action] }}>{actionLabels[quarantine.action]}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Confidence: {quarantine.confidence}%</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '4px' }}>{quarantine.reasons[0]}</div>
        </div>

        {/* Threat Category */}
        <div style={{ padding: '20px', borderRadius: 'var(--radius-md)', background: 'var(--bg-input)', textAlign: 'center' }}>
          <div style={{ fontSize: '2rem', marginBottom: '6px' }}>{categoryIcons[threatClass.primary]}</div>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: categoryColors[threatClass.primary], textTransform: 'uppercase' }}>{threatClass.primary}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Confidence: {threatClass.confidence}%</div>
        </div>

        {/* Spam Score */}
        <div style={{ padding: '20px', borderRadius: 'var(--radius-md)', background: 'var(--bg-input)', textAlign: 'center' }}>
          <div style={{ fontSize: '2rem', fontWeight: 900, color: spamResult.score >= 7 ? 'var(--danger)' : spamResult.score >= 4 ? 'var(--warning)' : 'var(--success)' }}>
            {spamResult.score}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>/10 Spam Score</div>
          <div style={{ fontSize: '0.7rem', marginTop: '4px' }}>
            <span className={`badge ${spamResult.verdict === 'spam' ? 'badge-fail' : spamResult.verdict === 'suspect' ? 'badge-warn' : 'badge-pass'}`}>
              {spamResult.verdict.toUpperCase()}
            </span>
          </div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '4px' }}>{spamResult.rulesTriggered}/{spamResult.rulesChecked} rules triggered</div>
        </div>
      </div>

      {/* Two column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        {/* Policy Compliance */}
        <div>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '10px', color: 'var(--text-muted)' }}>📋 Policy Compliance ({policyResult.passed}/{policyResult.total})</h4>
          {policyResult.checks.map((c, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 10px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', marginBottom: '4px', fontSize: '0.8rem' }}>
              <span>{c.status === 'pass' ? '✅' : c.status === 'fail' ? '❌' : '⚠️'}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: '0.8rem' }}>{c.policy}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{c.detail}</div>
              </div>
            </div>
          ))}
        </div>

        {/* BEC Detection + URL Defense */}
        <div>
          {/* BEC */}
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '10px', color: 'var(--text-muted)' }}>💼 BEC Detection</h4>
          <div style={{ padding: '10px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', marginBottom: '12px', borderLeft: `3px solid ${becResult.isBEC ? 'var(--danger)' : 'var(--success)'}` }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: becResult.isBEC ? 'var(--danger)' : 'var(--success)' }}>
              {becResult.isBEC ? '⚠️ BEC Indicators Detected' : '✅ No BEC Indicators'}
            </div>
            {becResult.indicators.map((ind, i) => (
              <div key={i} style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px', paddingLeft: '8px', borderLeft: `2px solid ${ind.level === 'critical' ? 'var(--danger)' : ind.level === 'high' ? 'var(--warning)' : 'var(--text-muted)'}` }}>
                {ind.text}
              </div>
            ))}
          </div>

          {/* URL Defense */}
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '10px', color: 'var(--text-muted)' }}>🔗 URL Defense ({urlDefense.totalURLs} URLs)</h4>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
            <span className="badge badge-fail" style={{ marginRight: '6px' }}>🚫 {urlDefense.blocked} blocked</span>
            <span className="badge badge-warn">🔄 {urlDefense.rewritten} rewritten</span>
          </div>
        </div>
      </div>

      {/* Triggered Rules (collapsed) */}
      {spamResult.triggered.length > 0 && (
        <details style={{ marginTop: '16px' }}>
          <summary style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', cursor: 'pointer', padding: '8px 0' }}>
            📜 Triggered Rules ({spamResult.triggered.length})
          </summary>
          <div style={{ marginTop: '8px' }}>
            {spamResult.triggered.map((r, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', background: i % 2 === 0 ? 'var(--bg-input)' : 'transparent', borderRadius: 'var(--radius-sm)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{r.id}</span>
                <span style={{ color: 'var(--text-muted)', flex: 1, marginLeft: '12px' }}>{r.desc}</span>
                <span style={{ color: 'var(--warning)', fontWeight: 600 }}>+{r.score}</span>
              </div>
            ))}
          </div>
        </details>
      )}
    </motion.div>
  );
}
