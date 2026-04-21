import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { analyzeWhois } from '../../utils/whoisHeuristics';

export default function WhoisTool() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);

  const handleAnalyze = () => {
    if (!input.trim()) return;
    setResult(analyzeWhois(input.trim().toLowerCase()));
  };

  const riskColors = { critical: 'var(--danger)', high: '#ff6b6b', medium: 'var(--warning)', low: 'var(--success)', none: 'var(--text-muted)' };

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <input className="input" value={input} onChange={e => setInput(e.target.value)}
          placeholder="Enter a domain to analyze (e.g., suspicious-login.xyz)" onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          style={{ fontFamily: 'var(--font-mono)' }} />
        <button className="btn btn-primary btn-sm" onClick={handleAnalyze} disabled={!input.trim()} style={{ whiteSpace: 'nowrap' }}>📋 Analyze</button>
      </div>

      {result && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          {/* Risk Score */}
          <div style={{ padding: '16px', borderRadius: 'var(--radius-md)', marginBottom: '16px',
            background: result.level === 'critical' || result.level === 'high' ? 'var(--danger-dim)' : result.level === 'medium' ? 'var(--warning-dim)' : 'var(--success-dim)',
            borderLeft: `3px solid ${riskColors[result.level]}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: riskColors[result.level] }}>
                  Domain Risk: {result.riskScore}/100
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {result.level === 'critical' ? 'Highly suspicious domain' : result.level === 'high' ? 'Suspicious patterns detected' : result.level === 'medium' ? 'Some risk indicators' : 'Low risk'}
                </div>
              </div>
              <span className={`badge ${result.level === 'critical' || result.level === 'high' ? 'badge-fail' : result.level === 'medium' ? 'badge-warn' : 'badge-pass'}`}>
                {result.level.toUpperCase()}
              </span>
            </div>
          </div>

          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px', marginBottom: '16px' }}>
            {[
              { label: 'TLD', value: result.tld, color: result.isTrustedTLD ? 'var(--success)' : 'var(--warning)' },
              { label: 'Length', value: result.domainLength, color: result.domainLength > 30 ? 'var(--warning)' : 'var(--text-primary)' },
              { label: 'Depth', value: result.subdomainDepth, color: result.subdomainDepth > 3 ? 'var(--warning)' : 'var(--text-primary)' },
              { label: 'Entropy', value: result.entropy, color: parseFloat(result.entropy) > 3.5 ? 'var(--warning)' : 'var(--text-primary)' },
            ].map((s, i) => (
              <div key={i} style={{ padding: '10px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', textAlign: 'center' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>{s.label}</div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: s.color }}>{s.value}</div>
              </div>
            ))}
          </div>

          {/* Findings */}
          {result.findings.map((f, i) => (
            <div key={i} className={`finding finding-${f.severity}`}>
              <span className="finding-icon">{f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : '🟢'}</span>
              <div>
                <div className="finding-title">{f.title}</div>
                <div className="finding-desc">{f.description}</div>
              </div>
            </div>
          ))}
        </motion.div>
      )}
    </div>
  );
}
