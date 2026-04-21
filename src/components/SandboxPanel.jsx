import React from 'react';
import { motion } from 'framer-motion';

export default function SandboxPanel({ result }) {
  if (!result) return null;

  const verdictColors = { malicious: 'var(--danger)', suspicious: 'var(--warning)', clean: 'var(--success)' };
  const verdictIcons = { malicious: '🔴', suspicious: '🟡', clean: '🟢' };
  const behaviorIcons = { execution: '⚡', persistence: '📌', evasion: '🛡️', c2: '📡', credential_theft: '🔑', spyware: '👁️', exfiltration: '📤', macro: '📄', obfuscation: '🔒' };

  return (
    <motion.div className="card analysis-full" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">🔬</span> Sandbox Analysis</div>
        <span className="badge badge-neutral">Hybrid Analysis-Style</span>
      </div>

      {/* Overall Verdict */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '20px', padding: '16px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', borderLeft: `4px solid ${verdictColors[result.verdict]}` }}>
        <div style={{ textAlign: 'center', minWidth: '100px' }}>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, color: verdictColors[result.verdict] }}>{result.overallScore}</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>/100 Maliciousness</div>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '1.1rem', fontWeight: 800, color: verdictColors[result.verdict], textTransform: 'uppercase', marginBottom: '4px' }}>
            {verdictIcons[result.verdict]} {result.verdict}
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            {result.totalFiles} file(s) analyzed • {result.maliciousFiles} malicious
          </div>
        </div>
      </div>

      {/* File Results */}
      {result.files.map((file, fi) => (
        <div key={fi} style={{ marginBottom: '20px', padding: '16px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', fontWeight: 700 }}>{file.staticResult.filename}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {file.staticResult.magicType} • Entropy: {file.staticResult.entropy}
              </div>
            </div>
            <span className={`badge ${file.verdict === 'malicious' ? 'badge-fail' : file.verdict === 'suspicious' ? 'badge-warn' : 'badge-pass'}`}>
              {file.maliciousnessScore}/100
            </span>
          </div>

          {/* Malware Family */}
          {file.family && (
            <div style={{ padding: '10px', background: 'var(--danger-dim)', borderRadius: 'var(--radius-sm)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>🦠</span>
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--danger)' }}>{file.family.name}</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{file.family.category} • {file.family.confidence}% confidence</div>
              </div>
            </div>
          )}

          {/* YARA Matches */}
          {file.yaraMatches.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase' }}>🔍 YARA Rules ({file.yaraMatches.length} matches)</div>
              {file.yaraMatches.map((m, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 8px', marginBottom: '2px', fontSize: '0.75rem' }}>
                  <span className={`badge ${m.severity === 'critical' ? 'badge-fail' : m.severity === 'high' ? 'badge-warn' : 'badge-info'}`} style={{ fontSize: '0.65rem' }}>{m.severity}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontSize: '0.7rem' }}>{m.name}</span>
                  <span style={{ color: 'var(--text-muted)' }}>— {m.desc}</span>
                </div>
              ))}
            </div>
          )}

          {/* Behavioral Indicators */}
          {file.behaviors.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase' }}>⚡ Behavioral Indicators</div>
              {file.behaviors.map((b, i) => (
                <div key={i} className={`finding finding-${b.severity}`} style={{ padding: '8px 12px', marginBottom: '4px' }}>
                  <span className="finding-icon">{behaviorIcons[b.type] || '📌'}</span>
                  <div>
                    <div className="finding-title" style={{ fontSize: '0.8rem' }}>{b.type.replace('_', ' ').toUpperCase()}</div>
                    <div className="finding-desc" style={{ fontSize: '0.7rem' }}>{b.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Process Tree */}
          {file.processTree.length > 1 && (
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase' }}>🌳 Process Tree</div>
              <div style={{ padding: '10px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                {file.processTree.map((p, i) => (
                  <div key={i} style={{ paddingLeft: `${(p.parent ? Math.min(i, 4) : 0) * 16}px`, marginBottom: '3px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>{p.parent ? '└─' : '●'}</span>
                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{p.name}</span>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>PID:{p.pid}</span>
                    <span style={{ color: 'var(--text-secondary)', fontSize: '0.65rem' }}>— {p.action}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}

      {result.files.length === 0 && (
        <div className="empty-state" style={{ padding: '20px' }}>
          <div className="empty-title">No attachments to sandbox</div>
          <div className="empty-desc">Body content was scanned for embedded threats</div>
        </div>
      )}
    </motion.div>
  );
}
