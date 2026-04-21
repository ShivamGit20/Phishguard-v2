import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { detectHomographs, analyzeDomainChars } from '../../utils/homographDetector';

export default function HomographDetector() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [chars, setChars] = useState([]);

  const handleAnalyze = () => {
    if (!input.trim()) return;
    const domain = input.trim().toLowerCase();
    setResult(detectHomographs(domain));
    setChars(analyzeDomainChars(domain));
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <input className="input" value={input} onChange={e => setInput(e.target.value)}
          placeholder="Enter a domain to check (e.g., gооgle.com)" onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
          style={{ fontFamily: 'var(--font-mono)' }} />
        <button className="btn btn-primary btn-sm" onClick={handleAnalyze} disabled={!input.trim()} style={{ whiteSpace: 'nowrap' }}>🎭 Analyze</button>
      </div>

      {result && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          {/* Verdict */}
          <div style={{ padding: '16px', borderRadius: 'var(--radius-md)', marginBottom: '16px',
            background: result.isHomograph ? 'var(--danger-dim)' : 'var(--success-dim)',
            borderLeft: `3px solid ${result.isHomograph ? 'var(--danger)' : 'var(--success)'}` }}>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: result.isHomograph ? 'var(--danger)' : 'var(--success)', marginBottom: '4px' }}>
              {result.isHomograph ? '⚠️ Homograph Attack Detected!' : '✅ No Homograph Characters Found'}
            </div>
            {result.isHomograph && (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Found {result.confusables.length} lookalike character(s).
                {result.matchedBrand && <> This domain appears to impersonate <strong style={{ color: 'var(--danger)' }}>{result.matchedBrand}</strong>.</>}
              </div>
            )}
            {result.isHomograph && (
              <div style={{ marginTop: '8px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                ASCII equivalent: <strong style={{ fontFamily: 'var(--font-mono)' }}>{result.asciiEquivalent}</strong>
              </div>
            )}
          </div>

          {/* Character breakdown */}
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>Character Analysis</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '16px' }}>
            {chars.map((c, i) => (
              <div key={i} style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '8px 6px',
                background: c.isConfusable ? 'var(--danger-dim)' : 'var(--bg-input)',
                borderRadius: 'var(--radius-sm)', minWidth: '44px',
                border: c.isConfusable ? '1px solid var(--danger)' : '1px solid var(--border-color)',
              }}>
                <span style={{ fontSize: '1.2rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: c.isConfusable ? 'var(--danger)' : 'var(--text-primary)' }}>{c.char}</span>
                <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: '2px' }}>U+{c.codePoint}</span>
                <span style={{ fontSize: '0.55rem', color: c.isConfusable ? 'var(--danger)' : 'var(--text-muted)' }}>{c.script}</span>
                {c.isConfusable && <span style={{ fontSize: '0.6rem', color: 'var(--warning)', marginTop: '2px' }}>→ {c.looksLike}</span>}
              </div>
            ))}
          </div>

          {/* Confusable details */}
          {result.confusables.length > 0 && (
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>Confusable Characters</div>
              {result.confusables.map((c, i) => (
                <div key={i} className="finding finding-critical">
                  <span className="finding-icon">🎭</span>
                  <div>
                    <div className="finding-title">Position {c.position}: "{c.original}" looks like "{c.looksLike}"</div>
                    <div className="finding-desc">Unicode U+{c.codePoint} ({c.unicodeName}) — visually identical to ASCII "{c.looksLike}"</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
