import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { defangBulk, refangBulk, defangURL, defangIP, defangEmail } from '../../utils/defanger';

export default function URLDefanger() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('defang');
  const [copied, setCopied] = useState(false);

  const handleProcess = () => {
    if (!input.trim()) return;
    const result = mode === 'defang' ? defangBulk(input) : refangBulk(input);
    setOutput(result);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div>
      <div className="tabs" style={{ marginBottom: '12px' }}>
        <button className={`tab-btn ${mode === 'defang' ? 'active' : ''}`} onClick={() => setMode('defang')}>🔓 Defang</button>
        <button className={`tab-btn ${mode === 'refang' ? 'active' : ''}`} onClick={() => setMode('refang')}>🔗 Refang</button>
      </div>

      <textarea className="textarea" value={input} onChange={e => setInput(e.target.value)}
        placeholder={mode === 'defang' ? 'Paste URLs, IPs, or emails to defang...\ne.g., https://malicious.com\n192.168.1.1\nuser@evil.com' : 'Paste defanged text to refang...\ne.g., hxxps[://]malicious[.]com'}
        style={{ minHeight: '120px', marginBottom: '12px' }} />

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <button className="btn btn-primary btn-sm" onClick={handleProcess} disabled={!input.trim()}>
          {mode === 'defang' ? '🔓 Defang' : '🔗 Refang'}
        </button>
      </div>

      {output && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>Result</span>
            <button className="btn btn-secondary btn-sm" onClick={handleCopy} style={{ fontSize: '0.75rem' }}>
              {copied ? '✅ Copied!' : '📋 Copy'}
            </button>
          </div>
          <div style={{ padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', borderLeft: '3px solid var(--accent-cyan)' }}>
            {output}
          </div>
        </motion.div>
      )}
    </div>
  );
}
