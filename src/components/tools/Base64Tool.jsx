import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { encodeBase64, decodeBase64, detectBase64Strings, analyzeDecodedContent } from '../../utils/base64Decoder';

export default function Base64Tool() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState('decode');
  const [detected, setDetected] = useState([]);
  const [threats, setThreats] = useState([]);

  const handleProcess = () => {
    if (!input.trim()) return;
    if (mode === 'decode') {
      const result = decodeBase64(input);
      setOutput(result);
      setThreats(analyzeDecodedContent(result));
      setDetected([]);
    } else if (mode === 'encode') {
      setOutput(encodeBase64(input));
      setThreats([]);
      setDetected([]);
    } else {
      const found = detectBase64Strings(input);
      setDetected(found);
      setOutput('');
      const allThreats = [];
      for (const f of found) {
        allThreats.push(...analyzeDecodedContent(f.decoded));
      }
      setThreats(allThreats);
    }
  };

  return (
    <div>
      <div className="tabs" style={{ marginBottom: '12px' }}>
        <button className={`tab-btn ${mode === 'decode' ? 'active' : ''}`} onClick={() => { setMode('decode'); setOutput(''); setDetected([]); }}>🔤 Decode</button>
        <button className={`tab-btn ${mode === 'encode' ? 'active' : ''}`} onClick={() => { setMode('encode'); setOutput(''); setDetected([]); }}>🔒 Encode</button>
        <button className={`tab-btn ${mode === 'detect' ? 'active' : ''}`} onClick={() => { setMode('detect'); setOutput(''); setDetected([]); }}>🔍 Auto-Detect</button>
      </div>

      <textarea className="textarea" value={input} onChange={e => setInput(e.target.value)}
        placeholder={mode === 'decode' ? 'Paste Base64 string to decode...' : mode === 'encode' ? 'Enter text to encode as Base64...' : 'Paste text to auto-detect Base64 strings...'}
        style={{ minHeight: '120px', marginBottom: '12px' }} />

      <button className="btn btn-primary btn-sm" onClick={handleProcess} disabled={!input.trim()} style={{ marginBottom: '16px' }}>
        {mode === 'decode' ? '🔤 Decode' : mode === 'encode' ? '🔒 Encode' : '🔍 Detect & Decode'}
      </button>

      {output && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ marginBottom: '12px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>Result</div>
          <div style={{ padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', borderLeft: '3px solid var(--accent-cyan)', maxHeight: '200px', overflow: 'auto' }}>
            {output}
          </div>
        </motion.div>
      )}

      {detected.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '8px' }}>
            Found {detected.length} Base64 string(s)
          </div>
          {detected.map((d, i) => (
            <div key={i} style={{ marginBottom: '12px', padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Encoded ({d.length} chars)</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '8px', wordBreak: 'break-all' }}>
                {d.encoded.substring(0, 80)}{d.encoded.length > 80 ? '...' : ''}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>Decoded</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', padding: '8px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', wordBreak: 'break-all', borderLeft: '3px solid var(--success)' }}>
                {d.decoded.substring(0, 200)}{d.decoded.length > 200 ? '...' : ''}
              </div>
            </div>
          ))}
        </motion.div>
      )}

      {threats.length > 0 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} style={{ marginTop: '12px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--danger)', marginBottom: '8px' }}>⚠️ Threats Detected in Decoded Content</div>
          {threats.map((t, i) => (
            <div key={i} className={`finding finding-${t.severity}`}>
              <span className="finding-icon">{t.severity === 'critical' ? '🔴' : '🟠'}</span>
              <div>
                <div className="finding-title">{t.description}</div>
                <div className="finding-desc">{t.detail}</div>
              </div>
            </div>
          ))}
        </motion.div>
      )}
    </div>
  );
}
