import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { hashText, hashFile, virusTotalURL } from '../../utils/hashGenerator';

export default function HashGenerator() {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState(null);
  const [mode, setMode] = useState('text');
  const [fileName, setFileName] = useState('');
  const [copied, setCopied] = useState('');
  const fileRef = useRef(null);

  const handleHashText = async () => {
    if (!input.trim()) return;
    const result = await hashText(input);
    setHashes(result);
  };

  const handleFileSelect = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setFileName(file.name);
    const result = await hashFile(file);
    setHashes(result);
  };

  const handleCopy = (hash, label) => {
    navigator.clipboard.writeText(hash);
    setCopied(label);
    setTimeout(() => setCopied(''), 2000);
  };

  const HashRow = ({ label, value }) => (
    <div style={{ marginBottom: '10px', padding: '12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{label}</span>
        <div style={{ display: 'flex', gap: '4px' }}>
          <button className="btn btn-secondary btn-sm" onClick={() => handleCopy(value, label)} style={{ padding: '2px 8px', fontSize: '0.7rem' }}>
            {copied === label ? '✅' : '📋'}
          </button>
          <a href={virusTotalURL(value)} target="_blank" rel="noopener noreferrer" className="btn btn-secondary btn-sm" style={{ padding: '2px 8px', fontSize: '0.7rem', textDecoration: 'none' }}>
            🔍 VT
          </a>
        </div>
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', wordBreak: 'break-all', color: 'var(--text-primary)' }}>{value}</div>
    </div>
  );

  return (
    <div>
      <div className="tabs" style={{ marginBottom: '12px' }}>
        <button className={`tab-btn ${mode === 'text' ? 'active' : ''}`} onClick={() => { setMode('text'); setHashes(null); }}>📝 Text</button>
        <button className={`tab-btn ${mode === 'file' ? 'active' : ''}`} onClick={() => { setMode('file'); setHashes(null); }}>📁 File</button>
      </div>

      {mode === 'text' ? (
        <>
          <textarea className="textarea" value={input} onChange={e => setInput(e.target.value)}
            placeholder="Enter text to hash..." style={{ minHeight: '100px', marginBottom: '12px' }} />
          <button className="btn btn-primary btn-sm" onClick={handleHashText} disabled={!input.trim()} style={{ marginBottom: '16px' }}>
            #️⃣ Generate Hashes
          </button>
        </>
      ) : (
        <div className="drop-zone" onClick={() => fileRef.current?.click()} style={{ marginBottom: '16px' }}>
          <div className="drop-icon">📁</div>
          <div className="drop-text">{fileName || 'Click to select a file'}</div>
          <div className="drop-hint">Any file type supported</div>
          <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={handleFileSelect} />
        </div>
      )}

      {hashes && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          {hashes.filename && (
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              File: <strong>{hashes.filename}</strong> ({(hashes.size / 1024).toFixed(1)} KB)
            </div>
          )}
          <HashRow label="MD5" value={hashes.md5} />
          <HashRow label="SHA-1" value={hashes.sha1} />
          <HashRow label="SHA-256" value={hashes.sha256} />
        </motion.div>
      )}
    </div>
  );
}
