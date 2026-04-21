import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { extractIOCs, exportAsJSON, exportAsCSV, downloadFile, getTypeLabel, getTypeIcon } from '../../utils/iocExtractor';

export default function IOCExtractorTool() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);

  const handleExtract = () => {
    if (input.trim()) setResults(extractIOCs(input));
  };

  const handleExportJSON = () => {
    if (results) downloadFile(exportAsJSON(results), 'iocs.json', 'application/json');
  };

  const handleExportCSV = () => {
    if (results) downloadFile(exportAsCSV(results), 'iocs.csv', 'text/csv');
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div>
      <textarea className="textarea" value={input} onChange={e => setInput(e.target.value)}
        placeholder="Paste email content, logs, or any text to extract IOCs..." style={{ minHeight: '140px', marginBottom: '12px' }} />
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <button className="btn btn-primary btn-sm" onClick={handleExtract} disabled={!input.trim()}>🧬 Extract IOCs</button>
        {results && results.total > 0 && (
          <>
            <button className="btn btn-secondary btn-sm" onClick={handleExportJSON}>📥 JSON</button>
            <button className="btn btn-secondary btn-sm" onClick={handleExportCSV}>📥 CSV</button>
          </>
        )}
      </div>

      {results && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
            Found <strong style={{ color: 'var(--accent-cyan)' }}>{results.total}</strong> indicators across {Object.keys(results.categories).length} categories
          </div>
          {Object.entries(results.categories).map(([type, values]) => (
            <div key={type} style={{ marginBottom: '16px' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>{getTypeIcon(type)}</span> {getTypeLabel(type)} <span className="badge badge-neutral">{values.length}</span>
              </div>
              {values.map((val, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)', marginBottom: '3px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                  <span style={{ wordBreak: 'break-all' }}>{val}</span>
                  <button className="btn btn-secondary btn-sm" onClick={() => handleCopy(val)} style={{ padding: '2px 8px', fontSize: '0.7rem', marginLeft: '8px', flexShrink: 0 }}>📋</button>
                </div>
              ))}
            </div>
          ))}
          {results.total === 0 && (
            <div className="empty-state" style={{ padding: '20px' }}>
              <div className="empty-title">No IOCs found</div>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
