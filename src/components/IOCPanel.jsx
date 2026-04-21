import React from 'react';
import { motion } from 'framer-motion';
import { getTypeLabel, getTypeIcon } from '../utils/iocExtractor';

export default function IOCPanel({ result }) {
  if (!result || result.total === 0) return null;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
  };

  const handleCopyAll = () => {
    const all = Object.entries(result.categories)
      .map(([type, values]) => `${getTypeLabel(type)}:\n${values.join('\n')}`)
      .join('\n\n');
    navigator.clipboard.writeText(all);
  };

  return (
    <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">🧬</span> Indicators of Compromise</div>
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <span className="badge badge-info">{result.total} IOCs</span>
          <button className="btn btn-secondary btn-sm" onClick={handleCopyAll} style={{ fontSize: '0.75rem' }}>📋 Copy All</button>
        </div>
      </div>

      {Object.entries(result.categories).map(([type, values]) => (
        <div key={type} style={{ marginBottom: '14px' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>{getTypeIcon(type)}</span> {getTypeLabel(type)}
            <span className="badge badge-neutral">{values.length}</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {values.slice(0, 10).map((val, i) => (
              <span key={i}
                onClick={() => handleCopy(val)}
                style={{
                  padding: '4px 10px', background: 'var(--bg-input)', borderRadius: 'var(--radius-sm)',
                  fontFamily: 'var(--font-mono)', fontSize: '0.75rem', cursor: 'pointer',
                  border: '1px solid var(--border-color)', transition: 'all 0.15s ease',
                  wordBreak: 'break-all',
                }}
                title="Click to copy"
              >
                {val}
              </span>
            ))}
            {values.length > 10 && (
              <span style={{ padding: '4px 10px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                +{values.length - 10} more
              </span>
            )}
          </div>
        </div>
      ))}
    </motion.div>
  );
}
