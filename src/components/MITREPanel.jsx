import React from 'react';
import { motion } from 'framer-motion';
import { getTechniqueURL } from '../utils/mitreMapper';

export default function MITREPanel({ result }) {
  if (!result || result.totalTechniques === 0) return null;

  const tacticColors = {
    'Initial Access': '#ff3b5c', 'Execution': '#ff6b6b', 'Persistence': '#ffab00',
    'Privilege Escalation': '#ff8f00', 'Defense Evasion': '#7c6aff', 'Credential Access': '#e040fb',
    'Lateral Movement': '#00bcd4', 'Command and Control': '#ff5722', 'Exfiltration': '#f44336',
  };

  return (
    <motion.div className="card analysis-full" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
      <div className="card-header">
        <div className="card-title"><span className="card-icon">🗺️</span> MITRE ATT&CK Mapping</div>
        <span className="badge badge-info">{result.totalTechniques} techniques • {result.totalTactics} tactics</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
        {result.byTactic.map((group, gi) => (
          <motion.div key={gi} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 * gi }}
            style={{ padding: '14px', background: 'var(--bg-input)', borderRadius: 'var(--radius-md)', borderTop: `3px solid ${tacticColors[group.tactic] || 'var(--accent-cyan)'}` }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: tacticColors[group.tactic] || 'var(--accent-cyan)', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              {group.tactic}
            </div>
            {group.techniques.map((t, ti) => (
              <a key={ti} href={getTechniqueURL(t.id)} target="_blank" rel="noopener noreferrer"
                style={{ display: 'block', padding: '8px 10px', background: 'var(--bg-primary)', borderRadius: 'var(--radius-sm)', marginBottom: '4px', textDecoration: 'none', transition: 'all 0.15s ease', border: '1px solid transparent' }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--border-hover)'}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'transparent'}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: tacticColors[group.tactic] || 'var(--accent-cyan)', fontWeight: 700, minWidth: '72px' }}>{t.id}</span>
                  <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>{t.name}</span>
                </div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px', paddingLeft: '78px' }}>{t.desc}</div>
              </a>
            ))}
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
