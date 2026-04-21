import React from 'react';
import { motion } from 'framer-motion';

export default function Dashboard({ history }) {
  const totalAnalyses = history.length;
  const avgScore = totalAnalyses > 0 ? Math.round(history.reduce((s, h) => s + h.score, 0) / totalAnalyses) : 0;
  const criticalCount = history.filter(h => h.score >= 75).length;
  const cleanCount = history.filter(h => h.score < 10).length;

  // Threat type breakdown
  const typeCounts = { header: 0, url: 0, content: 0, attachment: 0 };
  for (const h of history) {
    if (h.findingTypes) {
      for (const t of h.findingTypes) {
        if (typeCounts[t] !== undefined) typeCounts[t]++;
      }
    }
  }
  const topType = Object.entries(typeCounts).sort((a, b) => b[1] - a[1])[0];

  const getScoreColor = (score) => {
    if (score >= 75) return 'var(--danger)';
    if (score >= 50) return '#ff6b6b';
    if (score >= 25) return 'var(--warning)';
    return 'var(--success)';
  };

  return (
    <div>
      <div className="page-header">
        <h1>📊 Dashboard</h1>
        <p>Overview of your email analysis activity</p>
      </div>

      <div className="stats-grid" style={{ marginBottom: '24px' }}>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0 }}>
          <div className="stat-label">Total Analyses</div>
          <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{totalAnalyses}</div>
        </motion.div>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <div className="stat-label">Average Threat Score</div>
          <div className="stat-value" style={{ color: getScoreColor(avgScore) }}>{avgScore}</div>
          <div className="stat-sub">out of 100</div>
        </motion.div>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <div className="stat-label">Critical Threats</div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}>{criticalCount}</div>
        </motion.div>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <div className="stat-label">Clean Emails</div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{cleanCount}</div>
        </motion.div>
      </div>

      <div className="analysis-grid">
        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <div className="card-header">
            <div className="card-title"><span className="card-icon">🎯</span> Threat Distribution</div>
          </div>
          {totalAnalyses === 0 ? (
            <div className="empty-state" style={{ padding: '20px' }}>
              <div className="empty-title">No data yet</div>
              <div className="empty-desc">Analyze emails to see distribution</div>
            </div>
          ) : (
            <div>
              {[{ label: 'Header Issues', count: typeCounts.header, icon: '📨' },
                { label: 'URL Issues', count: typeCounts.url, icon: '🔗' },
                { label: 'Content Issues', count: typeCounts.content, icon: '📝' },
                { label: 'Attachment Issues', count: typeCounts.attachment, icon: '📎' }
              ].map((item, i) => {
                const maxCount = Math.max(...Object.values(typeCounts), 1);
                const pct = (item.count / maxCount) * 100;
                return (
                  <div key={i} style={{ marginBottom: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
                      <span>{item.icon} {item.label}</span>
                      <span style={{ fontWeight: 700 }}>{item.count}</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden' }}>
                      <motion.div
                        style={{ height: '100%', background: 'var(--gradient-primary)', borderRadius: '3px' }}
                        initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, delay: 0.1 * i }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>

        <motion.div className="card" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <div className="card-header">
            <div className="card-title"><span className="card-icon">📜</span> Recent Analyses</div>
          </div>
          {totalAnalyses === 0 ? (
            <div className="empty-state" style={{ padding: '20px' }}>
              <div className="empty-title">No analyses yet</div>
            </div>
          ) : (
            history.slice(0, 5).map((h, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{h.subject?.substring(0, 35) || 'No Subject'}</span>
                <span style={{ fontWeight: 700, color: getScoreColor(h.score) }}>{h.score}</span>
              </div>
            ))
          )}
        </motion.div>
      </div>
    </div>
  );
}
