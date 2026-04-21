import React from 'react';
import { motion } from 'framer-motion';

export default function AnalysisHistory({ history, onSelect, onClear }) {
  const getScoreColor = (score) => {
    if (score >= 75) return 'var(--danger)';
    if (score >= 50) return '#ff6b6b';
    if (score >= 25) return 'var(--warning)';
    return 'var(--success)';
  };

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>📋 Analysis History</h1>
          <p>{history.length} past analyses stored locally</p>
        </div>
        {history.length > 0 && (
          <button className="btn btn-danger btn-sm" onClick={onClear}>🗑️ Clear All</button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">📭</div>
            <div className="empty-title">No analysis history yet</div>
            <div className="empty-desc">Your past analyses will appear here</div>
          </div>
        </div>
      ) : (
        history.map((item, i) => (
          <motion.div
            key={i}
            className="history-item"
            onClick={() => onSelect(item)}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.03 * i }}
          >
            <div className="history-meta">
              <div className="history-subject">{item.subject || 'No Subject'}</div>
              <div className="history-date">{item.from || 'Unknown sender'} • {new Date(item.timestamp).toLocaleString()}</div>
            </div>
            <div className="history-score" style={{ color: getScoreColor(item.score) }}>
              {item.score}/100
            </div>
          </motion.div>
        ))
      )}
    </div>
  );
}
