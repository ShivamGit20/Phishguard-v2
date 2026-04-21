import React from 'react';

export default function Sidebar({ currentView, onNavigate }) {
  const items = [
    { id: 'analyzer', icon: '🔍', label: 'Analyzer' },
    { id: 'toolkit', icon: '🛠️', label: 'Toolkit' },
    { id: 'dashboard', icon: '📊', label: 'Dashboard' },
    { id: 'history', icon: '📋', label: 'History' },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <div>
          <div className="logo-text">PhishGuard</div>
          <span className="logo-version">v2.0</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {items.map(item => (
          <button
            key={item.id}
            className={`nav-item ${currentView === item.id ? 'active' : ''}`}
            onClick={() => onNavigate(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', padding: '8px 16px' }}>
          Client-side analysis only.
          <br />No data leaves your browser.
        </div>
      </div>
    </aside>
  );
}
