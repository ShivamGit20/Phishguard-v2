import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import IOCExtractorTool from './tools/IOCExtractor';
import URLDefanger from './tools/URLDefanger';
import Base64Tool from './tools/Base64Tool';
import HashGenerator from './tools/HashGenerator';
import HomographDetector from './tools/HomographDetector';
import WhoisTool from './tools/WhoisTool';

const TOOLS = [
  { id: 'ioc', icon: '🧬', label: 'IOC Extractor', desc: 'Extract indicators of compromise', component: IOCExtractorTool },
  { id: 'defang', icon: '🔓', label: 'URL Defanger', desc: 'Safely share malicious URLs', component: URLDefanger },
  { id: 'base64', icon: '🔤', label: 'Base64 Tool', desc: 'Decode & detect hidden payloads', component: Base64Tool },
  { id: 'hash', icon: '#️⃣', label: 'Hash Generator', desc: 'MD5, SHA-1, SHA-256 + VirusTotal', component: HashGenerator },
  { id: 'homograph', icon: '🎭', label: 'Homograph Detector', desc: 'Find unicode lookalike chars', component: HomographDetector },
  { id: 'whois', icon: '📋', label: 'Domain Analyzer', desc: 'Domain risk heuristics', component: WhoisTool },
];

export default function SecurityToolkit() {
  const [activeTool, setActiveTool] = useState('ioc');
  const ActiveComponent = TOOLS.find(t => t.id === activeTool)?.component;

  return (
    <div>
      <div className="page-header">
        <h1>🛠️ Security Toolkit</h1>
        <p>Standalone security tools for threat analysis and incident response</p>
      </div>

      {/* Tool selector grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '10px', marginBottom: '24px' }}>
        {TOOLS.map(tool => (
          <button
            key={tool.id}
            onClick={() => setActiveTool(tool.id)}
            style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px',
              padding: '16px 12px', borderRadius: 'var(--radius-md)',
              background: activeTool === tool.id ? 'var(--accent-cyan-dim)' : 'var(--bg-card)',
              border: `1px solid ${activeTool === tool.id ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
              cursor: 'pointer', transition: 'all 0.15s ease',
              fontFamily: 'var(--font-sans)',
            }}
          >
            <span style={{ fontSize: '1.5rem' }}>{tool.icon}</span>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: activeTool === tool.id ? 'var(--accent-cyan)' : 'var(--text-primary)' }}>{tool.label}</span>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textAlign: 'center' }}>{tool.desc}</span>
          </button>
        ))}
      </div>

      {/* Active tool */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">
            <span className="card-icon">{TOOLS.find(t => t.id === activeTool)?.icon}</span>
            {TOOLS.find(t => t.id === activeTool)?.label}
          </div>
        </div>
        <AnimatePresence mode="wait">
          <motion.div key={activeTool} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>
            {ActiveComponent && <ActiveComponent />}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}
