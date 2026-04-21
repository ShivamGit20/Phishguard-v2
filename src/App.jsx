import React, { useState, useEffect, useCallback } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import Sidebar from './components/Sidebar';
import ThemeToggle from './components/ThemeToggle';
import EmailInput from './components/EmailInput';
import ThreatGauge from './components/ThreatGauge';
import HeaderAnalysis from './components/HeaderAnalysis';
import URLAnalysis from './components/URLAnalysis';
import ContentAnalysis from './components/ContentAnalysis';
import AttachmentAnalysis from './components/AttachmentAnalysis';
import ThreatTimeline from './components/ThreatTimeline';
import ReportExport from './components/ReportExport';
import AnalysisHistory from './components/AnalysisHistory';
import Dashboard from './components/Dashboard';
import SecurityToolkit from './components/SecurityToolkit';
import IOCPanel from './components/IOCPanel';
import SEGPanel from './components/SEGPanel';
import SandboxPanel from './components/SandboxPanel';
import MITREPanel from './components/MITREPanel';
import ExecutiveSummary from './components/ExecutiveSummary';
import { parseEml } from './utils/emlParser';
import { analyzeHeaders } from './utils/headerParser';
import { analyzeURLs } from './utils/urlAnalyzer';
import { analyzeContent } from './utils/contentAnalyzer';
import { analyzeAttachments } from './utils/attachmentAnalyzer';
import { calculateThreatScore } from './utils/threatScorer';
import { generateReport } from './utils/pdfReport';
import { extractIOCs } from './utils/iocExtractor';
import { runSEGAnalysis } from './utils/segEngine';
import { runSandboxAnalysis } from './utils/sandboxEngine';
import { mapToMITRE } from './utils/mitreMapper';

const STORAGE_KEY = 'phishguard_history';

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch { return []; }
}

function saveHistory(history) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, 50)));
}

export default function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('phishguard_theme') || 'dark');
  const [view, setView] = useState('analyzer');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState(null);
  const [history, setHistory] = useState(loadHistory);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('phishguard_theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark');

  const handleAnalyze = useCallback((rawEmail) => {
    setIsAnalyzing(true);
    // Simulate async to show loading state
    setTimeout(() => {
      try {
        const parsed = parseEml(rawEmail);
        const headerResult = analyzeHeaders(parsed.headers);
        const bodyText = parsed.bodyHtml || parsed.bodyPlain || rawEmail;
        const urlResult = analyzeURLs(bodyText);
        const contentResult = analyzeContent(bodyText);
        const attachmentResult = analyzeAttachments(parsed.attachments);
        const iocResult = extractIOCs(rawEmail);
        const segResult = runSEGAnalysis(headerResult, urlResult, contentResult, attachmentResult, parsed);
        const sandboxResult = runSandboxAnalysis(parsed.attachments, bodyText, rawEmail);
        const threatResult = calculateThreatScore(headerResult, urlResult, contentResult, attachmentResult);
        const mitreResult = mapToMITRE(headerResult, urlResult, contentResult, attachmentResult, sandboxResult);

        const analysisResult = { headerResult, urlResult, contentResult, attachmentResult, threatResult, iocResult, segResult, sandboxResult, mitreResult };
        setResults(analysisResult);

        // Save to history
        const historyEntry = {
          timestamp: Date.now(),
          subject: headerResult.subject,
          from: headerResult.from,
          score: threatResult.score,
          level: threatResult.level,
          label: threatResult.label,
          totalFindings: threatResult.totalFindings,
          findingTypes: threatResult.allFindings.map(f => f.type),
          results: analysisResult,
        };
        const newHistory = [historyEntry, ...history].slice(0, 50);
        setHistory(newHistory);
        saveHistory(newHistory);
      } catch (err) {
        console.error('Analysis error:', err);
      }
      setIsAnalyzing(false);
    }, 800);
  }, [history]);

  const handleExportPDF = () => {
    if (results) {
      generateReport(results.threatResult, results.headerResult, results.urlResult, results.contentResult, results.attachmentResult);
    }
  };

  const handleHistorySelect = (item) => {
    setResults(item.results);
    setView('analyzer');
  };

  const handleClearHistory = () => {
    setHistory([]);
    saveHistory([]);
  };

  return (
    <div className="app-layout">
      <Sidebar currentView={view} onNavigate={setView} />
      <main className="main-content">
        {/* Top bar */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', marginBottom: '24px', gap: '12px' }}>
          <ReportExport onExport={handleExportPDF} hasResults={!!results} />
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
        </div>

        <AnimatePresence mode="wait">
          {view === 'analyzer' && (
            <motion.div key="analyzer" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="page-header">
                <h1>🔍 Email Analyzer</h1>
                <p>Paste raw email content or import an .eml file to analyze for phishing threats</p>
              </div>

              <EmailInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />

              {isAnalyzing && (
                <div className="analyzing-overlay">
                  <div className="analyzing-card">
                    <div className="loading-spinner" />
                    <p>Analyzing Email...</p>
                    <div className="sub">Scanning headers, URLs, content, and attachments</div>
                  </div>
                </div>
              )}

              {results && !isAnalyzing && (
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ marginTop: '24px' }}>
                  {/* Threat Score */}
                  <div className="card" style={{ marginBottom: '20px' }}>
                    <div className="card-header">
                      <div className="card-title"><span className="card-icon">🎯</span> Threat Assessment</div>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <span className="badge badge-fail">🔴 {results.threatResult.criticalCount}</span>
                        <span className="badge badge-warn">🟠 {results.threatResult.highCount}</span>
                        <span className="badge badge-info">🟡 {results.threatResult.mediumCount}</span>
                        <span className="badge badge-pass">🟢 {results.threatResult.lowCount}</span>
                      </div>
                    </div>
                    <ThreatGauge score={results.threatResult.score} level={results.threatResult.level} label={results.threatResult.label} />
                  </div>

                  {/* Executive Summary */}
                  <ExecutiveSummary threatResult={results.threatResult} segResult={results.segResult} sandboxResult={results.sandboxResult} mitreResult={results.mitreResult} headerResult={results.headerResult} />

                  {/* Analysis panels */}
                  <div className="analysis-grid" style={{ marginTop: '20px' }}>
                    <SEGPanel result={results.segResult} />
                    <SandboxPanel result={results.sandboxResult} />
                    <MITREPanel result={results.mitreResult} />
                    <HeaderAnalysis result={results.headerResult} />
                    <URLAnalysis result={results.urlResult} />
                    <ContentAnalysis result={results.contentResult} />
                    <AttachmentAnalysis result={results.attachmentResult} />
                    <ThreatTimeline findings={results.threatResult.allFindings} />
                    <IOCPanel result={results.iocResult} />
                  </div>
                </motion.div>
              )}
            </motion.div>
          )}

          {view === 'toolkit' && (
            <motion.div key="toolkit" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <SecurityToolkit />
            </motion.div>
          )}

          {view === 'dashboard' && (
            <motion.div key="dashboard" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Dashboard history={history} />
            </motion.div>
          )}

          {view === 'history' && (
            <motion.div key="history" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <AnalysisHistory history={history} onSelect={handleHistorySelect} onClear={handleClearHistory} />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
