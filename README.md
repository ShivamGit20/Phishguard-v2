# 🛡️ PhishGuard v2 — Enterprise Phishing Email Analyzer

> Industry-grade client-side phishing email analysis platform with Proofpoint-style SEG, Hybrid Analysis sandbox, MITRE ATT&CK mapping, and executive reporting.

![PhishGuard v2](https://img.shields.io/badge/version-2.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![React](https://img.shields.io/badge/React-19-61DAFB) ![Vite](https://img.shields.io/badge/Vite-8-646CFF)

## ✨ Features

### 🔍 Core Analysis (10 Engines)
- **EML Parser** — Full MIME parsing, header extraction, attachment detection
- **Header Analysis** — SPF/DKIM/DMARC validation, routing chain analysis
- **URL Analysis** — IP-based URLs, shorteners, typosquatting, punycode detection
- **Content Analysis** — Social engineering patterns, urgency language detection
- **Attachment Analysis** — Extension risk scoring, double extension tricks
- **IOC Extraction** — IPv4/IPv6, domains, URLs, emails, hashes, CVEs, BTC addresses
- **Threat Scoring** — Weighted 0-100 scoring across all categories

### 🏢 Enterprise Security (NEW)
- **Proofpoint-Style SEG** — 30+ spam rules, threat classification (phishing/malware/BEC/spam), URL Defense, policy engine, quarantine decisions
- **Hybrid Analysis Sandbox** — 18 YARA rules, behavioral indicators, malware family classification, process tree visualization, 0-100 maliciousness score
- **MITRE ATT&CK Mapping** — 22 techniques across 9 tactics, clickable ATT&CK links
- **Executive Summary** — One-glance verdict, key indicators grid, incident response recommendations

### 🛠️ Security Toolkit (6 Standalone Tools)
- **IOC Extractor** — Multi-indicator extraction with JSON/CSV export
- **URL Defanger** — Safe URL/IP/email obfuscation
- **Base64 Tool** — Decode, encode, and auto-detect hidden payloads
- **Hash Generator** — MD5/SHA-1/SHA-256 with VirusTotal lookup
- **Homograph Detector** — Unicode lookalike identification + brand impersonation
- **Domain Analyzer** — TLD risk, entropy, keyword, depth heuristics

### 🎨 UI/UX
- Premium dark/light theme with glassmorphism
- Animated threat gauge with real-time scoring
- Responsive layout with sidebar navigation
- PDF report export
- Analysis history with localStorage persistence

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

Open `http://localhost:5173` and click **Load Sample** to test with a pre-built phishing email.

## 🏗️ Architecture

```
src/
├── App.jsx                    # Main orchestrator
├── index.css                  # Design system (428 lines)
├── components/                # 22 React components
│   ├── ExecutiveSummary.jsx   # ★ Enterprise verdict
│   ├── SEGPanel.jsx           # ★ Proofpoint SEG
│   ├── SandboxPanel.jsx       # ★ Hybrid Analysis
│   ├── MITREPanel.jsx         # ★ ATT&CK mapping
│   └── tools/                 # 6 standalone tools
└── utils/                     # 16 analysis engines
    ├── segEngine.js           # ★ SEG (316 lines)
    ├── sandboxEngine.js       # ★ Sandbox (217 lines)
    └── mitreMapper.js         # ★ MITRE (119 lines)
```

### Analysis Pipeline

```
Email → EML Parse → Header Analysis → URL Analysis → Content Analysis
→ Attachment Analysis → IOC Extraction → SEG Engine → Sandbox Engine
→ Threat Scoring → MITRE Mapping → Results Display
```

## 🔒 Privacy

**100% client-side.** No data ever leaves your browser. All analysis runs locally using JavaScript — no API calls, no servers, no telemetry.

## 📦 Tech Stack

| Technology | Purpose |
|---|---|
| React 19 | UI framework |
| Vite 8 | Build tool |
| Framer Motion | Animations |
| jsPDF | PDF report generation |
| Web Crypto API | SHA-1/SHA-256 hashing |
| Vanilla CSS | Custom design system |

## 📄 License

MIT License — free for personal and commercial use.

---

Built with ❤️ for the cybersecurity community.
