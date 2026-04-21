// Hybrid Analysis-style Sandbox Engine
// Static analysis, YARA rules, behavioral indicators, malware classification

// ========== MAGIC BYTES DATABASE ==========
const MAGIC_BYTES = {
  'MZ': { type: 'PE Executable', risk: 95, family: 'Windows Executable' },
  'PK': { type: 'ZIP Archive', risk: 40, family: 'Archive' },
  '%PDF': { type: 'PDF Document', risk: 25, family: 'Document' },
  'Rar!': { type: 'RAR Archive', risk: 45, family: 'Archive' },
  '7z': { type: '7-Zip Archive', risk: 40, family: 'Archive' },
  '\x7fELF': { type: 'ELF Binary', risk: 90, family: 'Linux Executable' },
  '\xd0\xcf': { type: 'OLE2 Document', risk: 50, family: 'Office Document' },
  'GIF8': { type: 'GIF Image', risk: 5, family: 'Image' },
  '\x89PNG': { type: 'PNG Image', risk: 5, family: 'Image' },
  '\xff\xd8': { type: 'JPEG Image', risk: 5, family: 'Image' },
};

// ========== YARA-LIKE RULES ==========
const YARA_RULES = [
  { id: 'RULE_PE_HEADER', name: 'PE_Executable_Header', desc: 'Windows PE executable signature detected', pattern: /^TVq[A-Za-z0-9+/=]|^MZ/m, severity: 'critical', tags: ['malware', 'executable'] },
  { id: 'RULE_POWERSHELL', name: 'PowerShell_Command', desc: 'PowerShell execution command detected', pattern: /powershell|pwsh|Invoke-(Expression|Command|WebRequest|RestMethod)|IEX\s*\(/i, severity: 'critical', tags: ['execution', 'downloader'] },
  { id: 'RULE_CMD_EXEC', name: 'Command_Execution', desc: 'System command execution pattern', pattern: /cmd\.exe|command\.com|wscript|cscript|mshta|regsvr32/i, severity: 'critical', tags: ['execution'] },
  { id: 'RULE_DOWNLOAD', name: 'Download_Pattern', desc: 'File download functionality detected', pattern: /wget|curl|URLDownloadToFile|WebClient|Net\.WebClient|bitsadmin/i, severity: 'high', tags: ['downloader', 'c2'] },
  { id: 'RULE_REGISTRY', name: 'Registry_Modification', desc: 'Windows registry modification pattern', pattern: /HKLM|HKCU|RegSetValue|reg\s+add|CurrentVersion\\Run/i, severity: 'high', tags: ['persistence'] },
  { id: 'RULE_AUTORUN', name: 'AutoRun_Persistence', desc: 'Auto-start persistence mechanism', pattern: /autorun\.inf|startup|CurrentVersion\\Run|TaskScheduler/i, severity: 'high', tags: ['persistence'] },
  { id: 'RULE_ANTI_DEBUG', name: 'Anti_Debug', desc: 'Anti-debugging technique detected', pattern: /IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformation|OutputDebugString/i, severity: 'medium', tags: ['evasion'] },
  { id: 'RULE_ANTI_VM', name: 'Anti_VM', desc: 'Virtual machine detection pattern', pattern: /VMware|VirtualBox|QEMU|Sandbox|SbieDll|wine_get_unix/i, severity: 'medium', tags: ['evasion'] },
  { id: 'RULE_OBFUSCATION', name: 'String_Obfuscation', desc: 'String obfuscation detected', pattern: /fromCharCode|String\.fromChar|atob\s*\(|eval\s*\(|unescape\s*\(/i, severity: 'high', tags: ['obfuscation'] },
  { id: 'RULE_SHELLCODE', name: 'Shellcode_Pattern', desc: 'Potential shellcode pattern', pattern: /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){8,}|0x[0-9a-f]{2},\s*0x[0-9a-f]{2}/i, severity: 'critical', tags: ['shellcode'] },
  { id: 'RULE_MACRO_AUTO', name: 'Auto_Open_Macro', desc: 'Auto-executing macro pattern', pattern: /Auto_?Open|AutoExec|Document_Open|Workbook_Open|Sub\s+Auto/i, severity: 'high', tags: ['macro', 'execution'] },
  { id: 'RULE_VBA_SHELL', name: 'VBA_Shell_Exec', desc: 'VBA shell execution', pattern: /Shell\s*\(|WScript\.Shell|CreateObject.*Shell|Environ\(/i, severity: 'critical', tags: ['macro', 'execution'] },
  { id: 'RULE_CRYPTO', name: 'Crypto_API', desc: 'Cryptographic API usage', pattern: /CryptEncrypt|CryptDecrypt|AES|RC4|XOR|CryptoStream/i, severity: 'medium', tags: ['crypto'] },
  { id: 'RULE_KEYLOG', name: 'Keylogger_Pattern', desc: 'Keylogger behavior pattern', pattern: /GetAsyncKeyState|SetWindowsHookEx|GetKeyboardState|keylog/i, severity: 'critical', tags: ['spyware', 'keylogger'] },
  { id: 'RULE_SCREEN_CAP', name: 'Screen_Capture', desc: 'Screen capture capability', pattern: /BitBlt|CopyFromScreen|Screenshot|PrintWindow/i, severity: 'high', tags: ['spyware'] },
  { id: 'RULE_CREDENTIAL', name: 'Credential_Access', desc: 'Credential harvesting pattern', pattern: /mimikatz|lsass|SAM|NTDS|credential|hashdump/i, severity: 'critical', tags: ['credential_theft'] },
  { id: 'RULE_C2_BEACON', name: 'C2_Beacon', desc: 'Command & Control beacon pattern', pattern: /beacon|heartbeat|checkin|callback|reverse.*shell/i, severity: 'critical', tags: ['c2'] },
  { id: 'RULE_DATA_EXFIL', name: 'Data_Exfiltration', desc: 'Data exfiltration pattern', pattern: /upload|exfiltrate|smtp.*send|ftp.*put|POST.*data/i, severity: 'high', tags: ['exfiltration'] },
];

// ========== MALWARE FAMILIES ==========
const MALWARE_FAMILIES = [
  { name: 'Emotet', indicators: ['PowerShell', 'obfuscat', 'WScript', 'macro', 'AutoOpen'], category: 'Trojan/Downloader' },
  { name: 'TrickBot', indicators: ['cmd.exe', 'PowerShell', 'registry', 'credential', 'NTDS'], category: 'Banking Trojan' },
  { name: 'AgentTesla', indicators: ['keylog', 'GetAsyncKeyState', 'credential', 'smtp', 'screenshot'], category: 'Keylogger/Stealer' },
  { name: 'Lokibot', indicators: ['credential', 'browser', 'ftp', 'smtp', 'password'], category: 'Info Stealer' },
  { name: 'Remcos', indicators: ['keylog', 'screenshot', 'registry', 'persistence', 'reverse'], category: 'RAT' },
  { name: 'QakBot', indicators: ['PowerShell', 'regsvr32', 'DLL', 'injection', 'C2'], category: 'Banking Trojan' },
];

// ========== MAIN SANDBOX ANALYSIS ==========
export function runSandboxAnalysis(attachments, bodyText, rawEmail) {
  const results = [];

  for (const att of (attachments || [])) {
    results.push(analyzeFile(att, bodyText || '', rawEmail || ''));
  }

  // Also scan body for embedded threats
  const bodyResult = scanBody(bodyText || '', rawEmail || '');

  const maxScore = results.length > 0 ? Math.max(...results.map(r => r.maliciousnessScore)) : 0;
  const overallScore = Math.max(maxScore, bodyResult.score);
  const verdict = overallScore >= 70 ? 'malicious' : overallScore >= 40 ? 'suspicious' : 'clean';

  return {
    files: results,
    bodyAnalysis: bodyResult,
    overallScore,
    verdict,
    totalFiles: results.length,
    maliciousFiles: results.filter(r => r.maliciousnessScore >= 70).length,
  };
}

function analyzeFile(att, bodyText, rawEmail) {
  const filename = att.filename || 'unknown';
  const ext = filename.split('.').pop().toLowerCase();
  const yaraMatches = [];
  const behaviors = [];
  let maliciousnessScore = 0;

  // Static analysis
  const staticResult = {
    filename,
    extension: ext,
    size: att.size || 0,
    contentType: att.contentType || 'unknown',
    entropy: calculateStringEntropy(filename),
    magicType: detectMagicType(filename, att.contentType),
  };

  // YARA scanning against body text (since we don't have actual file bytes)
  const scanText = bodyText + ' ' + rawEmail;
  for (const rule of YARA_RULES) {
    if (rule.pattern.test(scanText)) {
      yaraMatches.push({ id: rule.id, name: rule.name, desc: rule.desc, severity: rule.severity, tags: rule.tags });
      maliciousnessScore += rule.severity === 'critical' ? 20 : rule.severity === 'high' ? 12 : 6;
    }
  }

  // Extension-based risk
  const execExts = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'wsf', 'ps1', 'msi', 'hta'];
  const macroExts = ['docm', 'xlsm', 'pptm', 'dotm'];
  if (execExts.includes(ext)) { maliciousnessScore += 30; behaviors.push({ type: 'execution', severity: 'critical', desc: 'Executable file type can run arbitrary code' }); }
  if (macroExts.includes(ext)) { maliciousnessScore += 20; behaviors.push({ type: 'macro', severity: 'high', desc: 'Macro-enabled document may contain malicious VBA code' }); }

  // Double extension
  const parts = filename.split('.');
  if (parts.length > 2) {
    maliciousnessScore += 25;
    behaviors.push({ type: 'evasion', severity: 'critical', desc: `Double extension trick: appears as .${parts[parts.length - 2]} but is .${ext}` });
  }

  // Behavioral indicators based on YARA tags
  const allTags = yaraMatches.flatMap(m => m.tags);
  if (allTags.includes('persistence')) behaviors.push({ type: 'persistence', severity: 'high', desc: 'Establishes persistence on the system' });
  if (allTags.includes('evasion')) behaviors.push({ type: 'evasion', severity: 'medium', desc: 'Employs anti-analysis/evasion techniques' });
  if (allTags.includes('c2')) behaviors.push({ type: 'c2', severity: 'critical', desc: 'Command & Control communication detected' });
  if (allTags.includes('credential_theft')) behaviors.push({ type: 'credential_theft', severity: 'critical', desc: 'Attempts to harvest credentials' });
  if (allTags.includes('keylogger')) behaviors.push({ type: 'spyware', severity: 'critical', desc: 'Keylogger functionality detected' });
  if (allTags.includes('exfiltration')) behaviors.push({ type: 'exfiltration', severity: 'high', desc: 'Data exfiltration capability' });

  // Malware family classification
  const family = classifyFamily(yaraMatches, behaviors);

  // Process tree (simulated)
  const processTree = buildProcessTree(filename, yaraMatches, behaviors);

  maliciousnessScore = Math.min(maliciousnessScore, 100);
  const verdict = maliciousnessScore >= 70 ? 'malicious' : maliciousnessScore >= 40 ? 'suspicious' : 'clean';

  return {
    staticResult,
    yaraMatches,
    behaviors,
    maliciousnessScore,
    verdict,
    family,
    processTree,
  };
}

function scanBody(bodyText, rawEmail) {
  const matches = [];
  const text = bodyText + ' ' + rawEmail;
  let score = 0;

  for (const rule of YARA_RULES) {
    if (rule.pattern.test(text)) {
      matches.push({ id: rule.id, name: rule.name, desc: rule.desc, severity: rule.severity });
      score += rule.severity === 'critical' ? 8 : rule.severity === 'high' ? 5 : 2;
    }
  }

  return { matches, score: Math.min(score, 100) };
}

function detectMagicType(filename, contentType) {
  const ext = filename.split('.').pop().toLowerCase();
  const extMap = {
    exe: 'PE Executable', dll: 'PE Executable', scr: 'PE Executable',
    pdf: 'PDF Document', doc: 'OLE2 Document', docx: 'Office Open XML',
    xls: 'OLE2 Document', xlsx: 'Office Open XML', zip: 'ZIP Archive',
    rar: 'RAR Archive', '7z': '7-Zip Archive', js: 'JavaScript',
    vbs: 'VBScript', ps1: 'PowerShell Script', bat: 'Batch Script',
    hta: 'HTML Application', iso: 'Disk Image', img: 'Disk Image',
  };
  return extMap[ext] || contentType || 'Unknown';
}

function calculateStringEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

function classifyFamily(yaraMatches, behaviors) {
  const matchedNames = yaraMatches.map(m => m.name.toLowerCase()).join(' ') + ' ' + behaviors.map(b => b.desc.toLowerCase()).join(' ');

  for (const family of MALWARE_FAMILIES) {
    const score = family.indicators.filter(i => matchedNames.includes(i.toLowerCase())).length;
    if (score >= 2) {
      return { name: family.name, category: family.category, confidence: Math.min(score * 25, 95) };
    }
  }
  return null;
}

function buildProcessTree(filename, yaraMatches, behaviors) {
  const tree = [{ pid: 1, name: filename, parent: null, action: 'Initial execution' }];
  let pid = 2;

  if (yaraMatches.some(m => m.tags?.includes('macro'))) {
    tree.push({ pid: pid++, name: 'WINWORD.EXE', parent: 1, action: 'Opens document' });
    tree.push({ pid: pid++, name: 'cmd.exe', parent: pid - 1, action: 'Macro spawns command shell' });
  }
  if (yaraMatches.some(m => m.tags?.includes('execution'))) {
    tree.push({ pid: pid++, name: 'powershell.exe', parent: tree.length > 1 ? pid - 1 : 1, action: 'PowerShell execution' });
  }
  if (yaraMatches.some(m => m.tags?.includes('downloader'))) {
    tree.push({ pid: pid++, name: 'svchost.exe', parent: pid - 1, action: 'Downloads payload' });
  }
  if (behaviors.some(b => b.type === 'persistence')) {
    tree.push({ pid: pid++, name: 'reg.exe', parent: pid - 1, action: 'Modifies registry for persistence' });
  }
  if (behaviors.some(b => b.type === 'c2')) {
    tree.push({ pid: pid++, name: 'rundll32.exe', parent: pid - 1, action: 'C2 beacon callback' });
  }

  return tree;
}
