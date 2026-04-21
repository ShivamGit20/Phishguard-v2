// MITRE ATT&CK Technique Mapper

const TECHNIQUE_DB = {
  'T1566': { tactic: 'Initial Access', name: 'Phishing', desc: 'Adversaries send phishing messages to gain access to victim systems.' },
  'T1566.001': { tactic: 'Initial Access', name: 'Spearphishing Attachment', desc: 'Adversaries send spearphishing emails with a malicious attachment.' },
  'T1566.002': { tactic: 'Initial Access', name: 'Spearphishing Link', desc: 'Adversaries send spearphishing emails with a malicious link.' },
  'T1204': { tactic: 'Execution', name: 'User Execution', desc: 'Adversary relies upon user interaction to execute malicious content.' },
  'T1204.001': { tactic: 'Execution', name: 'Malicious Link', desc: 'User clicks a malicious link to execute code.' },
  'T1204.002': { tactic: 'Execution', name: 'Malicious File', desc: 'User opens a malicious file to execute code.' },
  'T1059': { tactic: 'Execution', name: 'Command & Scripting Interpreter', desc: 'Adversaries use command-line interfaces or scripts.' },
  'T1059.001': { tactic: 'Execution', name: 'PowerShell', desc: 'Adversaries use PowerShell commands and scripts.' },
  'T1059.003': { tactic: 'Execution', name: 'Windows Command Shell', desc: 'Adversaries use cmd.exe to execute commands.' },
  'T1059.005': { tactic: 'Execution', name: 'Visual Basic', desc: 'Adversaries use VBS/VBA scripts for execution.' },
  'T1547': { tactic: 'Persistence', name: 'Boot/Logon Autostart', desc: 'Adversaries configure system to execute malware at startup.' },
  'T1547.001': { tactic: 'Persistence', name: 'Registry Run Keys', desc: 'Adversaries add programs to Run registry keys for persistence.' },
  'T1027': { tactic: 'Defense Evasion', name: 'Obfuscated Files', desc: 'Adversaries obfuscate payloads to hinder detection.' },
  'T1027.002': { tactic: 'Defense Evasion', name: 'Software Packing', desc: 'Adversaries use software packing to conceal code.' },
  'T1036': { tactic: 'Defense Evasion', name: 'Masquerading', desc: 'Adversaries manipulate features to appear legitimate.' },
  'T1036.007': { tactic: 'Defense Evasion', name: 'Double File Extension', desc: 'Adversaries use double file extensions to disguise files.' },
  'T1056': { tactic: 'Credential Access', name: 'Input Capture', desc: 'Adversaries capture user input to obtain credentials.' },
  'T1056.001': { tactic: 'Credential Access', name: 'Keylogging', desc: 'Adversaries capture keystrokes to harvest credentials.' },
  'T1555': { tactic: 'Credential Access', name: 'Credentials from Password Stores', desc: 'Adversaries search for stored credentials.' },
  'T1071': { tactic: 'Command and Control', name: 'Application Layer Protocol', desc: 'Adversaries use application layer protocols for C2.' },
  'T1041': { tactic: 'Exfiltration', name: 'Exfiltration Over C2 Channel', desc: 'Adversaries exfiltrate data over C2 channel.' },
  'T1534': { tactic: 'Lateral Movement', name: 'Internal Spearphishing', desc: 'Adversaries use internal spearphishing to move laterally.' },
  'T1078': { tactic: 'Privilege Escalation', name: 'Valid Accounts', desc: 'Adversaries obtain and use legitimate credentials.' },
};

const MAPPING_RULES = [
  // Initial Access
  { condition: (ctx) => ctx.hasPhishingURLs || ctx.isPhishing, techniques: ['T1566', 'T1566.002'] },
  { condition: (ctx) => ctx.hasMaliciousAttachment, techniques: ['T1566', 'T1566.001'] },
  // Execution
  { condition: (ctx) => ctx.hasLinks, techniques: ['T1204', 'T1204.001'] },
  { condition: (ctx) => ctx.hasMaliciousAttachment, techniques: ['T1204', 'T1204.002'] },
  { condition: (ctx) => ctx.yaraTagsInclude('execution') && ctx.bodyContains('powershell'), techniques: ['T1059', 'T1059.001'] },
  { condition: (ctx) => ctx.yaraTagsInclude('execution') && ctx.bodyContains('cmd'), techniques: ['T1059', 'T1059.003'] },
  { condition: (ctx) => ctx.yaraTagsInclude('macro'), techniques: ['T1059', 'T1059.005'] },
  // Persistence
  { condition: (ctx) => ctx.yaraTagsInclude('persistence'), techniques: ['T1547', 'T1547.001'] },
  // Defense Evasion
  { condition: (ctx) => ctx.yaraTagsInclude('obfuscation'), techniques: ['T1027'] },
  { condition: (ctx) => ctx.hasDoubleExtension, techniques: ['T1036', 'T1036.007'] },
  // Credential Access
  { condition: (ctx) => ctx.yaraTagsInclude('keylogger'), techniques: ['T1056', 'T1056.001'] },
  { condition: (ctx) => ctx.yaraTagsInclude('credential_theft'), techniques: ['T1555'] },
  { condition: (ctx) => ctx.isCredentialPhishing, techniques: ['T1078'] },
  // C2
  { condition: (ctx) => ctx.yaraTagsInclude('c2'), techniques: ['T1071'] },
  // Exfiltration
  { condition: (ctx) => ctx.yaraTagsInclude('exfiltration'), techniques: ['T1041'] },
];

export function mapToMITRE(headerResult, urlResult, contentResult, attachmentResult, sandboxResult) {
  const ctx = buildMappingContext(headerResult, urlResult, contentResult, attachmentResult, sandboxResult);
  const matched = new Set();

  for (const rule of MAPPING_RULES) {
    try {
      if (rule.condition(ctx)) {
        rule.techniques.forEach(t => matched.add(t));
      }
    } catch { /* skip */ }
  }

  const techniques = [...matched].map(id => ({
    id,
    ...TECHNIQUE_DB[id],
  })).filter(t => t.name);

  // Group by tactic
  const byTactic = {};
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  }

  // Tactic ordering
  const tacticOrder = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Command and Control', 'Exfiltration'];
  const ordered = tacticOrder.filter(t => byTactic[t]).map(tactic => ({ tactic, techniques: byTactic[tactic] }));

  return { techniques, byTactic: ordered, totalTechniques: techniques.length, totalTactics: ordered.length };
}

function buildMappingContext(headerResult, urlResult, contentResult, attachmentResult, sandboxResult) {
  const allYaraTags = new Set();
  if (sandboxResult) {
    for (const file of (sandboxResult.files || [])) {
      for (const match of (file.yaraMatches || [])) {
        (match.tags || []).forEach(t => allYaraTags.add(t));
      }
    }
    for (const match of (sandboxResult.bodyAnalysis?.matches || [])) {
      // bodyAnalysis matches don't have tags in current implementation
    }
  }

  const bodyText = (contentResult?.highlights?.map(h => h.text).join(' ') || '').toLowerCase();
  const hasDoubleExt = (attachmentResult?.findings || []).some(f => f.title?.includes('Double Extension'));
  const hasExec = (attachmentResult?.totalRisk || 0) >= 80;

  return {
    isPhishing: (headerResult?.dmarc?.result === 'fail') || (contentResult?.socialScore >= 5),
    hasPhishingURLs: (urlResult?.findings || []).some(f => f.severity === 'critical' || f.severity === 'high'),
    hasMaliciousAttachment: hasExec || hasDoubleExt,
    hasLinks: (urlResult?.urls || []).length > 0,
    hasDoubleExtension: hasDoubleExt,
    isCredentialPhishing: /verify.*account|confirm.*password|update.*payment/i.test(bodyText),
    yaraTagsInclude: (tag) => allYaraTags.has(tag),
    bodyContains: (term) => bodyText.includes(term.toLowerCase()),
  };
}

export function getTechniqueURL(id) {
  const base = id.includes('.') ? id.split('.')[0] : id;
  const sub = id.includes('.') ? id.split('.')[1] : '';
  return `https://attack.mitre.org/techniques/${base}/${sub ? sub + '/' : ''}`;
}
