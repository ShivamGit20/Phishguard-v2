// Attachment analyzer — risk scoring for email attachments

const EXTENSION_RISK = {
  critical: { extensions: ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta', '.cpl'], score: 95 },
  high: { extensions: ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.sldm', '.jar', '.iso', '.img', '.vhd'], score: 75 },
  medium: { extensions: ['.doc', '.xls', '.ppt', '.rtf', '.zip', '.rar', '.7z', '.tar', '.gz', '.cab', '.lnk', '.url'], score: 45 },
  low: { extensions: ['.pdf', '.docx', '.xlsx', '.pptx', '.csv', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4'], score: 10 },
};

export function analyzeAttachments(attachments) {
  const findings = [];
  const analyzed = [];

  if (!attachments || attachments.length === 0) {
    return { findings, analyzed, totalRisk: 0 };
  }

  let maxRisk = 0;

  for (const att of attachments) {
    const result = analyzeAttachment(att);
    analyzed.push(result);
    findings.push(...result.findings);
    if (result.riskScore > maxRisk) maxRisk = result.riskScore;
  }

  return { findings, analyzed, totalRisk: maxRisk };
}

function analyzeAttachment(att) {
  const findings = [];
  const filename = att.filename || 'unknown';
  const ext = getExtension(filename).toLowerCase();
  let riskScore = 0;
  let riskLevel = 'none';

  // Extension risk
  for (const [level, data] of Object.entries(EXTENSION_RISK)) {
    if (data.extensions.includes(ext)) {
      riskScore = data.score;
      riskLevel = level;
      if (level === 'critical') {
        findings.push({ severity: 'critical', type: 'attachment', title: `Dangerous File Type: ${ext}`, description: `"${filename}" is an executable file type that can run code on your system.`, detail: `Extension: ${ext}` });
      } else if (level === 'high') {
        findings.push({ severity: 'high', type: 'attachment', title: `High-Risk File Type: ${ext}`, description: `"${filename}" is a macro-enabled or executable format that may contain malicious code.`, detail: `Extension: ${ext}` });
      }
      break;
    }
  }

  // Double extension detection
  const parts = filename.split('.');
  if (parts.length > 2) {
    const secondToLast = '.' + parts[parts.length - 2].toLowerCase();
    if (EXTENSION_RISK.low.extensions.includes(secondToLast) || secondToLast === '.pdf' || secondToLast === '.doc') {
      findings.push({ severity: 'critical', type: 'attachment', title: 'Double Extension Detected', description: `"${filename}" uses a double extension trick to disguise a dangerous file as a safe one.`, detail: `Appears as: ${secondToLast} | Actually: ${ext}` });
      riskScore = Math.max(riskScore, 90);
      riskLevel = 'critical';
    }
  }

  // Very long filename (obfuscation)
  if (filename.length > 80) {
    findings.push({ severity: 'medium', type: 'attachment', title: 'Unusually Long Filename', description: `Filename is ${filename.length} characters long. This may be used to hide the real extension.`, detail: filename.substring(0, 50) + '...' });
    riskScore = Math.max(riskScore, 40);
  }

  // Unicode in filename
  if (/[^\x00-\x7F]/.test(filename)) {
    findings.push({ severity: 'medium', type: 'attachment', title: 'Unicode Characters in Filename', description: 'Filename contains non-ASCII characters that may be used for obfuscation.', detail: filename });
    riskScore = Math.max(riskScore, 35);
  }

  if (riskScore === 0) { riskScore = 5; riskLevel = 'none'; }

  return { filename, extension: ext, riskScore, riskLevel, findings, contentType: att.contentType, size: att.size };
}

function getExtension(filename) {
  const idx = filename.lastIndexOf('.');
  return idx !== -1 ? filename.substring(idx) : '';
}
