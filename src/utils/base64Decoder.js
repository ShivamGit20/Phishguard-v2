// Base64 decoder — detect and decode base64 content

const BASE64_REGEX = /(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

export function detectBase64Strings(text) {
  if (!text) return [];
  const matches = text.match(BASE64_REGEX) || [];
  return matches
    .filter(m => m.length >= 16) // minimum meaningful length
    .filter(m => {
      try {
        atob(m);
        return true;
      } catch { return false; }
    })
    .map(m => ({
      encoded: m,
      decoded: safeDecodeBase64(m),
      length: m.length,
    }));
}

export function encodeBase64(text) {
  try {
    return btoa(unescape(encodeURIComponent(text)));
  } catch {
    return 'Error: Unable to encode';
  }
}

export function decodeBase64(encoded) {
  return safeDecodeBase64(encoded);
}

function safeDecodeBase64(str) {
  try {
    const decoded = atob(str);
    // Try to decode as UTF-8
    try {
      return decodeURIComponent(escape(decoded));
    } catch {
      return decoded;
    }
  } catch {
    return 'Error: Invalid Base64 string';
  }
}

export function analyzeDecodedContent(decoded) {
  const threats = [];

  // Check for URLs in decoded content
  const urls = decoded.match(/https?:\/\/[^\s]+/gi);
  if (urls) {
    threats.push({ type: 'url', severity: 'high', description: `Found ${urls.length} hidden URL(s) in decoded content`, detail: urls.join(', ') });
  }

  // Check for script/command patterns
  const scriptPatterns = [
    { pattern: /powershell|cmd\.exe|bash|sh\s+-c/i, label: 'Shell command' },
    { pattern: /<script|javascript:/i, label: 'Script injection' },
    { pattern: /eval\(|exec\(|system\(/i, label: 'Code execution' },
    { pattern: /wget|curl|Invoke-WebRequest/i, label: 'Download command' },
  ];

  for (const { pattern, label } of scriptPatterns) {
    if (pattern.test(decoded)) {
      threats.push({ type: 'script', severity: 'critical', description: `${label} detected in decoded content`, detail: decoded.substring(0, 100) });
    }
  }

  // Check for embedded executable signatures
  if (decoded.startsWith('MZ') || decoded.startsWith('PK')) {
    threats.push({ type: 'binary', severity: 'critical', description: 'Binary executable content detected in Base64 data', detail: 'PE or ZIP header signature found' });
  }

  return threats;
}
