// WHOIS heuristics — client-side domain risk analysis

const RISKY_TLDS = {
  critical: ['.tk', '.ml', '.ga', '.cf', '.gq'],
  high: ['.xyz', '.top', '.club', '.online', '.site', '.icu', '.buzz', '.pw', '.cc', '.ws', '.work', '.click', '.link', '.bid', '.stream', '.download', '.racing'],
  medium: ['.info', '.biz', '.pro', '.name', '.mobi', '.space', '.website', '.tech', '.store', '.life'],
};

const TRUSTED_TLDS = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.int'];

const REGISTRAR_PATTERNS = {
  freeRegistrar: ['freenom', 'dot.tk', 'point.ml'],
};

export function analyzeWhois(domain) {
  if (!domain) return { findings: [], riskScore: 0 };

  const findings = [];
  let riskScore = 0;
  const parts = domain.toLowerCase().split('.');
  const tld = '.' + parts[parts.length - 1];
  const baseName = parts[0];

  // TLD risk
  if (RISKY_TLDS.critical.includes(tld)) {
    findings.push({ severity: 'critical', title: 'Free/Abuse-Prone TLD', description: `The TLD "${tld}" is frequently used in phishing campaigns and is available for free registration.`, detail: `TLD: ${tld}` });
    riskScore += 40;
  } else if (RISKY_TLDS.high.includes(tld)) {
    findings.push({ severity: 'high', title: 'High-Risk TLD', description: `The TLD "${tld}" has a high abuse rate and is commonly used in phishing.`, detail: `TLD: ${tld}` });
    riskScore += 25;
  } else if (RISKY_TLDS.medium.includes(tld)) {
    findings.push({ severity: 'medium', title: 'Elevated-Risk TLD', description: `The TLD "${tld}" has a moderate abuse rate.`, detail: `TLD: ${tld}` });
    riskScore += 15;
  } else if (TRUSTED_TLDS.includes(tld)) {
    findings.push({ severity: 'low', title: 'Common TLD', description: `The TLD "${tld}" is a well-established, commonly used TLD.`, detail: `TLD: ${tld}` });
  }

  // Domain length analysis
  if (baseName.length > 30) {
    findings.push({ severity: 'medium', title: 'Unusually Long Domain', description: `The domain name is ${baseName.length} characters long, which is unusual for legitimate brands.`, detail: baseName });
    riskScore += 15;
  }

  // Excessive hyphens
  const hyphens = (baseName.match(/-/g) || []).length;
  if (hyphens >= 3) {
    findings.push({ severity: 'high', title: 'Excessive Hyphens', description: `The domain contains ${hyphens} hyphens. Phishing domains often use hyphens to mimic legitimate URLs.`, detail: baseName });
    riskScore += 20;
  }

  // Numbers mixed with brand-like text
  if (/[a-z]+\d+[a-z]+/i.test(baseName) || /\d+[a-z]+\d+/i.test(baseName)) {
    findings.push({ severity: 'medium', title: 'Mixed Numbers and Letters', description: 'Domain contains interspersed numbers, a pattern common in phishing domains.', detail: baseName });
    riskScore += 10;
  }

  // Subdomain depth
  if (parts.length > 4) {
    findings.push({ severity: 'medium', title: 'Deep Subdomain Nesting', description: `Domain has ${parts.length - 1} levels, suggesting possible URL obfuscation.`, detail: domain });
    riskScore += 15;
  }

  // Brand impersonation keywords
  const brandKeywords = ['login', 'secure', 'verify', 'account', 'update', 'banking', 'support', 'service', 'help', 'admin'];
  const foundKeywords = brandKeywords.filter(k => baseName.includes(k));
  if (foundKeywords.length >= 2) {
    findings.push({ severity: 'high', title: 'Suspicious Keywords in Domain', description: `Domain contains security-related keywords: ${foundKeywords.join(', ')}. Common in phishing.`, detail: baseName });
    riskScore += 20;
  } else if (foundKeywords.length === 1) {
    findings.push({ severity: 'low', title: 'Security Keyword in Domain', description: `Domain contains: "${foundKeywords[0]}".`, detail: baseName });
    riskScore += 5;
  }

  // Entropy analysis (randomness)
  const entropy = calculateEntropy(baseName);
  if (entropy > 3.5 && baseName.length > 10) {
    findings.push({ severity: 'medium', title: 'High Randomness', description: `Domain name entropy is ${entropy.toFixed(2)}, suggesting algorithmically generated name (DGA).`, detail: baseName });
    riskScore += 15;
  }

  const level = riskScore >= 60 ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 20 ? 'medium' : riskScore >= 5 ? 'low' : 'none';

  return {
    findings,
    riskScore: Math.min(riskScore, 100),
    level,
    tld,
    domainLength: baseName.length,
    subdomainDepth: parts.length - 1,
    entropy: calculateEntropy(baseName).toFixed(2),
    isTrustedTLD: TRUSTED_TLDS.includes(tld),
  };
}

function calculateEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
