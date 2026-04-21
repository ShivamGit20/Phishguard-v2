// Content analyzer — detects social engineering and suspicious content patterns

const URGENCY_PHRASES = [
  { pattern: /\bimmediately\b/i, weight: 3 },
  { pattern: /\burgent(ly)?\b/i, weight: 4 },
  { pattern: /\basap\b/i, weight: 3 },
  { pattern: /\bact\s+now\b/i, weight: 4 },
  { pattern: /\bexpir(e|es|ed|ing)\b/i, weight: 3 },
  { pattern: /\bsuspend(ed)?\b/i, weight: 4 },
  { pattern: /\bdeactivat(e|ed|ion)\b/i, weight: 4 },
  { pattern: /\bterminat(e|ed|ion)\b/i, weight: 4 },
  { pattern: /\bfinal\s+(warning|notice)\b/i, weight: 5 },
  { pattern: /\blast\s+chance\b/i, weight: 4 },
  { pattern: /within\s+\d+\s+(hour|day|minute)/i, weight: 4 },
];

const SOCIAL_ENGINEERING = [
  { pattern: /\bverify\s+your\s+(account|identity|information)\b/i, weight: 4, label: 'Account verification request' },
  { pattern: /\bconfirm\s+your\s+(identity|password|account)\b/i, weight: 4, label: 'Identity confirmation request' },
  { pattern: /\bupdate\s+your\s+(payment|billing|account)\b/i, weight: 4, label: 'Account update request' },
  { pattern: /\bunusual\s+(activity|sign-in|login)\b/i, weight: 4, label: 'Unusual activity alert' },
  { pattern: /\bunauthorized\s+(access|transaction)\b/i, weight: 4, label: 'Unauthorized access claim' },
  { pattern: /\bclick\s+(here|below|the\s+link)\b/i, weight: 3, label: 'Click directive' },
  { pattern: /\bwin|won|winner|congratulations\b/i, weight: 3, label: 'Prize/winning claim' },
  { pattern: /\bdear\s+(customer|user|member|valued)\b/i, weight: 2, label: 'Generic greeting' },
  { pattern: /\bcredit\s+card\s+(number|details)\b/i, weight: 5, label: 'Credit card info request' },
  { pattern: /\bsocial\s+security\b/i, weight: 5, label: 'SSN request' },
  { pattern: /\bpassword\b/i, weight: 3, label: 'Password mention' },
  { pattern: /\bwire\s+transfer\b/i, weight: 4, label: 'Wire transfer request' },
  { pattern: /\bgift\s+card\b/i, weight: 4, label: 'Gift card request' },
];

export function analyzeContent(bodyText) {
  const findings = [];
  if (!bodyText) return { findings, urgencyScore: 0, socialScore: 0, highlights: [] };

  const text = bodyText.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  let urgencyScore = 0, socialScore = 0;
  const highlights = [];

  for (const { pattern, weight } of URGENCY_PHRASES) {
    const matches = text.match(pattern);
    if (matches) {
      urgencyScore += weight * matches.length;
      matches.forEach(m => highlights.push({ text: m, type: 'urgency' }));
    }
  }

  if (urgencyScore >= 8) {
    findings.push({ severity: 'high', type: 'content', title: 'High Urgency Language Detected', description: `Found ${highlights.filter(h => h.type === 'urgency').length} urgency indicators. Phishing emails use time pressure to bypass critical thinking.`, detail: highlights.filter(h => h.type === 'urgency').map(h => `"${h.text}"`).join(', ') });
  } else if (urgencyScore >= 4) {
    findings.push({ severity: 'medium', type: 'content', title: 'Moderate Urgency Language', description: 'Some urgency language detected.', detail: highlights.filter(h => h.type === 'urgency').map(h => `"${h.text}"`).join(', ') });
  }

  const seMatches = [];
  for (const { pattern, weight, label } of SOCIAL_ENGINEERING) {
    const matches = text.match(pattern);
    if (matches) {
      socialScore += weight * matches.length;
      seMatches.push(label);
      matches.forEach(m => highlights.push({ text: m, type: 'social' }));
    }
  }

  if (socialScore >= 10) {
    findings.push({ severity: 'critical', type: 'content', title: 'Strong Social Engineering Indicators', description: `Multiple social engineering patterns: ${seMatches.join(', ')}.`, detail: highlights.filter(h => h.type === 'social').map(h => `"${h.text}"`).join(', ') });
  } else if (socialScore >= 5) {
    findings.push({ severity: 'high', type: 'content', title: 'Social Engineering Patterns', description: `Detected: ${seMatches.join(', ')}.`, detail: highlights.filter(h => h.type === 'social').map(h => `"${h.text}"`).join(', ') });
  }

  // Grammar anomalies
  if ((text.match(/!{2,}/g) || []).length > 0) {
    findings.push({ severity: 'low', type: 'content', title: 'Excessive Exclamation Marks', description: 'Multiple exclamation marks detected.', detail: '' });
  }
  if ((text.match(/[A-Z]{5,}/g) || []).length > 2) {
    findings.push({ severity: 'low', type: 'content', title: 'Excessive Capitalization', description: 'Multiple fully capitalized words detected.', detail: '' });
  }

  return { findings, urgencyScore: Math.min(urgencyScore, 100), socialScore: Math.min(socialScore, 100), highlights };
}
