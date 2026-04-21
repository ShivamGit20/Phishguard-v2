// URL analyzer — extracts and evaluates URLs for phishing signals

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'short.io', 'cutt.ly', 'bl.ink', 'lnkd.in', 'rb.gy',
  'shorturl.at', 'tiny.cc', 'v.gd', 'x.co', 'clck.ru', 'qps.ru'
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.online', '.site', '.icu', '.buzz',
  '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws'
];

const LEGITIMATE_DOMAINS = [
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
  'netflix.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
  'bank', 'chase.com', 'wellsfargo.com', 'bankofamerica.com'
];

export function analyzeURLs(bodyText) {
  const findings = [];
  const urls = extractURLs(bodyText);

  for (const url of urls) {
    const analysis = analyzeURL(url);
    if (analysis.findings.length > 0) {
      findings.push(...analysis.findings);
    }
  }

  return { findings, urls: urls.map(u => ({ url: u, ...analyzeURL(u) })) };
}

function extractURLs(text) {
  if (!text) return [];
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const matches = text.match(urlRegex) || [];
  return [...new Set(matches)]; // deduplicate
}

function analyzeURL(url) {
  const findings = [];
  let riskScore = 0;

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // IP-based URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      findings.push({ severity: 'high', type: 'url', title: 'IP Address URL', description: `URL uses raw IP address (${hostname}) instead of a domain name. Legitimate services rarely do this.`, detail: url });
      riskScore += 30;
    }

    // Hex/octal encoded IP
    if (/^0x[0-9a-f]+$/i.test(hostname) || /^\d+$/.test(hostname)) {
      findings.push({ severity: 'critical', type: 'url', title: 'Encoded IP Address', description: 'URL uses an obfuscated IP address encoding technique.', detail: url });
      riskScore += 40;
    }

    // URL shortener
    if (URL_SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))) {
      findings.push({ severity: 'medium', type: 'url', title: 'URL Shortener Detected', description: `Shortened URL (${hostname}) hides the actual destination. Could redirect to a malicious site.`, detail: url });
      riskScore += 20;
    }

    // Suspicious TLD
    const tld = '.' + hostname.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      findings.push({ severity: 'medium', type: 'url', title: 'Suspicious TLD', description: `The domain uses a suspicious top-level domain (${tld}) commonly associated with phishing.`, detail: url });
      riskScore += 15;
    }

    // Lookalike/typosquatting check
    for (const legit of LEGITIMATE_DOMAINS) {
      if (hostname !== legit && hostname.includes(legit.split('.')[0]) && !hostname.endsWith('.' + legit)) {
        findings.push({ severity: 'high', type: 'url', title: 'Possible Domain Impersonation', description: `Domain "${hostname}" may be impersonating "${legit}".`, detail: url });
        riskScore += 30;
        break;
      }
    }

    // Excessive subdomains
    const parts = hostname.split('.');
    if (parts.length > 4) {
      findings.push({ severity: 'medium', type: 'url', title: 'Excessive Subdomains', description: `Domain has ${parts.length - 1} levels of subdomains, which is unusual and potentially suspicious.`, detail: url });
      riskScore += 15;
    }

    // Contains @ symbol (credential harvesting trick)
    if (url.includes('@')) {
      findings.push({ severity: 'high', type: 'url', title: 'URL Contains @ Symbol', description: 'The @ symbol in URLs can be used to mislead users about the actual destination.', detail: url });
      riskScore += 25;
    }

    // Data URI
    if (url.startsWith('data:')) {
      findings.push({ severity: 'critical', type: 'url', title: 'Data URI Detected', description: 'Data URIs can embed malicious content directly in the URL.', detail: url.substring(0, 100) + '...' });
      riskScore += 40;
    }

    // Punycode / IDN
    if (hostname.startsWith('xn--')) {
      findings.push({ severity: 'high', type: 'url', title: 'Internationalized Domain (Punycode)', description: 'Domain uses international characters that may visually impersonate a legitimate domain (homograph attack).', detail: url });
      riskScore += 30;
    }

    // Suspicious path keywords
    const suspiciousPathWords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'password', 'credential', 'banking'];
    const pathLower = parsed.pathname.toLowerCase();
    for (const word of suspiciousPathWords) {
      if (pathLower.includes(word)) {
        findings.push({ severity: 'medium', type: 'url', title: 'Suspicious Path Keyword', description: `URL path contains "${word}" which is common in phishing URLs.`, detail: url });
        riskScore += 10;
        break;
      }
    }

    // Non-standard port
    if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
      findings.push({ severity: 'medium', type: 'url', title: 'Non-Standard Port', description: `URL uses port ${parsed.port}, which is unusual for legitimate web services.`, detail: url });
      riskScore += 15;
    }

    return { findings, riskScore: Math.min(riskScore, 100), hostname, isShortener: URL_SHORTENERS.includes(hostname) };
  } catch {
    return { findings, riskScore: 0, hostname: '', isShortener: false };
  }
}
