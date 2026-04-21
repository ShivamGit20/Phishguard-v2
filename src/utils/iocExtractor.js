// IOC Extractor — extract Indicators of Compromise from text

const PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|info|biz|xyz|top|club|online|site|icu|io|co|me|us|uk|de|fr|ru|cn|jp|br|au|in|nl|se|no|fi|dk|pl|cz|sk|hu|ro|bg|hr|rs|ua|by|kz|ir|sa|ae|il|za|ng|ke|eg|ar|cl|mx|ca)\b/gi,
  url: /https?:\/\/[^\s<>"')\]]+/gi,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  btcAddress: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  cve: /CVE-\d{4}-\d{4,}/gi,
};

export function extractIOCs(text) {
  if (!text) return { categories: {}, total: 0 };

  const stripped = text.replace(/<[^>]+>/g, ' ');
  const categories = {};
  let total = 0;

  for (const [type, regex] of Object.entries(PATTERNS)) {
    const matches = stripped.match(new RegExp(regex.source, regex.flags)) || [];
    const unique = [...new Set(matches.map(m => m.toLowerCase()))];
    if (unique.length > 0) {
      // Filter out false positives
      const filtered = filterIOCs(type, unique);
      if (filtered.length > 0) {
        categories[type] = filtered;
        total += filtered.length;
      }
    }
  }

  return { categories, total };
}

function filterIOCs(type, items) {
  if (type === 'ipv4') {
    return items.filter(ip => {
      // Exclude private/loopback/link-local
      if (ip.startsWith('127.') || ip.startsWith('0.') || ip === '255.255.255.255') return false;
      return true;
    });
  }
  if (type === 'md5' || type === 'sha1' || type === 'sha256') {
    // Exclude strings that are all same char (like 000...0)
    return items.filter(h => new Set(h).size > 4);
  }
  return items;
}

export function exportAsJSON(iocs) {
  return JSON.stringify(iocs.categories, null, 2);
}

export function exportAsCSV(iocs) {
  const lines = ['Type,Value'];
  for (const [type, values] of Object.entries(iocs.categories)) {
    for (const val of values) {
      lines.push(`${type},"${val}"`);
    }
  }
  return lines.join('\n');
}

export function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const IOC_TYPE_LABELS = {
  ipv4: 'IPv4 Addresses',
  ipv6: 'IPv6 Addresses',
  domain: 'Domains',
  url: 'URLs',
  email: 'Email Addresses',
  md5: 'MD5 Hashes',
  sha1: 'SHA-1 Hashes',
  sha256: 'SHA-256 Hashes',
  btcAddress: 'Bitcoin Addresses',
  cve: 'CVE IDs',
};

export function getTypeLabel(type) {
  return IOC_TYPE_LABELS[type] || type;
}

const IOC_TYPE_ICONS = {
  ipv4: '🌐', ipv6: '🌐', domain: '🏷️', url: '🔗', email: '📧',
  md5: '#️⃣', sha1: '#️⃣', sha256: '#️⃣', btcAddress: '₿', cve: '🛡️',
};

export function getTypeIcon(type) {
  return IOC_TYPE_ICONS[type] || '📌';
}
