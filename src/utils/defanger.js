// URL/IP Defanger — convert malicious indicators to safe-to-share format

export function defangURL(url) {
  return url
    .replace(/https?/gi, m => m.replace(/t/i, 'x').replace(/T/i, 'X'))
    .replace(/\./g, '[.]')
    .replace(/:\/\//g, '[://]');
}

export function refangURL(defanged) {
  return defanged
    .replace(/hxxps?/gi, m => m.replace(/x/gi, 't'))
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\/\/\]/g, '://');
}

export function defangIP(ip) {
  return ip.replace(/\./g, '[.]');
}

export function refangIP(defanged) {
  return defanged.replace(/\[\.\]/g, '.');
}

export function defangDomain(domain) {
  return domain.replace(/\./g, '[.]');
}

export function defangEmail(email) {
  return email.replace(/@/g, '[@]').replace(/\./g, '[.]');
}

export function defangBulk(text) {
  let result = text;
  // Defang URLs
  result = result.replace(/https?:\/\/[^\s<>"')\]]+/gi, match => defangURL(match));
  // Defang remaining IPs
  result = result.replace(/\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g, match => defangIP(match));
  // Defang emails
  result = result.replace(/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, match => defangEmail(match));
  return result;
}

export function refangBulk(text) {
  let result = text;
  result = result.replace(/hxxps?\[:\/\/\][^\s]+/gi, match => refangURL(match));
  result = result.replace(/\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}/g, match => refangIP(match));
  result = result.replace(/\[\.\]/g, '.');
  result = result.replace(/\[@\]/g, '@');
  return result;
}
