// Header parser — extracts structured header data with security analysis

export function analyzeHeaders(headers) {
  const findings = [];
  const receivedChain = [];

  // SPF check
  const spf = extractAuthResult(headers, 'spf');
  const dkim = extractAuthResult(headers, 'dkim');
  const dmarc = extractAuthResult(headers, 'dmarc');

  if (spf.result === 'fail' || spf.result === 'softfail') {
    findings.push({ severity: 'critical', type: 'header', title: 'SPF Authentication Failed', description: `SPF result: ${spf.result}. The sending server is not authorized to send on behalf of this domain.`, detail: spf.raw });
  } else if (spf.result === 'none') {
    findings.push({ severity: 'medium', type: 'header', title: 'No SPF Record', description: 'No SPF record found for the sending domain. This is unusual for legitimate senders.', detail: spf.raw });
  }

  if (dkim.result === 'fail') {
    findings.push({ severity: 'critical', type: 'header', title: 'DKIM Signature Invalid', description: 'The DKIM signature verification failed. The email may have been tampered with in transit.', detail: dkim.raw });
  } else if (dkim.result === 'none') {
    findings.push({ severity: 'low', type: 'header', title: 'No DKIM Signature', description: 'No DKIM signature present. Cannot verify email integrity.', detail: dkim.raw });
  }

  if (dmarc.result === 'fail') {
    findings.push({ severity: 'critical', type: 'header', title: 'DMARC Policy Failed', description: 'DMARC validation failed. The email does not comply with the domain\'s DMARC policy.', detail: dmarc.raw });
  } else if (dmarc.result === 'none') {
    findings.push({ severity: 'low', type: 'header', title: 'No DMARC Policy', description: 'No DMARC policy found for the sending domain.', detail: dmarc.raw });
  }

  // From / Reply-To mismatch
  const from = typeof headers['from'] === 'string' ? headers['from'] : '';
  const replyTo = typeof headers['reply-to'] === 'string' ? headers['reply-to'] : '';
  if (from && replyTo) {
    const fromDomain = extractDomain(from);
    const replyDomain = extractDomain(replyTo);
    if (fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase()) {
      findings.push({ severity: 'high', type: 'header', title: 'From / Reply-To Domain Mismatch', description: `From domain (${fromDomain}) differs from Reply-To domain (${replyDomain}). This is a common phishing tactic.`, detail: `From: ${from}\nReply-To: ${replyTo}` });
    }
  }

  // Return-Path mismatch
  const returnPath = typeof headers['return-path'] === 'string' ? headers['return-path'] : '';
  if (from && returnPath) {
    const fromDomain = extractDomain(from);
    const rpDomain = extractDomain(returnPath);
    if (fromDomain && rpDomain && fromDomain.toLowerCase() !== rpDomain.toLowerCase()) {
      findings.push({ severity: 'medium', type: 'header', title: 'Return-Path Mismatch', description: `Return-Path domain (${rpDomain}) differs from From domain (${fromDomain}).`, detail: `From: ${from}\nReturn-Path: ${returnPath}` });
    }
  }

  // Received chain analysis
  const received = headers['received'];
  const receivedHeaders = Array.isArray(received) ? received : (received ? [received] : []);
  
  for (let i = 0; i < receivedHeaders.length; i++) {
    const hop = parseReceivedHeader(receivedHeaders[i], i + 1);
    receivedChain.push(hop);
  }

  // Check for suspicious hops
  for (const hop of receivedChain) {
    if (hop.fromIP && isPrivateIP(hop.fromIP)) {
      // Not necessarily suspicious, skip
    } else if (hop.from && hop.from.includes('.') && countDots(hop.from) > 4) {
      findings.push({ severity: 'low', type: 'header', title: 'Unusual Hostname in Routing', description: `A routing hop has an unusual hostname: ${hop.from}`, detail: hop.raw });
    }
  }

  // X-Mailer suspicious
  const xmailer = headers['x-mailer'] || '';
  if (typeof xmailer === 'string' && xmailer) {
    const suspiciousMailers = ['PHPMailer', 'SwiftMailer', 'Python', 'ruby', 'perl'];
    for (const m of suspiciousMailers) {
      if (xmailer.toLowerCase().includes(m.toLowerCase())) {
        findings.push({ severity: 'medium', type: 'header', title: 'Suspicious Mailer Software', description: `X-Mailer: ${xmailer}. Scripting-based mailers are commonly used in phishing campaigns.`, detail: `X-Mailer: ${xmailer}` });
        break;
      }
    }
  }

  return { findings, spf, dkim, dmarc, receivedChain, from, replyTo, returnPath, subject: headers['subject'] || 'No Subject', date: headers['date'] || '' };
}

function extractAuthResult(headers, protocol) {
  const authResults = headers['authentication-results'];
  const results = Array.isArray(authResults) ? authResults.join(' ') : (authResults || '');
  
  const regex = new RegExp(`${protocol}\\s*=\\s*(\\w+)`, 'i');
  const match = results.match(regex);
  
  // Also check dedicated headers
  let dedicated = '';
  if (protocol === 'spf') dedicated = headers['received-spf'] || '';
  if (protocol === 'dkim') dedicated = headers['dkim-signature'] ? 'present' : '';

  const result = match ? match[1].toLowerCase() : 'none';
  const raw = match ? results : (typeof dedicated === 'string' ? dedicated : '');
  
  return { result, raw, protocol };
}

function extractDomain(emailStr) {
  const match = emailStr.match(/@([a-zA-Z0-9.-]+)/);
  return match ? match[1] : null;
}

function parseReceivedHeader(header, hopNum) {
  const fromMatch = header.match(/from\s+([^\s(]+)/i);
  const byMatch = header.match(/by\s+([^\s(]+)/i);
  const ipMatch = header.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  const dateMatch = header.match(/;\s*(.+)$/);

  return {
    hop: hopNum,
    from: fromMatch ? fromMatch[1] : 'unknown',
    by: byMatch ? byMatch[1] : 'unknown',
    fromIP: ipMatch ? ipMatch[1] : null,
    date: dateMatch ? dateMatch[1].trim() : '',
    raw: header
  };
}

function isPrivateIP(ip) {
  return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.match(/^172\.(1[6-9]|2\d|3[01])\./);
}

function countDots(str) {
  return (str.match(/\./g) || []).length;
}
