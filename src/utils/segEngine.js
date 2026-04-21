// Proofpoint-style Secure Email Gateway Engine
// Performs spam scoring, threat classification, URL Defense, BEC detection, policy evaluation

// ========== SPAM SCORING ENGINE ==========
const SPAM_RULES = [
  // Header rules
  { id: 'HDR_NO_DKIM', test: (ctx) => ctx.dkim === 'none', score: 1.2, desc: 'No DKIM signature present' },
  { id: 'HDR_DKIM_FAIL', test: (ctx) => ctx.dkim === 'fail', score: 2.5, desc: 'DKIM signature verification failed' },
  { id: 'HDR_SPF_FAIL', test: (ctx) => ctx.spf === 'fail' || ctx.spf === 'softfail', score: 2.0, desc: 'SPF authentication failed' },
  { id: 'HDR_DMARC_FAIL', test: (ctx) => ctx.dmarc === 'fail', score: 2.5, desc: 'DMARC policy failed' },
  { id: 'HDR_FROM_REPLY_MISMATCH', test: (ctx) => ctx.fromDomain && ctx.replyDomain && ctx.fromDomain !== ctx.replyDomain, score: 2.0, desc: 'From and Reply-To domains mismatch' },
  { id: 'HDR_SUSPECT_MAILER', test: (ctx) => /phpmailer|swiftmailer|python/i.test(ctx.xmailer || ''), score: 1.5, desc: 'Suspicious X-Mailer software' },
  { id: 'HDR_NO_MSGID', test: (ctx) => !ctx.headers['message-id'], score: 1.0, desc: 'Missing Message-ID header' },
  { id: 'HDR_FORGED_OUTLOOK', test: (ctx) => /outlook|microsoft/i.test(ctx.xmailer || '') && ctx.spf !== 'pass', score: 1.8, desc: 'Claims Microsoft mailer but fails auth' },

  // Content rules
  { id: 'BODY_URGENCY', test: (ctx) => ctx.urgencyScore >= 8, score: 1.5, desc: 'High urgency language detected' },
  { id: 'BODY_SOCIAL_ENG', test: (ctx) => ctx.socialScore >= 10, score: 2.0, desc: 'Social engineering patterns' },
  { id: 'BODY_CRED_PHISH', test: (ctx) => /verify.*(account|identity)|confirm.*password|update.*payment/i.test(ctx.bodyText), score: 2.5, desc: 'Credential phishing language' },
  { id: 'BODY_HTML_FORM', test: (ctx) => /<form[\s>]/i.test(ctx.bodyText), score: 2.0, desc: 'HTML form in email body' },
  { id: 'BODY_HIDDEN_TEXT', test: (ctx) => /display:\s*none|font-size:\s*0|color:\s*#fff.*background.*#fff/i.test(ctx.bodyText), score: 1.5, desc: 'Hidden text detected' },
  { id: 'BODY_EXCESSIVE_CAPS', test: (ctx) => ((ctx.bodyText.match(/[A-Z]{5,}/g) || []).length > 3), score: 0.8, desc: 'Excessive capitalization' },
  { id: 'BODY_WIRE_TRANSFER', test: (ctx) => /wire\s+transfer|gift\s+card|bitcoin|cryptocurrency/i.test(ctx.bodyText), score: 2.0, desc: 'Financial transfer request' },

  // URL rules
  { id: 'URI_IP_HOST', test: (ctx) => ctx.urlFindings.some(f => f.title?.includes('IP Address')), score: 2.0, desc: 'URL with IP address host' },
  { id: 'URI_SHORTENER', test: (ctx) => ctx.urlFindings.some(f => f.title?.includes('Shortener')), score: 1.0, desc: 'URL shortener detected' },
  { id: 'URI_SUSPICIOUS_TLD', test: (ctx) => ctx.urlFindings.some(f => f.title?.includes('Suspicious TLD')), score: 1.5, desc: 'Suspicious TLD in URL' },
  { id: 'URI_IMPERSONATION', test: (ctx) => ctx.urlFindings.some(f => f.title?.includes('Impersonation')), score: 2.5, desc: 'Domain impersonation in URL' },
  { id: 'URI_PUNYCODE', test: (ctx) => ctx.urlFindings.some(f => f.title?.includes('Punycode')), score: 2.0, desc: 'Internationalized domain attack' },

  // Attachment rules
  { id: 'ATT_EXECUTABLE', test: (ctx) => ctx.attachmentRisk >= 80, score: 3.0, desc: 'Executable attachment detected' },
  { id: 'ATT_DOUBLE_EXT', test: (ctx) => ctx.attachmentFindings.some(f => f.title?.includes('Double Extension')), score: 3.0, desc: 'Double extension trick' },
  { id: 'ATT_MACRO', test: (ctx) => ctx.attachmentFindings.some(f => f.title?.includes('Macro')), score: 2.0, desc: 'Macro-enabled attachment' },
];

export function runSEGAnalysis(headerResult, urlResult, contentResult, attachmentResult, parsed) {
  const ctx = buildContext(headerResult, urlResult, contentResult, attachmentResult, parsed);
  const spamResult = runSpamScoring(ctx);
  const threatClass = classifyThreat(ctx, spamResult);
  const urlDefense = analyzeURLDefense(ctx);
  const becResult = detectBEC(ctx);
  const policyResult = evaluatePolicy(ctx, spamResult, threatClass);
  const quarantine = decideQuarantine(spamResult, threatClass, becResult, policyResult);

  return { spamResult, threatClass, urlDefense, becResult, policyResult, quarantine };
}

function buildContext(headerResult, urlResult, contentResult, attachmentResult, parsed) {
  return {
    headers: parsed.headers || {},
    dkim: headerResult?.dkim?.result || 'none',
    spf: headerResult?.spf?.result || 'none',
    dmarc: headerResult?.dmarc?.result || 'none',
    fromDomain: extractDomain(headerResult?.from || ''),
    replyDomain: extractDomain(headerResult?.replyTo || ''),
    xmailer: parsed.headers?.['x-mailer'] || '',
    bodyText: parsed.bodyHtml || parsed.bodyPlain || '',
    urgencyScore: contentResult?.urgencyScore || 0,
    socialScore: contentResult?.socialScore || 0,
    urlFindings: urlResult?.findings || [],
    urls: urlResult?.urls || [],
    attachmentRisk: attachmentResult?.totalRisk || 0,
    attachmentFindings: attachmentResult?.findings || [],
    attachments: attachmentResult?.analyzed || [],
    subject: headerResult?.subject || '',
    from: headerResult?.from || '',
    replyTo: headerResult?.replyTo || '',
  };
}

function extractDomain(str) {
  const m = str.match(/@([a-zA-Z0-9.-]+)/);
  return m ? m[1].toLowerCase() : '';
}

// ========== SPAM SCORING ==========
function runSpamScoring(ctx) {
  const triggered = [];
  let totalScore = 0;

  for (const rule of SPAM_RULES) {
    try {
      if (rule.test(ctx)) {
        triggered.push({ id: rule.id, score: rule.score, desc: rule.desc });
        totalScore += rule.score;
      }
    } catch { /* skip failed rules */ }
  }

  totalScore = Math.round(totalScore * 10) / 10;
  const capped = Math.min(totalScore, 10);
  const verdict = capped >= 7 ? 'spam' : capped >= 4 ? 'suspect' : capped >= 2 ? 'bulk' : 'clean';

  return { score: capped, rawScore: totalScore, verdict, triggered, rulesChecked: SPAM_RULES.length, rulesTriggered: triggered.length };
}

// ========== THREAT CLASSIFICATION ==========
function classifyThreat(ctx, spamResult) {
  const scores = { phishing: 0, malware: 0, bec: 0, spam: 0 };

  // Phishing indicators
  if (ctx.urlFindings.some(f => f.title?.includes('Impersonation'))) scores.phishing += 30;
  if (ctx.urlFindings.some(f => f.title?.includes('IP Address'))) scores.phishing += 20;
  if (/verify.*account|confirm.*identity|update.*payment/i.test(ctx.bodyText)) scores.phishing += 25;
  if (ctx.spf === 'fail' || ctx.dkim === 'fail') scores.phishing += 15;
  if (ctx.dmarc === 'fail') scores.phishing += 20;
  if (ctx.socialScore >= 5) scores.phishing += 15;

  // Malware indicators
  if (ctx.attachmentRisk >= 80) scores.malware += 40;
  if (ctx.attachmentFindings.some(f => f.title?.includes('Double Extension'))) scores.malware += 30;
  if (ctx.attachmentFindings.some(f => f.title?.includes('Executable'))) scores.malware += 30;

  // BEC indicators
  if (ctx.fromDomain !== ctx.replyDomain && ctx.replyDomain) scores.bec += 20;
  if (/wire\s+transfer|gift\s+card|payment/i.test(ctx.bodyText)) scores.bec += 25;
  if (/ceo|cfo|director|president|executive/i.test(ctx.from)) scores.bec += 15;
  if (ctx.urgencyScore >= 8 && /wire|transfer|payment|invoice/i.test(ctx.bodyText)) scores.bec += 20;

  // Spam indicators
  scores.spam = spamResult.score * 10;

  // Determine primary category
  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const primary = sorted[0][1] > 20 ? sorted[0][0] : 'clean';
  const confidence = sorted[0][1] > 0 ? Math.min(Math.round(sorted[0][1]), 100) : 0;

  return { primary, confidence, scores, allCategories: sorted };
}

// ========== URL DEFENSE ==========
function analyzeURLDefense(ctx) {
  const results = [];
  for (const u of ctx.urls) {
    const risk = [];
    let rewritten = false;

    if (u.riskScore >= 30) {
      rewritten = true;
      risk.push('Would be rewritten by URL Defense');
    }
    if (u.isShortener) {
      risk.push('Redirect chain requires real-time sandboxing');
      rewritten = true;
    }
    if (u.hostname && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u.hostname)) {
      risk.push('IP-based URL blocked at gateway');
      rewritten = true;
    }

    results.push({
      url: u.url,
      hostname: u.hostname,
      rewritten,
      riskScore: u.riskScore,
      actions: risk,
      clickTimeSafe: u.riskScore < 20,
    });
  }

  const blocked = results.filter(r => r.riskScore >= 50).length;
  const rewritten_count = results.filter(r => r.rewritten).length;

  return { results, totalURLs: results.length, blocked, rewritten: rewritten_count };
}

// ========== BEC DETECTION ==========
function detectBEC(ctx) {
  const indicators = [];
  let score = 0;

  // Display name spoofing
  const displayName = ctx.from.replace(/<[^>]+>/, '').trim().toLowerCase();
  const execTitles = ['ceo', 'cfo', 'cto', 'president', 'director', 'vp ', 'vice president', 'chief', 'executive'];
  if (execTitles.some(t => displayName.includes(t))) {
    indicators.push({ level: 'high', text: 'Executive title in display name — potential impersonation' });
    score += 30;
  }

  // Domain cousin detection
  if (ctx.fromDomain) {
    const lookalikes = generateCousins(ctx.fromDomain);
    if (lookalikes.length > 0) {
      indicators.push({ level: 'info', text: `Domain "${ctx.fromDomain}" could be a cousin domain` });
    }
  }

  // Reply-to mismatch
  if (ctx.fromDomain && ctx.replyDomain && ctx.fromDomain !== ctx.replyDomain) {
    indicators.push({ level: 'high', text: `Reply-To (${ctx.replyDomain}) differs from From (${ctx.fromDomain})` });
    score += 25;
  }

  // Free email provider in Reply-To
  const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com', 'aol.com'];
  if (freeProviders.includes(ctx.replyDomain)) {
    indicators.push({ level: 'high', text: `Reply-To uses free email provider (${ctx.replyDomain})` });
    score += 20;
  }

  // Financial urgency combo
  if (/wire|transfer|payment|invoice|bank/i.test(ctx.bodyText) && ctx.urgencyScore >= 4) {
    indicators.push({ level: 'critical', text: 'Financial request combined with urgency — classic BEC pattern' });
    score += 30;
  }

  const isBEC = score >= 40;
  return { isBEC, score: Math.min(score, 100), indicators };
}

function generateCousins(domain) {
  const base = domain.split('.')[0];
  const cousins = [];
  // Simple character substitution
  if (base.includes('l')) cousins.push(domain.replace('l', '1'));
  if (base.includes('o')) cousins.push(domain.replace('o', '0'));
  if (base.includes('i')) cousins.push(domain.replace('i', '1'));
  return cousins;
}

// ========== POLICY ENGINE ==========
function evaluatePolicy(ctx, spamResult, threatClass) {
  const checks = [];

  // DMARC enforcement
  checks.push({
    policy: 'DMARC Enforcement',
    status: ctx.dmarc === 'pass' ? 'pass' : ctx.dmarc === 'fail' ? 'fail' : 'warn',
    detail: ctx.dmarc === 'pass' ? 'DMARC aligned' : ctx.dmarc === 'fail' ? 'DMARC failed — policy violation' : 'No DMARC record found',
  });

  // Attachment policy
  const hasExec = ctx.attachmentRisk >= 80;
  checks.push({
    policy: 'Attachment Filtering',
    status: hasExec ? 'fail' : ctx.attachments.length > 0 ? 'warn' : 'pass',
    detail: hasExec ? 'Executable attachment blocked by policy' : ctx.attachments.length > 0 ? `${ctx.attachments.length} attachment(s) scanned` : 'No attachments',
  });

  // Content filtering
  checks.push({
    policy: 'Content Filtering',
    status: threatClass.primary === 'phishing' || threatClass.primary === 'malware' ? 'fail' : spamResult.verdict === 'spam' ? 'warn' : 'pass',
    detail: threatClass.primary !== 'clean' ? `Classified as ${threatClass.primary} (${threatClass.confidence}% confidence)` : 'Content clean',
  });

  // TLS encryption
  const receivedHeaders = ctx.headers['received'];
  const hasEncryption = Array.isArray(receivedHeaders)
    ? receivedHeaders.some(r => /TLS|ESMTPS|SSL/i.test(r))
    : /TLS|ESMTPS|SSL/i.test(receivedHeaders || '');
  checks.push({
    policy: 'Transport Encryption',
    status: hasEncryption ? 'pass' : 'warn',
    detail: hasEncryption ? 'TLS encryption detected in transit' : 'No encryption headers found',
  });

  // PII exposure check
  const hasPII = /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/.test(ctx.bodyText) || /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(ctx.bodyText);
  checks.push({
    policy: 'PII/DLP Check',
    status: hasPII ? 'fail' : 'pass',
    detail: hasPII ? 'Potential PII (SSN/credit card patterns) detected' : 'No PII patterns detected',
  });

  const passed = checks.filter(c => c.status === 'pass').length;
  const failed = checks.filter(c => c.status === 'fail').length;

  return { checks, passed, failed, total: checks.length };
}

// ========== QUARANTINE DECISION ==========
function decideQuarantine(spamResult, threatClass, becResult, policyResult) {
  let action = 'deliver';
  let confidence = 0;
  const reasons = [];

  if (threatClass.primary === 'malware') {
    action = 'reject';
    confidence = 95;
    reasons.push('Malware detected — message rejected');
  } else if (threatClass.primary === 'phishing' && threatClass.confidence >= 60) {
    action = 'reject';
    confidence = threatClass.confidence;
    reasons.push(`High-confidence phishing (${threatClass.confidence}%) — message rejected`);
  } else if (threatClass.primary === 'phishing') {
    action = 'quarantine';
    confidence = threatClass.confidence;
    reasons.push(`Phishing detected (${threatClass.confidence}% confidence) — quarantined for review`);
  } else if (becResult.isBEC) {
    action = 'quarantine';
    confidence = becResult.score;
    reasons.push('BEC indicators detected — quarantined for review');
  } else if (spamResult.verdict === 'spam') {
    action = 'quarantine';
    confidence = Math.round(spamResult.score * 10);
    reasons.push(`Spam score ${spamResult.score}/10 — quarantined`);
  } else if (spamResult.verdict === 'suspect') {
    action = 'quarantine';
    confidence = Math.round(spamResult.score * 10);
    reasons.push(`Suspicious content (score ${spamResult.score}/10) — quarantined`);
  } else if (policyResult.failed > 0) {
    action = 'quarantine';
    confidence = 60;
    reasons.push(`${policyResult.failed} policy violation(s) — quarantined`);
  } else {
    action = 'deliver';
    confidence = Math.max(10, 100 - spamResult.score * 10);
    reasons.push('No threats detected — delivered to inbox');
  }

  return { action, confidence, reasons };
}
