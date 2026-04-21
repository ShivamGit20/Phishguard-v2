// EML file parser — extracts headers, body, and attachment info from raw .eml text

export function parseEml(rawText) {
  const result = { headers: {}, rawHeaders: '', bodyPlain: '', bodyHtml: '', attachments: [], raw: rawText };
  if (!rawText) return result;

  // Split headers and body
  const headerBodySplit = rawText.indexOf('\r\n\r\n') !== -1
    ? rawText.indexOf('\r\n\r\n')
    : rawText.indexOf('\n\n');

  if (headerBodySplit === -1) {
    result.rawHeaders = rawText;
    parseHeaders(rawText, result);
    return result;
  }

  result.rawHeaders = rawText.substring(0, headerBodySplit);
  const bodyPart = rawText.substring(headerBodySplit).trim();
  parseHeaders(result.rawHeaders, result);

  const contentType = result.headers['content-type'] || '';
  const boundary = extractBoundary(contentType);

  if (boundary) {
    parseMimeParts(bodyPart, boundary, result);
  } else if (contentType.includes('text/html')) {
    result.bodyHtml = bodyPart;
  } else {
    result.bodyPlain = bodyPart;
  }

  return result;
}

function parseHeaders(headerText, result) {
  // Unfold headers (continuation lines start with whitespace)
  const unfolded = headerText.replace(/\r?\n[ \t]+/g, ' ');
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();

    if (result.headers[key]) {
      if (Array.isArray(result.headers[key])) {
        result.headers[key].push(value);
      } else {
        result.headers[key] = [result.headers[key], value];
      }
    } else {
      result.headers[key] = value;
    }
  }
}

function extractBoundary(contentType) {
  const match = contentType.match(/boundary\s*=\s*"?([^";\s]+)"?/i);
  return match ? match[1] : null;
}

function parseMimeParts(body, boundary, result) {
  const parts = body.split('--' + boundary);

  for (const part of parts) {
    if (part.trim() === '' || part.trim() === '--') continue;

    const partHeaderEnd = part.indexOf('\r\n\r\n') !== -1
      ? part.indexOf('\r\n\r\n')
      : part.indexOf('\n\n');

    if (partHeaderEnd === -1) continue;

    const partHeaders = part.substring(0, partHeaderEnd).trim().toLowerCase();
    const partBody = part.substring(partHeaderEnd).trim();

    const contentDisp = extractHeaderValue(partHeaders, 'content-disposition');
    const partContentType = extractHeaderValue(partHeaders, 'content-type');

    if (contentDisp && contentDisp.includes('attachment')) {
      const filename = extractFilename(contentDisp) || extractFilename(partContentType) || 'unknown';
      result.attachments.push({
        filename,
        contentType: partContentType,
        size: partBody.length,
        encoding: extractHeaderValue(partHeaders, 'content-transfer-encoding') || '7bit'
      });
    } else if (partContentType && partContentType.includes('text/html')) {
      result.bodyHtml = partBody;
    } else if (partContentType && partContentType.includes('text/plain')) {
      result.bodyPlain = partBody;
    } else if (!partContentType || partContentType.includes('text/')) {
      if (!result.bodyPlain) result.bodyPlain = partBody;
    }

    // Check for nested multipart
    const nestedBoundary = extractBoundary(partContentType || '');
    if (nestedBoundary) {
      parseMimeParts(partBody, nestedBoundary, result);
    }
  }
}

function extractHeaderValue(headers, name) {
  const regex = new RegExp(`^${name}:\\s*(.+)$`, 'mi');
  const match = headers.match(regex);
  return match ? match[1].trim() : '';
}

function extractFilename(str) {
  if (!str) return null;
  const match = str.match(/(?:file)?name\s*=\s*"?([^";\n]+)"?/i);
  return match ? match[1].trim() : null;
}
