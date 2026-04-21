// Homograph detector — detect unicode lookalike characters in domains

// Map of confusable characters: unicode char -> ASCII equivalent
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
  'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', 'ʟ': 'l', 'ɴ': 'n',
  'ο': 'o', // Greek omicron
  'α': 'a', // Greek alpha
  'ε': 'e', // Greek epsilon
  'ι': 'i', // Greek iota
  'κ': 'k', // Greek kappa
  'ν': 'n', // Greek nu
  'τ': 't', // Greek tau
  'υ': 'u', // Greek upsilon
  'ᴀ': 'a', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ᴍ': 'm', 'ᴏ': 'o',
  'ᴘ': 'p', 'ᴛ': 't', 'ᴜ': 'u',
  'ℓ': 'l', 'ⅰ': 'i', 'ⅱ': 'ii',
  '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e',
  'ꮪ': 's', 'ꭰ': 'd',
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
  '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
  'ⅼ': 'l', 'Ⅰ': 'I',
};

// Common target brands for homograph attacks
const TARGET_BRANDS = [
  'google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix',
  'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
  'bankofamerica', 'citibank', 'dropbox', 'github', 'outlook',
  'yahoo', 'gmail', 'icloud', 'adobe', 'salesforce', 'slack',
];

export function detectHomographs(domain) {
  if (!domain) return { isHomograph: false, confusables: [], matchedBrand: null };

  const chars = [...domain];
  const confusables = [];
  let asciiEquivalent = '';

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    if (CONFUSABLES[char]) {
      confusables.push({
        position: i,
        original: char,
        looksLike: CONFUSABLES[char],
        codePoint: char.codePointAt(0).toString(16).toUpperCase(),
        unicodeName: getScriptName(char),
      });
      asciiEquivalent += CONFUSABLES[char];
    } else {
      asciiEquivalent += char;
    }
  }

  // Check if the ASCII equivalent matches a known brand
  const domainBase = asciiEquivalent.split('.')[0].toLowerCase();
  let matchedBrand = null;
  for (const brand of TARGET_BRANDS) {
    if (domainBase === brand || domainBase.includes(brand)) {
      matchedBrand = brand;
      break;
    }
  }

  return {
    isHomograph: confusables.length > 0,
    confusables,
    asciiEquivalent,
    matchedBrand,
    originalDomain: domain,
    riskLevel: confusables.length > 0 && matchedBrand ? 'critical' : confusables.length > 0 ? 'high' : 'none',
  };
}

export function analyzeDomainChars(domain) {
  const chars = [...domain];
  return chars.map((char, i) => {
    const isConfusable = !!CONFUSABLES[char];
    const codePoint = char.codePointAt(0);
    const isASCII = codePoint < 128;
    return {
      char,
      position: i,
      codePoint: codePoint.toString(16).toUpperCase().padStart(4, '0'),
      isASCII,
      isConfusable,
      looksLike: CONFUSABLES[char] || null,
      script: getScriptName(char),
    };
  });
}

function getScriptName(char) {
  const cp = char.codePointAt(0);
  if (cp >= 0x0400 && cp <= 0x04FF) return 'Cyrillic';
  if (cp >= 0x0370 && cp <= 0x03FF) return 'Greek';
  if (cp >= 0x1D00 && cp <= 0x1D7F) return 'Phonetic Extensions';
  if (cp >= 0x2100 && cp <= 0x214F) return 'Letterlike Symbols';
  if (cp >= 0xFF00 && cp <= 0xFFEF) return 'Fullwidth';
  if (cp >= 0x13A0 && cp <= 0x13FF) return 'Cherokee';
  if (cp >= 0x1D400 && cp <= 0x1D7FF) return 'Mathematical';
  if (cp < 128) return 'ASCII';
  return 'Other';
}

export function batchAnalyzeDomains(domains) {
  return domains.map(d => detectHomographs(d)).filter(r => r.isHomograph);
}
