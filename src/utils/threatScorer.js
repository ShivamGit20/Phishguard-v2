// Threat scorer — aggregates all findings into a single 0-100 score

const WEIGHTS = {
  header: 0.30,
  url: 0.30,
  content: 0.25,
  attachment: 0.15,
};

const SEVERITY_SCORES = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

export function calculateThreatScore(headerResult, urlResult, contentResult, attachmentResult) {
  const allFindings = [
    ...(headerResult?.findings || []),
    ...(urlResult?.findings || []),
    ...(contentResult?.findings || []),
    ...(attachmentResult?.findings || []),
  ];

  // Calculate per-category scores
  const categoryScores = { header: 0, url: 0, content: 0, attachment: 0 };

  for (const f of allFindings) {
    const score = SEVERITY_SCORES[f.severity] || 0;
    if (categoryScores[f.type] !== undefined) {
      categoryScores[f.type] += score;
    }
  }

  // Cap each category at 100
  for (const k of Object.keys(categoryScores)) {
    categoryScores[k] = Math.min(categoryScores[k], 100);
  }

  // Weighted total
  let totalScore = 0;
  for (const [cat, weight] of Object.entries(WEIGHTS)) {
    totalScore += categoryScores[cat] * weight;
  }

  totalScore = Math.min(Math.round(totalScore), 100);

  const level = totalScore >= 75 ? 'critical' : totalScore >= 50 ? 'high' : totalScore >= 25 ? 'medium' : totalScore >= 10 ? 'low' : 'none';

  const label = { critical: 'Critical Threat', high: 'High Risk', medium: 'Moderate Risk', low: 'Low Risk', none: 'Clean' }[level];

  return {
    score: totalScore,
    level,
    label,
    categoryScores,
    totalFindings: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === 'critical').length,
    highCount: allFindings.filter(f => f.severity === 'high').length,
    mediumCount: allFindings.filter(f => f.severity === 'medium').length,
    lowCount: allFindings.filter(f => f.severity === 'low').length,
    allFindings,
  };
}
