import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

export default function ThreatGauge({ score, level, label }) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const duration = 1500;
    const stepTime = 16;
    const steps = duration / stepTime;
    const increment = score / steps;
    const timer = setInterval(() => {
      start += increment;
      if (start >= score) { start = score; clearInterval(timer); }
      setAnimatedScore(Math.round(start));
    }, stepTime);
    return () => clearInterval(timer);
  }, [score]);

  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokePct = ((100 - animatedScore) / 100) * circumference;

  const getColor = () => {
    if (animatedScore >= 75) return '#ff3b5c';
    if (animatedScore >= 50) return '#ff6b6b';
    if (animatedScore >= 25) return '#ffab00';
    if (animatedScore >= 10) return '#00e676';
    return '#525c72';
  };

  const getTrailColor = () => {
    if (animatedScore >= 75) return 'rgba(255,59,92,0.12)';
    if (animatedScore >= 50) return 'rgba(255,107,107,0.12)';
    if (animatedScore >= 25) return 'rgba(255,171,0,0.12)';
    return 'rgba(0,230,118,0.12)';
  };

  return (
    <motion.div
      className="gauge-container"
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
    >
      <svg width="200" height="200" viewBox="0 0 200 200">
        {/* Trail */}
        <circle cx="100" cy="100" r={radius} fill="none" stroke={getTrailColor()} strokeWidth="12" />
        {/* Active arc */}
        <circle
          cx="100" cy="100" r={radius} fill="none"
          stroke={getColor()} strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokePct}
          transform="rotate(-90 100 100)"
          style={{ transition: 'stroke-dashoffset 0.3s ease, stroke 0.3s ease' }}
        />
        {/* Glow filter */}
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <circle
          cx="100" cy="100" r={radius} fill="none"
          stroke={getColor()} strokeWidth="4" opacity="0.4"
          strokeDasharray={circumference}
          strokeDashoffset={strokePct}
          transform="rotate(-90 100 100)"
          filter="url(#glow)"
          style={{ transition: 'stroke-dashoffset 0.3s ease' }}
        />
      </svg>
      <div className="gauge-score" style={{ color: getColor(), marginTop: '-120px' }}>
        {animatedScore}
      </div>
      <div className="gauge-label" style={{ marginTop: '4px' }}>/100</div>
      <div style={{ marginTop: '40px', fontSize: '0.95rem', fontWeight: 700, color: getColor() }}>
        {label}
      </div>
    </motion.div>
  );
}
