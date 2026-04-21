import React from 'react';

export default function ReportExport({ onExport, hasResults }) {
  if (!hasResults) return null;

  return (
    <button className="btn btn-secondary btn-sm" onClick={onExport}>
      📄 Export PDF
    </button>
  );
}
