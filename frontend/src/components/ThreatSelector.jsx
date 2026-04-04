import React from 'react';

function severityClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

export default function ThreatSelector({ threats, selectedIndex, onSelect }) {
  if (!threats || threats.length === 0) return null;

  return (
    <div className="threat-selector">
      {threats.map((t, i) => {
        const score = t.risk_score?.score || 0;
        const severity = t.risk_score?.severity || 'Info';
        const isFP = t.false_positive_analysis?.is_false_positive;

        return (
          <button
            key={t.ip}
            className={`threat-tab ${i === selectedIndex ? 'active' : ''}`}
            onClick={() => onSelect(i)}
          >
            <span className="tab-ip">{t.ip}</span>
            <span className={`badge ${severityClass(severity)}`}>{severity}</span>
            <span className={`tab-score`} style={{ color: scoreColor(score) }}>
              {score}
            </span>
            {isFP && <span className="badge badge-fp">FP</span>}
          </button>
        );
      })}
    </div>
  );
}

function scoreColor(score) {
  if (score >= 8) return '#ef4444';
  if (score >= 6) return '#f97316';
  if (score >= 4) return '#eab308';
  return '#22c55e';
}
