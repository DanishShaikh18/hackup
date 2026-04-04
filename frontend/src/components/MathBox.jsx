import React from 'react';

function severityColor(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return '#ef4444';
  if (s === 'high') return '#f97316';
  if (s === 'medium') return '#eab308';
  if (s === 'low') return '#22c55e';
  return '#6b7280';
}

function severityClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

function alertCategoryIcon(cat) {
  const c = (cat || '').toLowerCase();
  if (c.includes('brute') || c.includes('credential')) return '🔑';
  if (c.includes('firewall') || c.includes('network')) return '🔥';
  if (c.includes('exfil')) return '📤';
  if (c.includes('scan') || c.includes('recon')) return '🔍';
  if (c.includes('compromise')) return '💀';
  return '⚠️';
}

export default function MathBox({ threat }) {
  if (!threat) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">📊 Risk Analysis</span></div>
        <div className="empty-state">
          <div className="empty-state-icon">📊</div>
          <div className="empty-state-text">Select a threat to view risk analysis</div>
        </div>
      </div>
    );
  }

  const risk = threat.risk_score || {};
  const score = risk.score || 0;
  const severity = risk.severity || 'Info';
  const color = severityColor(severity);
  const fp = threat.false_positive_analysis || {};
  const alerts = threat.triggered_alerts || [];

  // SVG gauge
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(score / 10, 1);
  const dashOffset = circumference * (1 - pct);

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          📊 Risk Analysis
          <span className="mono" style={{ fontSize: 12, color: '#8b9099' }}>
            {threat.ip}
          </span>
        </span>
      </div>
      <div className="panel-body">
        <div className="mathbox">
          {/* Gauge */}
          <div className="mathbox-left">
            <div className="score-gauge">
              <svg viewBox="0 0 96 96">
                <circle className="score-gauge-bg" cx="48" cy="48" r={radius} />
                <circle
                  className="score-gauge-fill"
                  cx="48" cy="48" r={radius}
                  stroke={color}
                  strokeDasharray={circumference}
                  strokeDashoffset={dashOffset}
                />
              </svg>
              <div className="score-gauge-text">
                <span className="score-gauge-value" style={{ color }}>{score}</span>
                <span className="score-gauge-label" style={{ color }}>{severity}</span>
              </div>
            </div>

            {/* FP status */}
            <div className={`fp-status ${fp.is_false_positive ? 'fp-status-safe' : 'fp-status-threat'}`}>
              <span className="fp-status-icon">{fp.is_false_positive ? '✓' : '✕'}</span>
              <span>{fp.is_false_positive ? 'Likely False Positive' : 'Confirmed Threat'}</span>
            </div>
          </div>

          {/* Formulas */}
          <div className="mathbox-right">
            <div className="formula-line">
              <span className="formula-label">Formula</span>
              {risk.formula_display}
            </div>
            <div className="formula-line">
              <span className="formula-label">Normalized</span>
              {risk.formula_normalized}
            </div>
            <div className="formula-line">
              <span className="formula-label">Confidence</span>
              {threat.evidence_summary?.confidence ?? '—'} ({threat.evidence_summary?.total_evidence_points ?? 0} evidence points)
            </div>
            <div className="formula-line">
              <span className="formula-label">FP Analysis ({fp.confidence || '—'})</span>
              {fp.reason || '—'}
            </div>
          </div>
        </div>

        {/* Triggered Alerts */}
        {alerts.length > 0 && (
          <div className="alerts-list">
            {alerts.map((a, i) => (
              <div key={i} className="alert-row">
                <span>{alertCategoryIcon(a.alert_category)}</span>
                <span className="alert-row-category">{a.alert_category || a.threshold_key}</span>
                <span className={`badge ${severityClass(a.severity)}`}>{a.severity}</span>
                <span className="alert-row-factor mono" style={{ color: severityColor(a.severity) }}>
                  {a.exceeded_by_factor ? `${a.exceeded_by_factor.toFixed(1)}×` : '—'}
                </span>
                <span className="alert-row-action">{a.recommended_action}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
