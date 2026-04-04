import React, { useState } from 'react';

const API = 'http://localhost:8000';

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

const AGENT_ICONS = {
  network_analyst: '🌐',
  identity_analyst: '🔑',
  threat_intel: '🎯',
};

export default function MathBox({ threat, caseId }) {
  const [agentReport, setAgentReport] = useState(null);
  const [agentLoading, setAgentLoading] = useState(false);
  const [agentOpen, setAgentOpen] = useState(false);

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

  const runMultiAgent = async () => {
    if (!caseId || !threat.ip) return;
    setAgentLoading(true);
    setAgentOpen(true);
    try {
      const res = await fetch(`${API}/multi-agent/${caseId}/${threat.ip}`, { method: 'POST' });
      const data = await res.json();
      setAgentReport(data.multi_agent_report || null);
    } catch {
      setAgentReport(null);
    } finally {
      setAgentLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          📊 Risk Analysis
          <span className="mono" style={{ fontSize: 12, color: '#8b9099' }}>
            {threat.ip}
          </span>
        </span>
        {caseId && (
          <button
            className="btn"
            style={{ fontSize: 11, padding: '4px 10px' }}
            onClick={runMultiAgent}
            disabled={agentLoading}
          >
            {agentLoading ? '⟳ Agents thinking...' : '🤖 Multi-Agent Analysis'}
          </button>
        )}
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

        {/* Multi-Agent Analysis Panel */}
        {agentOpen && (
          <div style={{
            marginTop: 12,
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-card)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '8px 12px',
              background: 'var(--bg-elevated)',
              borderBottom: '1px solid var(--border-subtle)',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <span>🤖 Multi-Agent SOC Report</span>
              <button
                onClick={() => setAgentOpen(false)}
                style={{
                  fontSize: 14,
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  background: 'none',
                  border: 'none',
                  padding: '0 4px',
                }}
              >✕</button>
            </div>

            {agentLoading ? (
              <div style={{ padding: 16 }}>
                <div className="skeleton skeleton-line" />
                <div className="skeleton skeleton-line" />
                <div className="skeleton skeleton-line" style={{ width: '60%' }} />
              </div>
            ) : agentReport ? (
              <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(agentReport.agents || {}).map(([key, agent]) => (
                  <div key={key} style={{
                    padding: '8px 10px',
                    background: 'var(--bg-base)',
                    borderRadius: 'var(--radius-badge)',
                    border: '1px solid var(--border-subtle)',
                  }}>
                    <div style={{
                      fontSize: 10,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      color: 'var(--accent-blue)',
                      marginBottom: 4,
                      letterSpacing: '0.04em',
                    }}>
                      {AGENT_ICONS[key] || '🤖'} {agent.name}
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {agent.finding}
                    </div>
                  </div>
                ))}

                {/* Coordinator */}
                <div style={{
                  padding: '10px 12px',
                  background: 'rgba(59, 130, 246, 0.06)',
                  borderRadius: 'var(--radius-badge)',
                  border: '1px solid rgba(59, 130, 246, 0.15)',
                }}>
                  <div style={{
                    fontSize: 10,
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    color: 'var(--pivot-gold)',
                    marginBottom: 4,
                    letterSpacing: '0.04em',
                  }}>
                    ⚡ Coordinator Synthesis
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, fontWeight: 500 }}>
                    {agentReport.coordinator_synthesis}
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: 16, fontSize: 12, color: 'var(--text-muted)', textAlign: 'center' }}>
                Multi-agent analysis unavailable. Check backend connection.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
