import React, { useState } from 'react';

const API = 'http://localhost:8000';

function scoreColor(score) {
  if (score >= 8) return '#ef4444';
  if (score >= 6) return '#f97316';
  if (score >= 4) return '#eab308';
  return '#22c55e';
}

function severityClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

export default function SOARButton({ threats }) {
  const [blockedMap, setBlockedMap] = useState({});

  const actionableThreats = (threats || []).filter(
    t => !t.false_positive_analysis?.is_false_positive
  );

  if (actionableThreats.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">🚀 SOAR Actions</span></div>
        <div className="empty-state">
          <div className="empty-state-icon">🚀</div>
          <div className="empty-state-text">No actionable threats — all clear or all false positives</div>
        </div>
      </div>
    );
  }

  const handleBlock = async (ip) => {
    try {
      const res = await fetch(`${API}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setBlockedMap(prev => ({
          ...prev,
          [ip]: data.details?.rule_added || 'BLOCKED',
        }));
      }
    } catch (err) {
      console.error('Block failed:', err);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          🚀 SOAR Actions
          <span className="panel-badge">{actionableThreats.length}</span>
        </span>
      </div>
      <div className="panel-body">
        <div className="soar-actions">
          {actionableThreats.map(t => {
            const score = t.risk_score?.score || 0;
            const severity = t.risk_score?.severity || 'Info';
            const isBlocked = !!blockedMap[t.ip];
            const ruleId = blockedMap[t.ip];

            return (
              <div key={t.ip} className="soar-row">
                <span className="soar-ip">{t.ip}</span>
                <span className={`badge ${severityClass(severity)}`}>{severity}</span>
                <span className="soar-score" style={{ color: scoreColor(score) }}>{score}/10</span>
                {isBlocked && <span className="soar-rule">Rule: {ruleId}</span>}
                <button
                  className={`soar-btn ${isBlocked ? 'soar-btn-blocked' : 'soar-btn-block'}`}
                  onClick={() => !isBlocked && handleBlock(t.ip)}
                  disabled={isBlocked}
                >
                  {isBlocked ? '✓ Blocked' : 'Block IP'}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
