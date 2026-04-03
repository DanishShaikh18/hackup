export default function MathBox({ threat }) {
  if (!threat) {
    return (
      <div className="panel">
        <div className="panel__header">
          <span className="panel__header-icon">🧮</span>
          Risk Score Breakdown
        </div>
        <div className="empty-state">
          <div className="empty-state__icon">📊</div>
          <div className="empty-state__text">
            No risk score calculated yet.
          </div>
        </div>
      </div>
    );
  }

  const risk = threat.risk_score;
  const score = risk.score;
  const severity = risk.severity.toLowerCase();
  const breakdown = risk.breakdown;
  const fp = threat.false_positive_analysis;
  const evidence = threat.evidence_summary;

  return (
    <div className="panel">
      <div className="panel__header">
        <span className="panel__header-icon">🧮</span>
        Risk Score Breakdown
        <span style={{ marginLeft: 'auto', fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          IP: {threat.ip}
        </span>
      </div>
      <div className="panel__body">
        <div className="math-box">
          <div className={`score-gauge score-gauge--${severity}`}>
            {score}
            <span className="score-gauge__label">{risk.severity}</span>
          </div>
          <div className="math-formula">
            <span className="math-formula__line">
              <span className="math-formula__label">Formula:</span>
              <span className="math-formula__highlight">
                (KillChainWeight × Confidence) + AssetValue
              </span>
            </span>
            <span className="math-formula__line">
              <span className="math-formula__label">Calculation:</span>
              <span className="math-formula__value">{risk.formula_display}</span>
            </span>
            <span className="math-formula__line">
              <span className="math-formula__label">Normalized:</span>
              <span className="math-formula__value">{risk.formula_normalized}</span>
            </span>
            <span className="math-formula__line" style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
              <span className="math-formula__label">KC Weight:</span>
              <span className="math-formula__value">{breakdown.kill_chain_weight}</span>
            </span>
            <span className="math-formula__line">
              <span className="math-formula__label">Confidence:</span>
              <span className="math-formula__value">{(breakdown.confidence * 100).toFixed(0)}% ({evidence.total_evidence_points} evidence points)</span>
            </span>
            <span className="math-formula__line">
              <span className="math-formula__label">Asset Value:</span>
              <span className="math-formula__value">{breakdown.asset_value}</span>
            </span>
            <span className="math-formula__line" style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
              <span className="math-formula__label">FP Check:</span>
              <span style={{ color: fp.is_false_positive ? 'var(--severity-low)' : 'var(--severity-critical)', fontSize: '0.75rem' }}>
                {fp.is_false_positive ? '✅ Likely False Positive' : '❌ NOT a False Positive'}
              </span>
            </span>
            <span className="math-formula__line">
              <span className="math-formula__label">Reason:</span>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>{fp.reason}</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
