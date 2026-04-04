import React from 'react';

function stageColor(stage, active) {
  if (!active) return '#555b66';
  const s = (stage || '').toLowerCase();
  if (s.includes('recon')) return '#3b82f6';
  if (s.includes('weapon')) return '#6366f1';
  if (s.includes('delivery')) return '#f97316';
  if (s.includes('exploit')) return '#ef4444';
  if (s.includes('install')) return '#dc2626';
  if (s.includes('command')) return '#a855f7';
  if (s.includes('action')) return '#ef4444';
  return '#6b7280';
}

export default function KillChainTimeline({ killChain }) {
  if (!killChain || killChain.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">⛓️ Kill Chain</span></div>
        <div className="empty-state">
          <div className="empty-state-icon">⛓️</div>
          <div className="empty-state-text">Run analysis to view kill chain progression</div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          ⛓️ Kill Chain
          <span className="panel-badge">
            {killChain.filter(s => s.active).length}/{killChain.length}
          </span>
        </span>
      </div>
      <div className="panel-body">
        <div className="killchain">
          {killChain.map((stage, i) => {
            const color = stageColor(stage.stage, stage.active);
            return (
              <React.Fragment key={stage.stage}>
                {i > 0 && (
                  <div className="killchain-connector">
                    <span className="killchain-arrow">→</span>
                  </div>
                )}
                <div className="killchain-stage">
                  <div
                    className={`killchain-dot ${stage.active ? 'killchain-dot-active' : 'killchain-dot-inactive'}`}
                    style={stage.active ? { color, borderColor: color, background: `${color}18` } : {}}
                  >
                    {stage.weight}
                  </div>
                  <span className={`killchain-label ${!stage.active ? 'killchain-label-inactive' : ''}`}>
                    {stage.stage}
                  </span>
                  {stage.active && stage.techniques && stage.techniques.length > 0 && (
                    <div className="killchain-techniques">
                      {stage.techniques.map((t, j) => (
                        <span key={j} className="tooltip-wrapper">
                          <span className="killchain-technique-id">{t.technique_id}</span>
                          <span className="tooltip-text">{t.technique_name}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
}
