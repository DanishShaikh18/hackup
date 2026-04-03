export default function KillChainTimeline({ killChain }) {
  if (!killChain || killChain.length === 0) {
    return (
      <div className="panel">
        <div className="panel__header">
          <span className="panel__header-icon">⚔️</span>
          Cyber Kill Chain
        </div>
        <div className="empty-state">
          <div className="empty-state__icon">🔗</div>
          <div className="empty-state__text">
            Kill Chain timeline will appear after analysis.
          </div>
        </div>
      </div>
    );
  }

  const stageIcons = {
    'Reconnaissance': '🔍',
    'Weaponization': '🔧',
    'Delivery': '📧',
    'Exploitation': '💥',
    'Installation': '📦',
    'Command & Control': '📡',
    'Actions on Objectives': '🎯',
  };

  return (
    <div className="panel">
      <div className="panel__header">
        <span className="panel__header-icon">⚔️</span>
        Cyber Kill Chain
      </div>
      <div className="panel__body">
        <div className="kill-chain">
          {killChain.map((stage, i) => (
            <div
              key={i}
              className={`kill-chain__stage kill-chain__stage--${stage.active ? 'active' : 'inactive'}`}
            >
              <div className="kill-chain__dot">
                {stageIcons[stage.stage] || (i + 1)}
              </div>
              <div className="kill-chain__name">{stage.stage}</div>
              {stage.active && stage.techniques.map((tech, ti) => (
                <div key={ti} className="kill-chain__technique">
                  {tech.technique_id}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
