import React from 'react';

function stageColor(stage) {
  const s = (stage || '').toLowerCase();
  if (s.includes('recon')) return '#3b82f6';
  if (s.includes('delivery')) return '#f97316';
  if (s.includes('exploit')) return '#ef4444';
  if (s.includes('install')) return '#dc2626';
  if (s.includes('command')) return '#a855f7';
  if (s.includes('action')) return '#ef4444';
  return '#6b7280';
}

function formatTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function mitreLabel(mitre) {
  if (!mitre) return null;
  const id = mitre.id || mitre.technique_id || '';
  const name = mitre.name || mitre.technique_name || '';
  if (!id) return null;
  return { id, name };
}

export default function AttackTimeline({ timeline, ip }) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">🕐 Attack Timeline</span></div>
        <div className="empty-state">
          <div className="empty-state-icon">🕐</div>
          <div className="empty-state-text">Run analysis to see attack reconstruction</div>
        </div>
      </div>
    );
  }

  const pivotCount = timeline.filter(e => e.is_pivot_point).length;

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          🕐 Attack Timeline
          <span className="panel-badge">{timeline.length}</span>
          {pivotCount > 0 && (
            <span className="badge badge-pivot" style={{ marginLeft: 4 }}>
              {pivotCount} pivot{pivotCount > 1 ? 's' : ''}
            </span>
          )}
        </span>
        {ip && (
          <span className="mono" style={{ fontSize: 12, color: '#8b9099' }}>{ip}</span>
        )}
      </div>
      <div className="attack-timeline">
        <div className="attack-timeline-list">
          {timeline.map((evt, i) => {
            const isPivot = evt.is_pivot_point;
            const kcStage = evt.kill_chain_stage;
            const dotColor = isPivot ? '#f59e0b' : stageColor(kcStage);
            const mitre = mitreLabel(evt.mitre_technique);
            const sourceBadge = evt.source === 'Firewall' ? 'badge-source-fw' : 'badge-source-auth';
            const sourceIcon = evt.source === 'Firewall' ? '🔥' : '🔑';

            return (
              <div key={i} className={`atk-event ${isPivot ? 'atk-event-pivot' : ''}`}>
                <span className="atk-event-time">{formatTime(evt.timestamp)}</span>

                <div className="atk-event-dot-col">
                  <span
                    className={`atk-event-dot ${isPivot ? 'atk-event-dot-pivot' : ''}`}
                    style={{ background: dotColor }}
                  />
                  {i < timeline.length - 1 && <div className="atk-event-line" />}
                </div>

                <div className="atk-event-content">
                  <div className="atk-event-badges">
                    {mitre && (
                      <span className="tooltip-wrapper">
                        <span className="badge badge-info" style={{ fontSize: 9 }}>{mitre.id}</span>
                        <span className="tooltip-text">{mitre.name}</span>
                      </span>
                    )}
                    {kcStage && (
                      <span className="badge badge-info" style={{ fontSize: 9, borderColor: `${dotColor}44`, color: dotColor }}>
                        {kcStage}
                      </span>
                    )}
                    <span className={`badge ${sourceBadge}`} style={{ fontSize: 9 }}>
                      {sourceIcon} {evt.source}
                    </span>
                    {isPivot && (
                      <span className="badge badge-pivot" style={{ fontSize: 9, fontWeight: 700 }}>
                        ⚡ PIVOT
                      </span>
                    )}
                  </div>
                  <span className="atk-event-significance">{evt.significance}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
