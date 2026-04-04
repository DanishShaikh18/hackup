import React, { useState, useRef, useEffect } from 'react';
// FIXED: removed ReactDOM import — position:fixed doesn't need a portal

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

// FIXED: BUG 2 — position:fixed tooltip. No portal needed, fixed escapes all overflow clipping.
function PortalTooltip({ anchorRef, visible, id, name }) {
  const [coords, setCoords] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (visible && anchorRef.current) {
      const rect = anchorRef.current.getBoundingClientRect();
      // FIXED: position:fixed uses viewport coords directly — no scrollY/scrollX needed
      setCoords({
        top: rect.bottom + 8,
        left: rect.left + rect.width / 2,
      });
    }
  }, [visible, anchorRef]);

  if (!visible) return null;

  // FIXED: Render inline with position:fixed — escapes every stacking context and overflow:hidden
  return (
    <div
      style={{
        position: 'fixed', // FIXED: was 'absolute' — fixed escapes ALL parent overflow
        top: coords.top,
        left: coords.left,
        transform: 'translateX(-50%)',
        zIndex: 99999,
        pointerEvents: 'none',
        backgroundColor: '#0d1117',
        border: '1px solid #2d3748',
        borderRadius: 7,
        padding: '7px 12px',
        boxShadow: '0 6px 20px rgba(0,0,0,0.7)',
        minWidth: 180,
        maxWidth: 280,
        whiteSpace: 'normal',
        lineHeight: 1.5,
      }}
    >
      <div style={{
        position: 'absolute',
        top: -6,
        left: '50%',
        transform: 'translateX(-50%)',
        width: 0,
        height: 0,
        borderLeft: '6px solid transparent',
        borderRight: '6px solid transparent',
        borderBottom: '6px solid #2d3748',
      }} />
      <div style={{
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 11,
        color: '#93c5fd',
        fontWeight: 700,
        marginBottom: 3,
      }}>
        {id}
      </div>
      <div style={{
        fontFamily: 'Inter, sans-serif',
        fontSize: 11,
        color: '#cbd5e1',
      }}>
        {name}
      </div>
    </div>
  );
}

function MitreBadge({ id, name }) {
  const [visible, setVisible] = useState(false);
  const ref = useRef(null);

  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
      <span
        ref={ref}
        className="badge badge-info"
        style={{ fontSize: 9, cursor: 'default' }}
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
      >
        {id}
      </span>
      <PortalTooltip anchorRef={ref} visible={visible} id={id} name={name} />
    </span>
  );
}

export default function AttackTimeline({ timeline, ip }) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">🕐 Attack Timeline</span>
        </div>
        <div className="empty-state">
          <div className="empty-state-icon">🕐</div>
          <div className="empty-state-text">Run analysis to see attack reconstruction</div>
        </div>
      </div>
    );
  }

  const pivotCount = timeline.filter(e => e.is_pivot_point).length;

  return (
    <div className="panel" style={{ minHeight: 300 }}>
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

      <div style={{ overflowX: 'auto', overflowY: 'visible', paddingBottom: 8 }}>
        <div
          className="attack-timeline-list"
          style={{
            minWidth: Math.max(timeline.length * 120, 600),
            overflowY: 'visible',
          }}
        >
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
                  <div className="atk-event-badges" style={{ overflow: 'visible' }}>
                    {mitre && <MitreBadge id={mitre.id} name={mitre.name} />}
                    {kcStage && (
                      <span
                        className="badge badge-info"
                        style={{ fontSize: 9, borderColor: `${dotColor}44`, color: dotColor }}
                      >
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