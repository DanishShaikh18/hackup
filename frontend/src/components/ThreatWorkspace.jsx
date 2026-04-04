import React, { useState, useEffect, useRef, useCallback } from 'react'; // FIXED: added useRef, useCallback for position:fixed tooltips
import { sevColor, sevClass, formatTimeShort } from '../App';

const API = 'http://localhost:8000';

const KILL_CHAIN = [
  'Reconnaissance', 'Weaponization', 'Delivery',
  'Exploitation', 'Installation', 'Command & Control', 'Actions on Objectives',
];

const LOADING_STEPS = [
  'Ingesting logs',
  'Correlating IPs',
  'Scoring threats',
  'Mapping MITRE ATT&CK',
  'Building attack timeline',
  'Generating AI summary',
];

// ── SVG Arc Gauge Helpers ─────────────────────────
function polarToCart(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function arcPath(cx, cy, r, startAngle, endAngle) {
  const s = polarToCart(cx, cy, r, startAngle);
  const e = polarToCart(cx, cy, r, endAngle);
  let sweep = endAngle - startAngle;
  if (sweep < 0) sweep += 360;
  const largeArc = sweep > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
}

function RiskGauge({ score, severity }) {
  const cx = 70, cy = 65, r = 52;
  const startA = 210, totalArc = 300;
  const pct = Math.min((score || 0) / 10, 1);
  let fillEnd = startA + pct * totalArc;
  if (fillEnd >= 360) fillEnd -= 360;

  const bgD = arcPath(cx, cy, r, startA, (startA + totalArc) % 360);
  const fillD = pct > 0.01 ? arcPath(cx, cy, r, startA, fillEnd) : '';
  const color = sevColor(severity);

  return (
    <svg className="risk-gauge-svg" viewBox="0 0 140 120">
      <path d={bgD} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" strokeLinecap="round" />
      {fillD && (
        <path d={fillD} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          style={{ transition: 'all 0.6s ease', filter: `drop-shadow(0 0 6px ${color})` }} />
      )}
      <text className="risk-gauge-score" x={cx} y={cy - 2} textAnchor="middle" dominantBaseline="central">
        {score}
      </text>
      <text className="risk-gauge-label" x={cx} y={cy + 18} textAnchor="middle">
        {severity}
      </text>
    </svg>
  );
}

// ── Confidence Meter ──────────────────────────────
function ConfidenceMeter({ value }) {
  const pct = Math.round((value || 0) * 100);
  const filled = Math.round((value || 0) * 10);
  return (
    <div className="conf-meter">
      <div className="conf-bar">
        {Array.from({ length: 10 }, (_, i) => {
          let cls = '';
          if (i < filled) {
            if (filled <= 3) cls = 'conf-seg-filled-low';
            else if (filled <= 6) cls = 'conf-seg-filled-mid';
            else cls = 'conf-seg-filled-high';
          }
          return <div key={i} className={`conf-seg ${cls}`} />;
        })}
      </div>
      <span className="conf-label">{pct}%</span>
    </div>
  );
}

// ── Loading Sequence ──────────────────────────────
function LoadingSequence() {
  const [step, setStep] = useState(0);
  useEffect(() => {
    const iv = setInterval(() => {
      setStep(p => (p < LOADING_STEPS.length - 1 ? p + 1 : p));
    }, 500);
    return () => clearInterval(iv);
  }, []);

  return (
    <div className="loading-seq">
      {LOADING_STEPS.map((label, i) => {
        const done = i < step;
        const active = i === step;
        return (
          <div key={i} className={`loading-step ${done ? 'loading-step-done' : active ? 'loading-step-active' : ''}`}>
            <div className={`loading-check ${done ? 'loading-check-done' : active ? 'loading-check-active' : ''}`}>
              {done ? '✓' : ''}
            </div>
            {label}...
          </div>
        );
      })}
    </div>
  );
}

// ── MAIN COMPONENT ─────────────────────────────────
export default function ThreatWorkspace({
  threats, activeThreat, selectedIdx, onSelectThreat,
  analyzing, analyzeType, caseId, timezone,
}) {
  const [compareMode, setCompareMode] = useState(false);
  const [compareIdx, setCompareIdx] = useState(1);
  const [hoveredEvent, setHoveredEvent] = useState(null);
  const [popoverCoords, setPopoverCoords] = useState(null); // FIXED: track viewport coords for position:fixed tooltip
  const nodeRefs = useRef({}); // FIXED: refs for each timeline node
  const [maReport, setMaReport] = useState(null);
  const [maLoading, setMaLoading] = useState(false);
  const [maOpen, setMaOpen] = useState(false);

  // Reset multi-agent when threat changes
  useEffect(() => { setMaReport(null); setMaOpen(false); }, [activeThreat?.ip]);

  const runMultiAgent = async () => {
    if (!caseId || !activeThreat?.ip) return;
    setMaLoading(true); setMaOpen(true);
    try {
      const r = await fetch(`${API}/multi-agent/${caseId}/${activeThreat.ip}`, { method: 'POST' });
      const d = await r.json();
      setMaReport(d.multi_agent_report || null);
    } catch { setMaReport(null); }
    finally { setMaLoading(false); }
  };

  // ── Render ───────────────────
  if (analyzing) {
    return <main className="cc-center"><LoadingSequence /></main>;
  }

  if (!threats.length) {
    return (
      <main className="cc-center">
        <div className="empty-state" style={{ marginTop: 60 }}>
          <div className="empty-icon">🔍</div>
          <div className="empty-text">
            Press <kbd className="shortcut-key" style={{ fontSize: 11 }}>A</kbd> to analyze logs or
            <kbd className="shortcut-key" style={{ fontSize: 11, marginLeft: 4 }}>R</kbd> for raw syslog
          </div>
        </div>
      </main>
    );
  }

  if (compareMode && threats.length >= 2) {
    const t1 = threats[selectedIdx];
    const t2 = threats[compareIdx % threats.length];
    return (
      <main className="cc-center">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className="panel-title">Comparison Mode</span>
          <button className="btn-compare" onClick={() => setCompareMode(false)}>✕ Exit</button>
        </div>
        <div className="compare-grid">
          {[t1, t2].map((t, ci) => {
            const risk = t.risk_score || {};
            const activeKC = (t.kill_chain || []).filter(k => k.active).map(k => k.stage);
            return (
              <div key={ci} className="compare-col">
                <div className="threat-header" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 8 }}>
                  <span className="th-ip" style={{ fontSize: 20 }}>{t.ip}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span className={`badge ${sevClass(risk.severity)}`}>{risk.severity}</span>
                    <ConfidenceMeter value={t.evidence_summary?.confidence} />
                  </div>
                  <RiskGauge score={risk.score} severity={risk.severity} />
                  <div className="formula-block" style={{ width: '100%' }}>
                    <span className="formula-label">Formula</span>
                    {risk.formula_display}
                  </div>
                  <div style={{ width: '100%' }}>
                    <span className="formula-label" style={{ display: 'block', marginBottom: 6 }}>Kill Chain</span>
                    <div className="kc-bar">
                      {KILL_CHAIN.map((stage, i) => {
                        const active = activeKC.includes(stage);
                        return (
                          <div key={i} className="kc-stage">
                            {i > 0 && <div className={`kc-connector ${active ? 'kc-connector-active' : ''}`} />}
                            <div className={`kc-node ${active ? 'kc-node-active' : ''}`} />
                            <span className={`kc-label ${active ? 'kc-label-active' : ''}`}>{stage.split(' ')[0]}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                    <span>Alerts: <strong style={{ color: 'var(--text-primary)' }}>{t.triggered_alerts?.length || 0}</strong></span>
                    <span>Evidence: <strong style={{ color: 'var(--text-primary)' }}>{t.evidence_summary?.total_evidence_points || 0}</strong> pts</span>
                    <span>FP: <strong style={{ color: t.false_positive_analysis?.is_false_positive ? 'var(--color-low)' : 'var(--color-critical)' }}>
                      {t.false_positive_analysis?.is_false_positive ? 'Yes' : 'No'}
                    </strong></span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </main>
    );
  }

  // Normal mode
  const risk = activeThreat?.risk_score || {};
  const fp = activeThreat?.false_positive_analysis || {};
  const activeKC = (activeThreat?.kill_chain || []).filter(k => k.active).map(k => k.stage);
  const timeline = activeThreat?.attack_timeline || [];
  const mitreTechniques = activeThreat?.mitre_techniques || [];

  // Swimlane time positions
  let timePositions = [];
  if (timeline.length > 1) {
    const times = timeline.map(e => new Date(e.timestamp).getTime());
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    const range = maxT - minT || 1;
    timePositions = times.map(t => ((t - minT) / range) * 100);
  } else if (timeline.length === 1) {
    timePositions = [50];
  }

  return (
    <main className="cc-center">
      {/* Threat Pills */}
      <div className="threat-pills">
        {threats.map((t, i) => {
          const isFP = t.false_positive_analysis?.is_false_positive;
          return (
            <button
              key={i}
              className={`threat-pill ${i === selectedIdx ? 'threat-pill-active' : ''}`}
              onClick={() => onSelectThreat(i)}
            >
              <span className="pill-dot" style={{ background: sevColor(t.risk_score?.severity) }} />
              <span className="pill-ip">{t.ip}</span>
              <span className="pill-score" style={{ color: sevColor(t.risk_score?.severity) }}>
                {t.risk_score?.score}
              </span>
              {isFP && <span className="pill-fp-tag">FP</span>}
            </button>
          );
        })}
        {threats.length >= 2 && (
          <button className="btn-compare" onClick={() => { setCompareMode(true); setCompareIdx(selectedIdx === 0 ? 1 : 0); }}>
            ⇔ Compare
          </button>
        )}
      </div>

      {/* Threat Header */}
      <div className="threat-header">
        <span className="th-ip">{activeThreat.ip}</span>
        <div className="th-meta">
          <span className={`badge ${sevClass(risk.severity)}`}>{risk.severity}</span>
          <ConfidenceMeter value={activeThreat.evidence_summary?.confidence} />
          <div className="fp-verdict">
            <span
              className="fp-icon"
              style={{
                background: fp.is_false_positive ? 'var(--bg-low)' : 'var(--bg-critical)',
                color: fp.is_false_positive ? 'var(--color-low)' : 'var(--color-critical)',
              }}
            >
              {fp.is_false_positive ? '✓' : '✕'}
            </span>
            <span style={{ color: fp.is_false_positive ? 'var(--color-low)' : 'var(--color-critical)' }}>
              {fp.is_false_positive ? 'False Positive' : 'Confirmed Threat'}
            </span>
          </div>
        </div>
        <div className="th-actions">
          <button className="btn-action" onClick={runMultiAgent} disabled={maLoading || !caseId}>
            {maLoading ? '⟳' : '🤖'} Multi-Agent
          </button>
        </div>
      </div>

      {/* Risk Score + Formula + Kill Chain */}
      <div className="risk-section">
        <div className="risk-gauge-wrap">
          <RiskGauge score={risk.score} severity={risk.severity} />
        </div>
        <div className="risk-details">
          <div className="formula-block">
            <span className="formula-label">Risk Score Formula</span>
            {risk.formula_display}
          </div>
          <div className="formula-block">
            <span className="formula-label">Normalized</span>
            {risk.formula_normalized}
          </div>
          <div className="formula-block">
            <span className="formula-label">FP Analysis — {fp.confidence || '—'}</span>
            {fp.reason || '—'}
          </div>
          <div>
            <span className="formula-label" style={{ display: 'block', marginBottom: 6 }}>Kill Chain Progression</span>
            <div className="kc-bar">
              {KILL_CHAIN.map((stage, i) => {
                const active = activeKC.includes(stage);
                return (
                  <div key={i} className="kc-stage">
                    {i > 0 && <div className={`kc-connector ${active ? 'kc-connector-active' : ''}`} />}
                    <div className={`kc-node ${active ? 'kc-node-active' : ''}`} />
                    <span className={`kc-label ${active ? 'kc-label-active' : ''}`}>
                      {stage.length > 12 ? stage.split(' ')[0] : stage}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Multi-Agent Panel */}
      {maOpen && (
        <div className="ma-panel">
          <div className="panel-title-bar">
            <span className="panel-title">🤖 Multi-Agent SOC Report</span>
            <button className="btn-action" style={{ padding: '2px 8px', fontSize: 13 }} onClick={() => setMaOpen(false)}>✕</button>
          </div>
          {maLoading ? (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>Agents analyzing threat...</div>
          ) : maReport ? (
            <>
              <div className="ma-agents">
                {Object.entries(maReport.agents || {}).map(([key, agent]) => (
                  <div key={key} className="ma-agent-card">
                    <div className="ma-agent-name">{agent.name}</div>
                    <div className="ma-agent-finding">{agent.finding}</div>
                  </div>
                ))}
              </div>
              <div className="ma-coordinator">
                <div className="ma-coord-label">⚡ Coordinator Synthesis</div>
                <div className="ma-coord-text">{maReport.coordinator_synthesis}</div>
              </div>
            </>
          ) : (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>Analysis unavailable.</div>
          )}
        </div>
      )}

      {/* Swimlane Attack Timeline */}
      {timeline.length > 0 && (
        <div className="swimlane-panel" style={{ height: 'auto', minHeight: 280, overflow: 'visible' }}>{/* FIXED: BUG 1 — auto height, visible overflow */}
          <div className="panel-title-bar">
            <span className="panel-title">Attack Timeline</span>
            <span className="panel-badge-count">{timeline.length} events</span>
          </div>
          <div className="swimlane" style={{ overflowX: 'auto', overflowY: 'visible', paddingBottom: 16 }}>{/* FIXED: BUG 1 — visible vertical overflow */}
            <div className="swimlane-axis" style={{
              position: 'relative',
              display: 'flex',
              flexDirection: 'row',
              alignItems: 'center',
              minWidth: Math.max(timeline.length * 60, 400),
              paddingTop: 40,
              paddingBottom: 40,
              overflowY: 'visible',
            }}>{/* FIXED: BUG 1 — flex row, min-width, vertical padding for breathing room */}
              {timeline.map((ev, i) => {
                const left = `${timePositions[i] ?? 50}%`;
                const isPivot = ev.is_pivot_point;
                const stageColor = (() => {
                  const s = (ev.kill_chain_stage || '').toLowerCase();
                  if (s.includes('recon')) return 'var(--color-info)';
                  if (s.includes('delivery')) return 'var(--color-high)';
                  if (s.includes('exploit')) return 'var(--color-critical)';
                  if (s.includes('action')) return 'var(--color-pivot)';
                  return 'var(--color-medium)';
                })();

                return (
                  <div
                    key={i}
                    ref={el => { nodeRefs.current[i] = el; }}
                    className={`swimlane-node ${isPivot ? 'swimlane-diamond' : ''}`}
                    style={{
                      left,
                      borderColor: stageColor,
                      marginLeft: -11,
                    }}
                    onMouseEnter={() => {
                      // FIXED: BUG 2 — compute viewport coords via getBoundingClientRect for position:fixed
                      setHoveredEvent(i);
                      const el = nodeRefs.current[i];
                      if (el) {
                        const rect = el.getBoundingClientRect();
                        setPopoverCoords({
                          top: rect.top - 8, // 8px above the node
                          left: rect.left + rect.width / 2,
                        });
                      }
                    }}
                    onMouseLeave={() => { setHoveredEvent(null); setPopoverCoords(null); }}
                  >
                    <span className="swimlane-time-label">
                      {formatTimeShort(ev.timestamp, timezone)}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
          {/* FIXED: BUG 2 — popover rendered OUTSIDE the overflow container, with position:fixed */}
          {hoveredEvent !== null && popoverCoords && timeline[hoveredEvent] && (
            <div
              className="event-popover"
              style={{
                top: popoverCoords.top,
                left: popoverCoords.left,
                transform: 'translate(-50%, -100%)',
              }}
            >
              <div className="popover-row">
                <span>{timeline[hoveredEvent].source}</span>
                <strong>{timeline[hoveredEvent].event_type}</strong>
              </div>
              <div className="popover-row">
                <span className="mono" style={{ fontSize: 10 }}>{formatTimeShort(timeline[hoveredEvent].timestamp, timezone)}</span>
                {timeline[hoveredEvent].mitre_technique && (
                  <span className="badge badge-medium" style={{ fontSize: 9 }}>
                    {timeline[hoveredEvent].mitre_technique.id || timeline[hoveredEvent].mitre_technique.technique_id}
                  </span>
                )}
              </div>
              {timeline[hoveredEvent].is_pivot_point && (
                <div style={{ fontSize: 9, color: 'var(--color-pivot)', fontWeight: 600, marginTop: 3 }}>
                  ⚡ PIVOT POINT
                </div>
              )}
              {timeline[hoveredEvent].significance && <div className="popover-sig">{timeline[hoveredEvent].significance}</div>}
            </div>
          )}
        </div>
      )}

      {/* MITRE Technique Grid */}
      {mitreTechniques.length > 0 && (
        <div className="mitre-panel">
          <div className="panel-title-bar">
            <span className="panel-title">MITRE ATT&CK Mapping</span>
            <span className="panel-badge-count">{mitreTechniques.length}</span>
          </div>
          <div className="mitre-grid">
            {mitreTechniques.map((tech, i) => (
              <div key={i} className="mitre-cell mitre-cell-active">
                <span className="mitre-cell-id">{tech.technique_id}</span>
                {tech.technique_name}
                <span style={{ display: 'block', fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>
                  {tech.tactic} → {tech.kill_chain_stage}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </main>
  );
}
