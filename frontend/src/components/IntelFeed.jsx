import React, { useState } from 'react';
import { formatTS, sevColor, sevClass } from '../App';

const SHORTCUTS = [
  { key: 'A', label: 'Run analysis' },
  { key: 'R', label: 'Analyze raw logs' },
  { key: 'Tab', label: 'Cycle threats' },
  { key: 'C', label: 'Toggle chat' },
  { key: '?', label: 'Shortcuts' },
  { key: 'Esc', label: 'Close panels' },
];

export default function IntelFeed({ cases, activeCaseId, timezone, onLoadCase }) {
  const [keysOpen, setKeysOpen] = useState(true);

  return (
    <aside className="cc-left">
      <div className="intel-header">
        Intelligence Feed
        {cases.length > 0 && (
          <span style={{ float: 'right', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            {cases.length}
          </span>
        )}
      </div>

      <div className="intel-cases">
        {cases.length === 0 ? (
          <div className="empty-state" style={{ padding: '30px 10px' }}>
            <div className="empty-icon">📡</div>
            <div className="empty-text">No investigations yet. Run an analysis to begin.</div>
          </div>
        ) : (
          cases.map(c => (
            <button
              key={c.case_id}
              className={`case-card ${c.case_id === activeCaseId ? 'case-card-active' : ''}`}
              onClick={() => onLoadCase(c.case_id)}
            >
              <div
                className="case-sev-strip"
                style={{ background: sevColor(c.top_severity) }}
              />
              <div className="case-body">
                <div className="case-row1">
                  <span className="case-id">{c.case_id}</span>
                  <span className={`badge ${sevClass(c.top_severity)}`}>{c.top_severity}</span>
                </div>
                <div className="case-row2">
                  <span className="case-time">{formatTS(c.timestamp, timezone)}</span>
                  <span className="case-threats">{c.threat_count} threat{c.threat_count !== 1 ? 's' : ''}</span>
                </div>
              </div>
            </button>
          ))
        )}
      </div>

      <div className="shortcuts-section">
        <button className="shortcuts-toggle" onClick={() => setKeysOpen(!keysOpen)}>
          <span>⌨ Shortcuts</span>
          <span style={{ fontSize: 11 }}>{keysOpen ? '▾' : '▸'}</span>
        </button>
        {keysOpen && (
          <div className="shortcuts-list">
            {SHORTCUTS.map(s => (
              <div key={s.key} className="shortcut-row">
                <span>{s.label}</span>
                <span className="shortcut-key">{s.key}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
