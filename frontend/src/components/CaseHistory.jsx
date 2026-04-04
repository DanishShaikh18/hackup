import React, { useState } from 'react';

function severityClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

export default function CaseHistory({ cases, onLoadCase }) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div style={{
      borderBottom: '1px solid var(--border)',
      flexShrink: 0,
    }}>
      <button
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          width: '100%',
          padding: '10px 14px',
          background: 'none',
          borderBottom: collapsed ? 'none' : '1px solid var(--border-subtle)',
          cursor: 'pointer',
        }}
      >
        <span style={{
          fontSize: 12,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: 'var(--text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}>
          📁 Case History
          {cases.length > 0 && (
            <span className="panel-badge">{cases.length}</span>
          )}
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
          {collapsed ? '▸' : '▾'}
        </span>
      </button>

      {!collapsed && (
        <div style={{
          maxHeight: 200,
          overflowY: 'auto',
        }}>
          {cases.length === 0 ? (
            <div style={{
              padding: '16px 14px',
              textAlign: 'center',
              fontSize: 12,
              color: 'var(--text-muted)',
            }}>
              No past cases. Run an analysis to start.
            </div>
          ) : (
            cases.map((c) => (
              <button
                key={c.case_id}
                onClick={() => onLoadCase(c.case_id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  width: '100%',
                  padding: '6px 14px',
                  background: 'none',
                  borderBottom: '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  transition: 'background 0.15s ease',
                  textAlign: 'left',
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'var(--bg-hover)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'none'}
              >
                <span style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  color: 'var(--text-primary)',
                  minWidth: 0,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  flex: 1,
                }}>
                  {c.case_id}
                </span>
                <span className={`badge ${severityClass(c.top_severity)}`} style={{ fontSize: 9, flexShrink: 0 }}>
                  {c.top_severity}
                </span>
                <span style={{
                  fontSize: 10,
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)',
                  flexShrink: 0,
                }}>
                  {c.correlated_ips?.length || 0} IP{(c.correlated_ips?.length || 0) !== 1 ? 's' : ''}
                </span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}
