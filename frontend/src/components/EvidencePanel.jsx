import React, { useState } from 'react';
import { formatTS, sevColor } from '../App';

const API = 'http://localhost:8000';

export default function EvidencePanel({ evidence, alerts, threats, correlatedIps, timezone }) {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [blockTarget, setBlockTarget] = useState(null);
  const [blocking, setBlocking] = useState(false);
  const [blockedIps, setBlockedIps] = useState({});
  const [confirmIp, setConfirmIp] = useState(null);

  const filtered = evidence.filter(e => {
    if (filter === 'fw' && !e.source?.toLowerCase().includes('firewall')) return false;
    if (filter === 'auth' && !e.source?.toLowerCase().includes('auth')) return false;
    if (search && !e.src_ip?.includes(search) && !e.details?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const handleBlock = async (ip) => {
    setBlocking(true);
    try {
      const r = await fetch(`${API}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      const data = await r.json();
      if (data.status === 'success') {
        setBlockedIps(prev => ({ ...prev, [ip]: data.details }));
      }
    } catch { /* */ }
    finally { setBlocking(false); setConfirmIp(null); }
  };

  // Threats that can be blocked
  const blockableThreats = threats.filter(t => !t.false_positive_analysis?.is_false_positive && !blockedIps[t.ip]);

  return (
    <aside className="cc-right">
      {/* Evidence Section */}
      <div className="ev-section">
        <div className="panel-title-bar" style={{ borderBottom: 'none', paddingBottom: 0 }}>
          <span className="panel-title">Evidence Log</span>
          <span className="panel-badge-count">{filtered.length}</span>
        </div>

        <div className="ev-filters">
          {['all', 'fw', 'auth'].map(f => (
            <button
              key={f}
              className={`ev-filter-chip ${filter === f ? 'ev-filter-chip-active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? 'All' : f === 'fw' ? 'FW' : 'Auth'}
            </button>
          ))}
          <input
            className="ev-search"
            placeholder="Search IP..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="ev-list">
          {filtered.length === 0 ? (
            <div className="empty-state" style={{ padding: '20px 10px' }}>
              <div className="empty-icon">📋</div>
              <div className="empty-text">No evidence to display</div>
            </div>
          ) : (
            filtered.slice(0, 100).map((ev, i) => {
              const isFW = ev.source?.toLowerCase().includes('firewall');
              const isCorrelated = correlatedIps.includes(ev.src_ip);
              return (
                <div key={i} className="ev-card">
                  <div className="ev-card-row1">
                    <span className={`ev-source ${isFW ? 'ev-source-fw' : 'ev-source-auth'}`}>
                      {isFW ? 'FW' : 'AUTH'}
                    </span>
                    <span className="ev-ts">{formatTS(ev.timestamp, timezone)}</span>
                    <span className={`ev-ip ${isCorrelated ? 'ev-ip-correlated' : ''}`}>{ev.src_ip}</span>
                  </div>
                  <div className="ev-card-row2">
                    <span className="ev-event-type">{ev.event}</span>
                    {ev.details}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Alerts Section */}
      {alerts.length > 0 && (
        <div className="alert-section">
          <div className="panel-title-bar">
            <span className="panel-title">Triggered Alerts</span>
            <span className="panel-badge-count">{alerts.length}</span>
          </div>
          {alerts.map((a, i) => (
            <div
              key={i}
              className="alert-card"
              style={{ borderLeftColor: sevColor(a.severity) }}
            >
              <div className="alert-cat">
                {a.alert_category}
                <span className={`badge ${a.severity?.toLowerCase() === 'critical' ? 'badge-critical' : a.severity?.toLowerCase() === 'high' ? 'badge-high' : 'badge-medium'}`}
                  style={{ marginLeft: 6 }}>{a.severity}</span>
              </div>
              <div className="alert-metric">
                <span>Threshold: <strong className="mono">{a.threshold_value}</strong></span>
                <span>Observed: <strong className="mono">{a.observed_value}</strong></span>
                <span className="alert-factor" style={{ color: sevColor(a.severity) }}>
                  {a.exceeded_by_factor ? `${a.exceeded_by_factor.toFixed(1)}×` : '—'}
                </span>
              </div>
              <div className="alert-action">{a.recommended_action}</div>
            </div>
          ))}
        </div>
      )}

      {/* SOAR Section */}
      <div className="soar-section">
        <div className="soar-title">SOAR Actions</div>

        {blockableThreats.length === 0 && Object.keys(blockedIps).length === 0 ? (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            No actionable threats or all IPs blocked.
          </div>
        ) : (
          <>
            {blockableThreats.map(t => (
              <div key={t.ip} style={{ marginBottom: 6 }}>
                {confirmIp === t.ip ? (
                  <div className="soar-confirm">
                    <div className="soar-confirm-text">
                      Block <span className="soar-confirm-ip">{t.ip}</span>?
                      This will add a firewall deny rule.
                    </div>
                    <div className="soar-confirm-btns">
                      <button className="btn-soar-cancel" onClick={() => setConfirmIp(null)}>Cancel</button>
                      <button className="btn-soar-block" onClick={() => handleBlock(t.ip)} disabled={blocking}>
                        🔒 {blocking ? 'Blocking...' : 'Block IP →'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    className="btn-action btn-action-danger"
                    style={{ width: '100%', justifyContent: 'center' }}
                    onClick={() => setConfirmIp(t.ip)}
                  >
                    🔒 Block {t.ip}
                  </button>
                )}
              </div>
            ))}
          </>
        )}

        {Object.keys(blockedIps).length > 0 && (
          <div className="blocked-list">
            {Object.entries(blockedIps).map(([ip, details]) => (
              <div key={ip} className="soar-blocked">
                ✓ {ip}
                <span className="soar-blocked-rule">{details.rule_added}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
