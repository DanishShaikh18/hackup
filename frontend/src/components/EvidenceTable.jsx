import React, { useState, useMemo } from 'react';

function formatTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts;
  }
}

function eventBadgeClass(event) {
  const e = (event || '').toLowerCase();
  if (e === 'deny') return 'badge-event-deny';
  if (e === 'allow') return 'badge-event-allow';
  if (e === 'login_failed') return 'badge-event-login_failed';
  if (e === 'login_success') return 'badge-event-login_success';
  return 'badge-info';
}

function eventLabel(event) {
  const e = (event || '').toUpperCase();
  return e.replace('_', ' ');
}

const FILTERS = ['All', 'Firewall', 'Auth'];

export default function EvidenceTable({ evidence, correlatedIps }) {
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');

  const correlatedSet = useMemo(() => new Set(correlatedIps || []), [correlatedIps]);

  const filtered = useMemo(() => {
    if (!evidence) return [];
    return evidence.filter(e => {
      if (filter === 'Firewall' && !e.source?.includes('Firewall')) return false;
      if (filter === 'Auth' && !e.source?.includes('Auth')) return false;
      if (search && !e.src_ip?.includes(search)) return false;
      return true;
    });
  }, [evidence, filter, search]);

  if (!evidence || evidence.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header"><span className="panel-title">📋 Evidence Table</span></div>
        <div className="empty-state">
          <div className="empty-state-icon">📋</div>
          <div className="empty-state-text">No evidence to display</div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">
          📋 Evidence Table
          <span className="panel-badge">{filtered.length}</span>
        </span>
      </div>

      <div className="evidence-controls">
        <div className="evidence-filters">
          {FILTERS.map(f => (
            <button
              key={f}
              className={`evidence-filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'All' ? 'All Sources' : f === 'Firewall' ? '🔥 Firewall' : '🔑 Auth'}
            </button>
          ))}
        </div>
        <input
          className="evidence-search"
          placeholder="Filter by IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="evidence-scroll">
        <table className="evidence-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Time</th>
              <th>IP</th>
              <th>Event</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e, i) => {
              const isCorrelated = correlatedSet.has(e.src_ip);
              const sourceClass = e.source?.includes('Firewall') ? 'badge-source-fw' : 'badge-source-auth';
              const sourceIcon = e.source?.includes('Firewall') ? '🔥' : '🔑';

              return (
                <tr key={i}>
                  <td>
                    <span className={`badge ${sourceClass}`} style={{ fontSize: 10 }}>
                      {sourceIcon} {e.source?.includes('Firewall') ? 'FW' : 'AUTH'}
                    </span>
                  </td>
                  <td className="evidence-time">{formatTime(e.timestamp)}</td>
                  <td>
                    <span className={`evidence-ip ${isCorrelated ? 'evidence-ip-correlated' : ''}`}>
                      {e.src_ip}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${eventBadgeClass(e.event)}`} style={{ fontSize: 10 }}>
                      {eventLabel(e.event)}
                    </span>
                  </td>
                  <td className="evidence-details" title={e.details}>{e.details}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
