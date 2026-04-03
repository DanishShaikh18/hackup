export default function EvidenceTable({ evidence, correlatedIPs }) {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="panel">
        <div className="panel__header">
          <span className="panel__header-icon">📋</span>
          Evidence Table
        </div>
        <div className="empty-state">
          <div className="empty-state__icon">🔍</div>
          <div className="empty-state__text">
            No evidence loaded. Click "Analyze Logs" to ingest firewall and auth log data.
          </div>
        </div>
      </div>
    );
  }

  const suspiciousIPs = new Set(correlatedIPs || []);

  return (
    <div className="panel">
      <div className="panel__header">
        <span className="panel__header-icon">📋</span>
        Evidence Table
        <span style={{ marginLeft: 'auto', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          {evidence.length} events
        </span>
      </div>
      <div className="table-scroll">
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
            {evidence.map((e, i) => {
              const isCorrelated = suspiciousIPs.has(e.src_ip);
              const eventClass = e.event === 'deny' || e.event === 'login_failed' ? 'fail' : 
                                 e.event === 'allow' || e.event === 'login_success' ? 'success' : '';
              return (
                <tr key={i} className={isCorrelated ? 'correlated' : ''}>
                  <td>
                    <span className={`badge badge--${e.source.toLowerCase()}`}>
                      {e.source === 'Firewall' ? '🔥' : '🔑'} {e.source}
                    </span>
                  </td>
                  <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ color: isCorrelated ? 'var(--accent-red)' : 'inherit', fontWeight: isCorrelated ? 600 : 400 }}>
                    {e.src_ip}
                  </td>
                  <td>
                    <span className={`badge badge--${eventClass}`}>
                      {e.event}
                    </span>
                  </td>
                  <td>{e.details}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
