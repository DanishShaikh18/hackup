import { useState } from 'react';

const API = 'http://localhost:8000';

export default function SOARButton({ threats }) {
  const [blockedIPs, setBlockedIPs] = useState(new Set());
  const [loading, setLoading] = useState(null);
  const [toast, setToast] = useState(null);

  if (!threats || threats.length === 0) {
    return null;
  }

  // Only show for non-false-positive threats
  const actionableThreats = threats.filter(t => !t.false_positive_analysis?.is_false_positive);

  if (actionableThreats.length === 0) return null;

  const handleBlock = async (ip) => {
    setLoading(ip);
    try {
      const res = await fetch(`${API}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      if (data.status === 'success') {
        setBlockedIPs((prev) => new Set([...prev, ip]));
        setToast(`✅ ${ip} blocked — Rule ${data.details?.rule_added}`);
        setTimeout(() => setToast(null), 3000);
      }
    } catch {
      setToast(`❌ Failed to block ${ip}`);
      setTimeout(() => setToast(null), 3000);
    }
    setLoading(null);
  };

  return (
    <>
      <div className="panel">
        <div className="panel__header">
          <span className="panel__header-icon">🚨</span>
          SOAR Actions
        </div>
        <div className="panel__body">
          <div className="soar-actions">
            {actionableThreats.map((threat) => {
              const ip = threat.ip;
              const isBlocked = blockedIPs.has(ip);
              const isLoading = loading === ip;

              return (
                <div key={ip} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span className="soar-ip">{ip}</span>
                  {isBlocked ? (
                    <button className="soar-btn soar-btn--blocked" disabled>
                      ✅ Blocked
                    </button>
                  ) : (
                    <button
                      id={`block-${ip.replace(/\./g, '-')}`}
                      className="soar-btn soar-btn--block"
                      onClick={() => handleBlock(ip)}
                      disabled={isLoading}
                    >
                      {isLoading ? (
                        <><span className="loader"></span> Blocking...</>
                      ) : (
                        <>🚫 Block IP</>
                      )}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
      {toast && <div className="toast">{toast}</div>}
    </>
  );
}
