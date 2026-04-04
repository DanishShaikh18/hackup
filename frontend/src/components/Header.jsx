import React, { useState, useEffect } from 'react';

function AnimCounter({ value, duration = 600 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    if (!value) { setDisplay(0); return; }
    let start = 0;
    const end = value;
    const startTime = performance.now();
    const tick = (now) => {
      const p = Math.min((now - startTime) / duration, 1);
      setDisplay(Math.round(start + (end - start) * p));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value, duration]);
  return <span className="count-anim">{display}</span>;
}

export default function Header({ analysisData, analyzing, analyzeType, timezone, tzOptions, onTimezoneChange, onAnalyze }) {
  const noAnalysis = !analysisData && !analyzing;

  return (
    <header className="cc-header">
      <div className="hdr-left">
        <div className="hdr-logo">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <span>SOCentinel</span>
        </div>
        <span className="hdr-subtitle">SOC Co-Pilot</span>
      </div>

      <div className="hdr-center">
        {analysisData && (
          <>
            <div className="hdr-chip">
              <span className="hdr-chip-dot" />
              <span className="hdr-chip-label">Case</span>
              {analysisData.case_id}
            </div>
            <div className="hdr-chip">
              <span className="hdr-chip-label">FW</span>
              <AnimCounter value={analysisData.correlation_summary?.total_firewall_events || 0} />
            </div>
            <div className="hdr-chip">
              <span className="hdr-chip-label">Auth</span>
              <AnimCounter value={analysisData.correlation_summary?.total_auth_events || 0} />
            </div>
            <div className="hdr-chip">
              <span className="hdr-chip-label">IPs</span>
              <AnimCounter value={analysisData.correlation_summary?.correlated_ips || 0} />
            </div>
          </>
        )}
      </div>

      <div className="hdr-right">
        <select
          className="tz-select"
          value={timezone}
          onChange={(e) => onTimezoneChange(e.target.value)}
        >
          {tzOptions.map(tz => (
            <option key={tz.value} value={tz.value}>{tz.label}</option>
          ))}
        </select>

        <button
          className={`btn-analyze btn-analyze-primary ${
            analyzing && analyzeType === '/analyze' ? 'btn-analyzing-anim' : ''
          } ${noAnalysis ? 'btn-cta-pulse' : ''}`}
          onClick={() => onAnalyze('/analyze')}
          disabled={analyzing}
        >
          {analyzing && analyzeType === '/analyze' ? '⟳ Analyzing...' : '▶ Analyze'}
        </button>
        <button
          className={`btn-analyze ${analyzing && analyzeType === '/analyze-raw' ? 'btn-analyzing-anim' : ''}`}
          onClick={() => onAnalyze('/analyze-raw')}
          disabled={analyzing}
        >
          {analyzing && analyzeType === '/analyze-raw' ? '⟳ Parsing...' : '📄 Raw'}
        </button>
      </div>
    </header>
  );
}
