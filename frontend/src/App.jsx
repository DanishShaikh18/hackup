import { useState } from 'react';
import ChatPanel from './components/ChatPanel';
import EvidenceTable from './components/EvidenceTable';
import MathBox from './components/MathBox';
import KillChainTimeline from './components/KillChainTimeline';
import SOARButton from './components/SOARButton';

const API = 'http://localhost:8000';

export default function App() {
  const [analysisData, setAnalysisData] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);

  const runAnalysis = async () => {
    setAnalyzing(true);
    try {
      const res = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_value: 3 }),
      });
      const data = await res.json();
      setAnalysisData(data);
    } catch {
      console.error('Failed to reach backend.');
    }
    setAnalyzing(false);
  };

  // Get the top threat for MathBox + KillChain
  const topThreat = analysisData?.threats?.length
    ? analysisData.threats.reduce((a, b) =>
        a.risk_score.score > b.risk_score.score ? a : b
      )
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Header */}
      <header className="app-header">
        <span className="app-header__logo">🛡️</span>
        <h1 className="app-header__title">SOCentinel</h1>
        <span className="app-header__subtitle">Hybrid Security Reasoning Engine</span>
        <button
          id="analyze-btn"
          className="app-header__analyze-btn"
          onClick={runAnalysis}
          disabled={analyzing}
        >
          {analyzing ? (
            <><span className="loader"></span> Analyzing...</>
          ) : (
            <>⚡ Analyze Logs</>
          )}
        </button>
      </header>

      {/* Info bar when analysis is loaded */}
      {analysisData && (
        <div style={{ padding: '0.5rem 1rem' }}>
          <div className="info-row">
            <div className="info-row__item">
              <span>📁</span> Case:
              <span className="info-row__value">{analysisData.case_id}</span>
            </div>
            <div className="info-row__item">
              <span>🔥</span> Firewall Events:
              <span className="info-row__value">{analysisData.correlation_summary?.total_firewall_events}</span>
            </div>
            <div className="info-row__item">
              <span>🔑</span> Auth Events:
              <span className="info-row__value">{analysisData.correlation_summary?.total_auth_events}</span>
            </div>
            <div className="info-row__item">
              <span>🔗</span> Correlated IPs:
              <span className="info-row__value">{analysisData.correlation_summary?.correlated_ips}</span>
            </div>
          </div>
        </div>
      )}

      {/* Split Layout */}
      <div className="split-layout">
        {/* Left: Chat */}
        <ChatPanel analysisData={analysisData} onAnalysisRequest={runAnalysis} />

        {/* Right: Evidence Workspace */}
        <div className="evidence-workspace">
          <MathBox threat={topThreat} />
          <KillChainTimeline killChain={topThreat?.kill_chain} />
          <EvidenceTable
            evidence={analysisData?.evidence_table}
            correlatedIPs={analysisData?.correlation_summary?.ips}
          />
          <SOARButton threats={analysisData?.threats} />
        </div>
      </div>
    </div>
  );
}
