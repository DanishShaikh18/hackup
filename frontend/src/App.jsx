import React, { useState, useCallback, useRef } from 'react';
import './App.css';
import ChatPanel from './components/ChatPanel';
import ThreatSelector from './components/ThreatSelector';
import MathBox from './components/MathBox';
import KillChainTimeline from './components/KillChainTimeline';
import AttackTimeline from './components/AttackTimeline';
import EvidenceTable from './components/EvidenceTable';
import SOARButton from './components/SOARButton';

const API = 'http://localhost:8000';

export default function App() {
  const [analysisData, setAnalysisData] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeType, setAnalyzeType] = useState(null);
  const [selectedThreatIndex, setSelectedThreatIndex] = useState(0);
  const chatRef = useRef(null);

  const runAnalysis = useCallback(async (endpoint) => {
    setAnalyzing(true);
    setAnalyzeType(endpoint);
    try {
      const res = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_value: 3 }),
      });
      const data = await res.json();
      setAnalysisData(data);

      // Auto-select highest risk threat
      if (data.threats && data.threats.length > 0) {
        let maxIdx = 0;
        let maxScore = 0;
        data.threats.forEach((t, i) => {
          const s = t.risk_score?.score || 0;
          if (s > maxScore) {
            maxScore = s;
            maxIdx = i;
          }
        });
        setSelectedThreatIndex(maxIdx);
      }

      // Push AI summary to chat
      if (data.ai_summary && chatRef.current) {
        chatRef.current.addAiMessage(data.ai_summary);
      }
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      setAnalyzing(false);
      setAnalyzeType(null);
    }
  }, []);

  const threats = analysisData?.threats || [];
  const activeThreat = threats[selectedThreatIndex] || null;
  const correlatedIps = threats.map(t => t.ip);

  return (
    <div className="app-shell">
      {/* ── Header ───────────────────────── */}
      <header className="header">
        <div className="header-left">
          <div className="header-logo">
            <span className="shield">🛡️</span>
            <h1>SOCentinel</h1>
            <span className="subtitle">SOC Co-Pilot</span>
          </div>
        </div>

        <div className="header-center">
          {analysisData && (
            <>
              <div className="header-pill">
                <span className="pill-label">Case</span>
                {analysisData.case_id}
              </div>
              <div className="header-pill">
                <span className="pill-label">FW</span>
                {analysisData.correlation_summary?.total_firewall_events || 0}
              </div>
              <div className="header-pill">
                <span className="pill-label">Auth</span>
                {analysisData.correlation_summary?.total_auth_events || 0}
              </div>
              <div className="header-pill">
                <span className="pill-label">IPs</span>
                {analysisData.correlation_summary?.correlated_ips || 0}
              </div>
            </>
          )}
        </div>

        <div className="header-right">
          <button
            className={`btn btn-primary ${analyzing && analyzeType === '/analyze' ? 'btn-analyzing' : ''}`}
            onClick={() => runAnalysis('/analyze')}
            disabled={analyzing}
          >
            {analyzing && analyzeType === '/analyze' ? '⟳ Analyzing...' : '▶ Analyze'}
          </button>
          <button
            className={`btn ${analyzing && analyzeType === '/analyze-raw' ? 'btn-analyzing' : ''}`}
            onClick={() => runAnalysis('/analyze-raw')}
            disabled={analyzing}
          >
            {analyzing && analyzeType === '/analyze-raw' ? '⟳ Parsing...' : '📄 Analyze Raw'}
          </button>
        </div>
      </header>

      {/* ── Sidebar: Chat ────────────────── */}
      <aside className="sidebar">
        <ChatPanel ref={chatRef} />
      </aside>

      {/* ── Workspace ────────────────────── */}
      <main className="workspace">
        {analyzing ? (
          <LoadingSkeleton />
        ) : !analysisData ? (
          <div className="empty-state" style={{ marginTop: 80 }}>
            <div className="empty-state-icon">🔍</div>
            <div className="empty-state-text">
              Click <strong>Analyze</strong> or <strong>Analyze Raw</strong> to start an investigation
            </div>
          </div>
        ) : (
          <>
            <ThreatSelector
              threats={threats}
              selectedIndex={selectedThreatIndex}
              onSelect={setSelectedThreatIndex}
            />
            <MathBox threat={activeThreat} />
            <KillChainTimeline killChain={activeThreat?.kill_chain} />
            <AttackTimeline
              timeline={activeThreat?.attack_timeline}
              ip={activeThreat?.ip}
            />
            <EvidenceTable
              evidence={analysisData.evidence_table}
              correlatedIps={correlatedIps}
            />
            <SOARButton threats={threats} />
          </>
        )}
      </main>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="loading-overlay">
      <div className="skeleton skeleton-line" style={{ width: '40%' }} />
      <div className="skeleton skeleton-block" />
      <div className="skeleton skeleton-line" style={{ width: '70%' }} />
      <div className="skeleton skeleton-block" />
      <div className="skeleton skeleton-line" style={{ width: '55%' }} />
      <div className="skeleton skeleton-block" />
    </div>
  );
}
