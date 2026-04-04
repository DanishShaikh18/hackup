import React, { useState, useCallback, useRef, useEffect } from 'react';
import './App.css';
import Header from './components/Header';
import IntelFeed from './components/IntelFeed';
import ThreatWorkspace from './components/ThreatWorkspace';
import EvidencePanel from './components/EvidencePanel';
import ChatDrawer from './components/ChatDrawer';
import ShortcutsModal from './components/ShortcutsModal';

const API = 'http://localhost:8000';

const TZ_OPTIONS = [
  { label: 'UTC', value: 'UTC' },
  { label: 'IST', value: 'Asia/Kolkata' },
  { label: 'EST', value: 'America/New_York' },
  { label: 'PST', value: 'America/Los_Angeles' },
  { label: 'Local', value: Intl.DateTimeFormat().resolvedOptions().timeZone },
];

export function formatTS(ts, tz) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
      timeZone: tz,
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return ts; }
}

export function formatTimeShort(ts, tz) {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', {
      timeZone: tz,
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return ''; }
}

export function sevColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'var(--color-critical)';
  if (s === 'high') return 'var(--color-high)';
  if (s === 'medium') return 'var(--color-medium)';
  if (s === 'low') return 'var(--color-low)';
  return 'var(--color-info)';
}

export function sevClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  if (s === 'low') return 'badge-low';
  return 'badge-info';
}

export default function App() {
  const [analysisData, setAnalysisData] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeType, setAnalyzeType] = useState(null);
  const [selectedThreatIdx, setSelectedThreatIdx] = useState(0);
  const [caseHistory, setCaseHistory] = useState([]);
  const [chatOpen, setChatOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [timezone, setTimezone] = useState('UTC');
  const chatRef = useRef(null);

  const fetchCases = useCallback(async () => {
    try {
      const r = await fetch(`${API}/cases`);
      const d = await r.json();
      setCaseHistory(d.cases || []);
    } catch { /* */ }
  }, []);

  const runAnalysis = useCallback(async (endpoint) => {
    setAnalyzing(true);
    setAnalyzeType(endpoint);
    try {
      const r = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asset_value: 3 }),
      });
      const data = await r.json();
      setAnalysisData(data);
      if (data.threats?.length) {
        let mi = 0, ms = 0;
        data.threats.forEach((t, i) => {
          const s = t.risk_score?.score || 0;
          if (s > ms) { ms = s; mi = i; }
        });
        setSelectedThreatIdx(mi);
      }
      if (data.ai_summary && chatRef.current) {
        chatRef.current.addAiMessage(data.ai_summary, true);
      }
      fetchCases();
    } catch (err) {
      console.error('Analysis failed:', err);
    } finally {
      setAnalyzing(false);
      setAnalyzeType(null);
    }
  }, [fetchCases]);

  const loadCase = useCallback(async (caseId) => {
    try {
      const r = await fetch(`${API}/cases/${caseId}`);
      const data = await r.json();
      if (data.error) return;
      setAnalysisData(data);
      if (data.threats?.length) {
        let mi = 0, ms = 0;
        data.threats.forEach((t, i) => {
          const s = t.risk_score?.score || 0;
          if (s > ms) { ms = s; mi = i; }
        });
        setSelectedThreatIdx(mi);
      }
    } catch { /* */ }
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      // Don't capture when typing in inputs
      const tag = e.target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      if (e.key === '?') { e.preventDefault(); setShortcutsOpen(p => !p); }
      if (e.key === 'c' || e.key === 'C') { e.preventDefault(); setChatOpen(p => !p); }
      if (e.key === 'Escape') { setChatOpen(false); setShortcutsOpen(false); }
      if (e.key === 'a' && !e.ctrlKey && !e.metaKey) { e.preventDefault(); if (!analyzing) runAnalysis('/analyze'); }
      if (e.key === 'r' && !e.ctrlKey && !e.metaKey) { e.preventDefault(); if (!analyzing) runAnalysis('/analyze-raw'); }
      if (e.key === 'Tab' && analysisData?.threats?.length > 1) {
        e.preventDefault();
        setSelectedThreatIdx(p => (p + 1) % analysisData.threats.length);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [analyzing, analysisData, runAnalysis]);

  const threats = analysisData?.threats || [];
  const activeThreat = threats[selectedThreatIdx] || null;
  const caseId = analysisData?.case_id || null;

  return (
    <div className="cc-shell">
      <Header
        analysisData={analysisData}
        analyzing={analyzing}
        analyzeType={analyzeType}
        timezone={timezone}
        tzOptions={TZ_OPTIONS}
        onTimezoneChange={setTimezone}
        onAnalyze={runAnalysis}
      />

      <IntelFeed
        cases={caseHistory}
        activeCaseId={caseId}
        timezone={timezone}
        onLoadCase={loadCase}
      />

      <ThreatWorkspace
        threats={threats}
        activeThreat={activeThreat}
        selectedIdx={selectedThreatIdx}
        onSelectThreat={setSelectedThreatIdx}
        analyzing={analyzing}
        analyzeType={analyzeType}
        caseId={caseId}
        timezone={timezone}
      />

      <EvidencePanel
        evidence={analysisData?.evidence_table || []}
        alerts={activeThreat?.triggered_alerts || []}
        threats={threats}
        correlatedIps={threats.map(t => t.ip)}
        timezone={timezone}
      />

      {/* Chat FAB */}
      {!chatOpen && (
        <button className="chat-fab" onClick={() => setChatOpen(true)} title="SOC Co-Pilot (C)">
          💬
        </button>
      )}

      <ChatDrawer
        ref={chatRef}
        open={chatOpen}
        onClose={() => setChatOpen(false)}
        timezone={timezone}
      />

      {shortcutsOpen && <ShortcutsModal onClose={() => setShortcutsOpen(false)} />}
    </div>
  );
}
