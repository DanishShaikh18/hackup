import AlertQueue from './components/AlertQueue';
import TriageCard from './components/TriageCard';
import AgentPanel from './components/AgentPanel';
import Timeline from './components/Timeline';
import AttackMap from './components/AttackMap';
import ActionPanel from './components/ActionPanel';
import MFAGateModal from './components/MFAGateModal';
import SimilarCases from './components/SimilarCases';
import CaseBuilder from './components/CaseBuilder';
import CISOReport from './components/CISOReport';
import NLQueryBar from './components/NLQueryBar';

export default function App() {
  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base)' }}>
      <header style={{
        padding: '1rem 2rem',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: '0.75rem'
      }}>
        <span style={{ fontSize: '1.5rem' }}>🛡️</span>
        <h1 style={{
          fontSize: '1.25rem',
          fontWeight: 600,
          color: 'var(--accent-gold)'
        }}>SOCentinel</h1>
        <span style={{
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          marginLeft: 'auto'
        }}>AI-Driven SOC Co-Pilot</span>
      </header>
      <main style={{ padding: '1rem' }}>
        <NLQueryBar />
        <AlertQueue />
      </main>
    </div>
  );
}
