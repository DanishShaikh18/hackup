import React, { useState, useRef, useEffect, forwardRef, useImperativeHandle } from 'react';
import { formatTimeShort } from '../App';

const API = 'http://localhost:8000';

const QUICK_QUERIES = [
  'Summarize threats',
  'Why not FP?',
  'Block recommendation',
  'MITRE breakdown',
];

function renderMd(text) {
  if (!text) return text;
  let html = text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.*?)`/g, '<code>$1</code>')
    .replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>')
    .replace(/\n/g, '<br/>');
  if (html.includes('<li>')) {
    html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
  }
  return html;
}

const ChatDrawer = forwardRef(function ChatDrawer({ open, onClose, timezone }, ref) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const listRef = useRef(null);

  useImperativeHandle(ref, () => ({
    addAiMessage(text, grounded = true) {
      setMessages(prev => [...prev, {
        role: 'ai', text, ts: new Date().toISOString(), grounded, blocked: false,
      }]);
    },
  }));

  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [messages, sending]);

  const send = async (text) => {
    const msg = (text || input).trim();
    if (!msg) return;
    setInput('');
    setMessages(prev => [...prev, { role: 'user', text: msg, ts: new Date().toISOString() }]);
    setSending(true);

    try {
      const r = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      });
      const data = await r.json();
      const blocked = data.injection_detected;
      setMessages(prev => [...prev, {
        role: 'ai',
        text: blocked ? '⚠ Blocked — injection pattern detected' : (data.reply || ''),
        ts: new Date().toISOString(),
        grounded: data.grounded ?? (data.type === 'search'),
        blocked,
      }]);
    } catch {
      setMessages(prev => [...prev, {
        role: 'ai',
        text: 'Connection error. AI model unreachable.',
        ts: new Date().toISOString(),
        grounded: false,
        blocked: false,
      }]);
    } finally {
      setSending(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <>
      <div className={`chat-overlay ${open ? 'chat-overlay-open' : ''}`} onClick={onClose} />
      <div className={`chat-drawer ${open ? 'chat-drawer-open' : ''}`}>
        <div className="chat-header">
          <span className="chat-online-dot" />
          <span className="chat-title">SOC Co-Pilot</span>
          <button className="chat-close" onClick={onClose}>✕</button>
        </div>

        <div className="chat-messages" ref={listRef}>
          {messages.length === 0 && (
            <div className="empty-state" style={{ padding: '40px 10px' }}>
              <div className="empty-icon">💬</div>
              <div className="empty-text">Ask the AI co-pilot anything about the investigation</div>
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} className={`chat-msg chat-msg-${m.role}`}>
              <div className={`chat-bubble ${m.blocked ? 'chat-bubble-blocked' : ''}`}>
                {m.role === 'ai' && !m.blocked ? (
                  <div dangerouslySetInnerHTML={{ __html: renderMd(m.text) }} />
                ) : (
                  m.text
                )}
              </div>
              <div className="chat-msg-meta">
                <span className="chat-msg-time">{formatTimeShort(m.ts, timezone)}</span>
                {m.role === 'ai' && !m.blocked && (
                  <span className={`chat-grounded ${m.grounded ? 'chat-grounded-true' : 'chat-grounded-false'}`}>
                    {m.grounded ? 'Grounded' : 'Generative'}
                  </span>
                )}
              </div>
            </div>
          ))}

          {sending && (
            <div className="chat-typing">
              <div className="chat-typing-dot" />
              <div className="chat-typing-dot" />
              <div className="chat-typing-dot" />
            </div>
          )}
        </div>

        <div className="chat-quick-chips">
          {QUICK_QUERIES.map(q => (
            <button key={q} className="chat-quick-chip" onClick={() => send(q)}>
              {q}
            </button>
          ))}
        </div>

        <div className="chat-input-area">
          <textarea
            className="chat-textarea"
            placeholder="Ask the co-pilot..."
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKey}
            rows={1}
          />
          <button className="chat-send" onClick={() => send()} disabled={sending || !input.trim()}>
            ↑
          </button>
        </div>
      </div>
    </>
  );
});

export default ChatDrawer;
