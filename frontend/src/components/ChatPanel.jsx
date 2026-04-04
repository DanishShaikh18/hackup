import React, { useState, useRef, useEffect, forwardRef, useImperativeHandle, useCallback } from 'react';

const API = 'http://localhost:8000';

const ChatPanel = forwardRef(function ChatPanel(_, ref) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);

  const now = () => {
    const d = new Date();
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading, scrollToBottom]);

  useImperativeHandle(ref, () => ({
    addAiMessage: (text) => {
      setMessages(prev => [...prev, { role: 'ai', text, time: now() }]);
    },
  }));

  const handleSend = async () => {
    const msg = input.trim();
    if (!msg || loading) return;

    setMessages(prev => [...prev, { role: 'user', text: msg, time: now() }]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      });
      const data = await res.json();
      const reply = data.reply || data.error || 'No response';
      setMessages(prev => [...prev, { role: 'ai', text: reply, time: now() }]);
    } catch {
      setMessages(prev => [...prev, { role: 'ai', text: '⚠ Connection error — is the backend running?', time: now() }]);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div className="chat-header-title">
          <span className="chat-header-dot" />
          SOC Co-Pilot
        </div>
      </div>

      <div className="chat-messages" ref={scrollRef}>
        {messages.length === 0 && (
          <div className="empty-state" style={{ padding: '40px 12px' }}>
            <div className="empty-state-icon">💬</div>
            <div className="empty-state-text">
              Ask questions about the investigation or search logs
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`chat-msg chat-msg-${m.role}`}>
            <div className="chat-msg-bubble">{m.text}</div>
            <span className="chat-msg-time">{m.time}</span>
          </div>
        ))}

        {loading && (
          <div className="chat-typing">
            <span className="chat-typing-dot" />
            <span className="chat-typing-dot" />
            <span className="chat-typing-dot" />
          </div>
        )}
      </div>

      <div className="chat-input-area">
        <input
          className="chat-input"
          placeholder="Ask about the investigation..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
        />
        <button
          className="chat-send-btn"
          onClick={handleSend}
          disabled={!input.trim() || loading}
          title="Send message"
        >
          ↑
        </button>
      </div>
    </div>
  );
});

export default ChatPanel;
