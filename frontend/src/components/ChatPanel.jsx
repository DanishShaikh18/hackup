import { useState, useRef, useEffect } from 'react';

const API = 'http://localhost:8000';

export default function ChatPanel({ analysisData, onAnalysisRequest }) {
  const [messages, setMessages] = useState([
    {
      role: 'system',
      content: 'SOCentinel Co-Pilot ready. Click "Analyze Logs" to start an investigation, or ask me anything about security.',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  // When new analysis arrives, add the AI summary as a message
  useEffect(() => {
    if (analysisData?.ai_summary) {
      setMessages((prev) => [
        ...prev,
        { role: 'ai', content: analysisData.ai_summary },
      ]);
    }
  }, [analysisData?.case_id]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async () => {
    const msg = input.trim();
    if (!msg || loading) return;

    setMessages((prev) => [...prev, { role: 'user', content: msg }]);
    setInput('');
    setLoading(true);

    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg }),
      });
      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        {
          role: 'ai',
          content: data.reply || 'No response received.',
          type: data.type,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'ai', content: 'Connection error. Is the backend running?' },
      ]);
    }
    setLoading(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="chat-panel">
      <div className="chat-panel__header">
        <span>🤖</span>
        SOC Co-Pilot
      </div>

      <div className="chat-panel__messages">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-bubble chat-bubble--${msg.role}`}>
            {msg.content}
          </div>
        ))}
        {loading && (
          <div className="chat-bubble chat-bubble--ai">
            <div className="typing-dots">
              <span></span><span></span><span></span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-panel__input-area">
        <input
          id="chat-input"
          className="chat-panel__input"
          placeholder="Ask about the investigation..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={loading}
        />
        <button
          id="chat-send-btn"
          className="chat-panel__send"
          onClick={sendMessage}
          disabled={loading || !input.trim()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
