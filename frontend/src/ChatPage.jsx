import { useState, useRef, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Send, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, RotateCcw, Trash2 } from 'lucide-react';
import axios from 'axios';
import LoadingState from './LoadingState';
import CountdownTimer from './CountdownTimer';

const DEFAULT_CHAT_PREFERENCES = { compactChat: false, sendOnEnter: true };

function storedChatPreferences() {
  try {
    const user = JSON.parse(localStorage.getItem('hp_user') || 'null');
    return { ...DEFAULT_CHAT_PREFERENCES, ...JSON.parse(localStorage.getItem(`hp_user_preferences_${user?.username || 'guest'}`) || '{}') };
  } catch {
    return DEFAULT_CHAT_PREFERENCES;
  }
}

const CLASSIFICATION_CONFIG = {
  SAFE: { icon: ShieldCheck, color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: '#10b981', label: '🟢 SAFE' },
  SUSPICIOUS: { icon: AlertTriangle, color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: '#f59e0b', label: '🟡 SUSPICIOUS' },
  MALICIOUS: { icon: ShieldX, color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: '#ef4444', label: '🔴 MALICIOUS' },
  UNCLASSIFIED: { icon: AlertTriangle, color: '#8a8070', bg: 'rgba(138,128,112,0.08)', border: '#8a8070', label: '⚪ UNCLASSIFIED' },
};

const WELCOME_MESSAGE = {
  role: 'assistant',
  content: 'Hello! I am your internal AI assistant (SENTINEL-7). I can help you analyze data or summarize reports.',
};

function SecurityCard({ data }) {
  const cfg = CLASSIFICATION_CONFIG[data.classification] || CLASSIFICATION_CONFIG.UNCLASSIFIED;
  const Icon = cfg.icon;
  return (
    <div role={data.classification === 'MALICIOUS' ? 'alert' : 'status'} aria-live={data.classification === 'MALICIOUS' ? 'assertive' : 'polite'} style={{ border: `1px solid ${cfg.border}`, background: cfg.bg, borderRadius: '10px', padding: '14px 18px', marginBottom: '10px', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: cfg.color, fontWeight: 'bold', fontSize: '0.9rem', marginBottom: '10px' }}>
        <Icon size={16} /> {cfg.label}
      </div>
      {data.classification === 'MALICIOUS' && <strong style={{ display: 'block', marginBottom: '8px', color: cfg.color, fontSize: '0.77rem' }}>MALICIOUS PROMPT DETECTED · REQUEST BLOCKED</strong>}
      <div className="analysis-complete"><ShieldCheck size={13} /> THREAT ANALYSIS COMPLETE</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 20px', color: 'var(--text-secondary)' }}>
        <span>Threat: <span style={{ color: 'var(--text-primary)' }}>{data.threat_type ?? '—'}</span></span>
        <span>Severity: <span style={{ color: cfg.color }}>{data.severity ?? '—'}</span></span>
        <span>Confidence: <span style={{ color: 'var(--text-primary)' }}>{typeof data.confidence === 'number' ? `${(data.confidence * 100).toFixed(1)}%` : '—'}</span></span>
        <span>Risk score: <span style={{ color: 'var(--text-primary)' }}>{typeof data.risk_score === 'number' ? data.risk_score : '—'}</span></span>
        <span>Action: <span style={{ color: cfg.color, fontWeight: 'bold' }}>{data.action ?? '—'}</span></span>
      </div>
      {data.reason && (
        <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: `1px solid ${cfg.border}33`, color: 'var(--text-secondary)' }}>
          Reason: {data.reason}
        </div>
      )}
    </div>
  );
}

export default function ChatPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const conversationParam = searchParams.get('conversation');
  const [messages, setMessages] = useState([WELCOME_MESSAGE]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [preferences, setPreferences] = useState(storedChatPreferences);
  const [conversationId, setConversationId] = useState(conversationParam || '');
  const [openingConversation, setOpeningConversation] = useState(Boolean(conversationParam));
  const [chatStatus, setChatStatus] = useState({ consecutive_count: 0, warning_threshold: 3, block_threshold: 5, blocked_until: null });
  const scrollRef = useRef(null);

  const refreshChatStatus = useCallback(async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/user/chat-status');
      setChatStatus(response.data);
    } catch {
      setChatStatus(current => current);
    }
  }, []);

  useEffect(() => { scrollRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => {
    if (!conversationParam) {
      setConversationId('');
      setMessages([WELCOME_MESSAGE]);
      setOpeningConversation(false);
      return undefined;
    }
    let active = true;
    setOpeningConversation(true);
    axios.get(`http://127.0.0.1:8000/api/user/conversations/${encodeURIComponent(conversationParam)}`)
      .then(({ data }) => {
        if (!active) return;
        setConversationId(data.conversation.conversation_id);
        setMessages(data.messages.flatMap(message => [
          { role: 'user', content: message.prompt },
          { role: 'assistant', content: message.response, prompt: message.prompt, security: message },
        ]));
      })
      .catch(() => {
        if (active) setMessages([{ ...WELCOME_MESSAGE, content: 'This conversation is unavailable. Start a new chat or choose another conversation from Chat History.' }]);
      })
      .finally(() => { if (active) setOpeningConversation(false); });
    return () => { active = false; };
  }, [conversationParam]);
  useEffect(() => { refreshChatStatus(); }, [refreshChatStatus]);
  useEffect(() => {
    const onPreferencesChanged = event => setPreferences(current => ({ ...current, ...event.detail }));
    window.addEventListener('hp-user-preferences', onPreferencesChanged);
    return () => window.removeEventListener('hp-user-preferences', onPreferencesChanged);
  }, []);

  const sendMessage = async (prompt = input, regenerate = false) => {
    const message = prompt.trim();
    if (!message || loading || (chatStatus.blocked_until && new Date(chatStatus.blocked_until).getTime() > Date.now())) return;
    if (!regenerate) {
      setMessages(prev => [...prev, { role: 'user', content: message }]);
      setInput('');
    }
    setLoading(true);
    setScanStep(0);
    const scanInterval = window.setInterval(() => setScanStep(step => (step + 1) % 3), 700);

    try {
      const res = await axios.post('http://127.0.0.1:8000/api/chat', { message, conversation_id: conversationId || null });
      const d = res.data;
      if (d.conversation_id && d.conversation_id !== conversationId) {
        setConversationId(d.conversation_id);
        setSearchParams({ conversation: d.conversation_id }, { replace: true });
      }
      setChatStatus(current => ({ ...current, consecutive_count: d.consecutive_count ?? current.consecutive_count, warning_threshold: d.warning_threshold ?? current.warning_threshold, block_threshold: d.block_threshold ?? current.block_threshold, blocked_until: d.blocked_until ?? null, is_chat_blocked: Boolean(d.blocked_until) }));
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: d.response,
        prompt: message,
        security: {
          classification: d.classification,
          threat_type: d.threat_type,
          severity: d.severity,
          confidence: d.confidence,
          risk_score: d.risk_score,
          action: d.action,
          reason: d.reason,
        },
      }]);
    } catch (err) {
      const detail = err.response?.data?.detail;
      if (err.response?.status === 429 && typeof detail === 'object') {
        setChatStatus(current => ({ ...current, consecutive_count: detail.consecutive_count ?? current.consecutive_count, blocked_until: detail.blocked_until, is_chat_blocked: true }));
      }
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: typeof detail === 'string' ? detail : detail?.message || 'Unable to process your request. Please try again.',
        isError: true,
        prompt: message,
      }]);
    } finally {
      window.clearInterval(scanInterval);
      setLoading(false);
    }
  };

  const onKey = (e) => { if (preferences.sendOnEnter && e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
  const clearChat = () => {
    if (loading) return;
    setMessages([WELCOME_MESSAGE]);
    setInput('');
    setConversationId('');
    setSearchParams({}, { replace: true });
  };

  const onBlockExpired = useCallback(() => { refreshChatStatus(); }, [refreshChatStatus]);
  const isChatBlocked = Boolean(chatStatus.blocked_until && new Date(chatStatus.blocked_until).getTime() > Date.now());

  return (
    <div className={`chat-feed${preferences.compactChat ? ' chat-compact' : ''}`}>
      <header className="chat-console-header">
        <div><span className="eyebrow">PRIVATE AI SECURITY SESSION</span><h1>Secure AI Chat Console</h1><p>Prompts are analyzed before they reach the assistant.</p></div>
        <div className="chat-header-actions"><button className="chat-clear-button" onClick={clearChat} disabled={loading || messages.length <= 1} aria-label="Start a new chat"><Trash2 size={15} /> New chat</button></div>
      </header>
      {chatStatus.consecutive_count >= chatStatus.warning_threshold && !isChatBlocked && <div className="chat-threat-warning" role="alert"><ShieldAlert size={17} /><span><strong>Security Warning: {chatStatus.consecutive_count} consecutive malicious prompts detected.</strong> Admin has been notified. Further attempts may temporarily restrict chat access.</span></div>}
      {isChatBlocked && <div className="chat-block-banner" role="alert"><ShieldX size={20} /><div><strong>Chat Temporarily Blocked</strong><span>{chatStatus.consecutive_count} consecutive malicious prompts were detected. Your chat access has been temporarily restricted.</span><CountdownTimer until={chatStatus.blocked_until} onExpire={onBlockExpired} /></div></div>}
      {openingConversation && <LoadingState label="Opening conversation..." compact />}
      {messages.map((msg, idx) => (
        <div key={idx} style={{ width: '100%', display: 'flex', flexDirection: 'column' }}>
          {msg.role === 'user' && (
            <div className="chat-bubble user">{msg.content}</div>
          )}
          {msg.role === 'assistant' && (
            <div style={{ alignSelf: 'flex-start', maxWidth: '80%' }}>
              {msg.security && <SecurityCard data={msg.security} />}
              <div className={`chat-bubble ai${msg.isError ? ' error' : ''}`}>
                {msg.isError && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#ef4444', fontSize: '0.8rem', marginBottom: '8px' }}>
                    <ShieldAlert size={15} /> REQUEST FAILED
                  </div>
                )}
                {msg.content}
              </div>
              {msg.prompt && msg.security?.classification !== 'MALICIOUS' && <button className="chat-retry-button" onClick={() => sendMessage(msg.prompt, true)} disabled={loading}><RotateCcw size={13} /> {msg.isError ? 'Retry prompt' : 'Regenerate response'}</button>}
            </div>
          )}
        </div>
      ))}
      {loading && (
        <div className="chat-scan-state" role="status" aria-live="polite">
          <div className="chat-bubble ai scan-bubble">
            <LoadingState label="SENTINEL is analyzing..." compact />
            <div className="scan-steps">{['Scanning content', 'Checking intent', 'Evaluating risk'].map((step, index) => <span className={scanStep === index ? 'scan-step-active' : ''} key={step}><i /> {step}</span>)}</div>
          </div>
        </div>
      )}
      <div ref={scrollRef} />

      <div className="input-bar">
        <input
          type="text"
          className="input-field"
          placeholder="Enter a prompt to securely analyze..."
          aria-label="Enter a prompt to securely analyze"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKey}
          disabled={loading || isChatBlocked || openingConversation}
        />
        <button className="send-btn" onClick={sendMessage} disabled={loading || isChatBlocked || openingConversation || !input.trim()}>
          <Send size={18} />
        </button>
      </div>
    </div>
  );
}
