import { useState, useRef, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Send, ShieldAlert, ShieldX, RotateCcw, Trash2, Pencil, Square, Check, X } from 'lucide-react';
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

const WELCOME_MESSAGE = {
  role: 'assistant',
  content: 'Hello! I am your internal AI assistant (SENTINEL-7). I can help you analyze data or summarize reports.',
};

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
  // Edit state: { index: number, value: string } | null
  const [editState, setEditState] = useState(null);
  const scrollRef = useRef(null);
  const abortRef = useRef(null);
  const scanIntervalRef = useRef(null);

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
          { role: 'assistant', content: message.response, prompt: message.prompt, _blocked: message.classification === 'MALICIOUS' },
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

  // Stop/abort current generation
  const stopGeneration = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      abortRef.current = null;
    }
    if (scanIntervalRef.current) {
      window.clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }
    setLoading(false);
  };

  const sendMessage = async (prompt = input, regenerate = false) => {
    const message = prompt.trim();
    if (!message || loading || (chatStatus.blocked_until && new Date(chatStatus.blocked_until).getTime() > Date.now())) return;

    if (!regenerate) {
      setMessages(prev => [...prev, { role: 'user', content: message }]);
      setInput('');
    }

    setLoading(true);
    setScanStep(0);
    scanIntervalRef.current = window.setInterval(() => setScanStep(step => (step + 1) % 3), 700);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await axios.post(
        'http://127.0.0.1:8000/api/chat',
        { message, conversation_id: conversationId || null },
        { signal: controller.signal },
      );
      const d = res.data;
      if (d.conversation_id && d.conversation_id !== conversationId) {
        setConversationId(d.conversation_id);
        setSearchParams({ conversation: d.conversation_id }, { replace: true });
      }
      setChatStatus(current => ({
        ...current,
        consecutive_count: d.consecutive_count ?? current.consecutive_count,
        warning_threshold: d.warning_threshold ?? current.warning_threshold,
        block_threshold: d.block_threshold ?? current.block_threshold,
        blocked_until: d.blocked_until ?? null,
        is_chat_blocked: Boolean(d.blocked_until),
      }));
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: d.response,
        prompt: message,
        _blocked: d.classification === 'MALICIOUS',
      }]);
    } catch (err) {
      if (axios.isCancel(err) || err.name === 'CanceledError') {
        // User stopped generation — remove the pending user bubble if regenerate
        if (!regenerate) {
          setMessages(prev => prev.slice(0, -1));
          setInput(message);
        }
        return;
      }
      const detail = err.response?.data?.detail;
      if (err.response?.status === 429 && typeof detail === 'object') {
        setChatStatus(current => ({
          ...current,
          consecutive_count: detail.consecutive_count ?? current.consecutive_count,
          blocked_until: detail.blocked_until,
          is_chat_blocked: true,
        }));
      }
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: typeof detail === 'string' ? detail : detail?.message || 'Unable to process your request. Please try again.',
        isError: true,
        prompt: message,
        _blocked: false,
      }]);
    } finally {
      if (scanIntervalRef.current) {
        window.clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
      abortRef.current = null;
      setLoading(false);
    }
  };

  // Edit: start editing a user message at index
  const startEdit = (idx, content) => {
    if (loading) return;
    setEditState({ index: idx, value: content });
  };

  // Edit: confirm — remove all messages from that index onward, resend
  const confirmEdit = async () => {
    if (!editState) return;
    const { index, value } = editState;
    const trimmed = value.trim();
    if (!trimmed) return;
    // Keep messages before the edited user bubble, replace it with new content
    setMessages(prev => prev.slice(0, index));
    setEditState(null);
    await sendMessage(trimmed, false);
  };

  const cancelEdit = () => setEditState(null);

  const onKey = (e) => {
    if (preferences.sendOnEnter && e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const onEditKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); confirmEdit(); }
    if (e.key === 'Escape') cancelEdit();
  };

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
        <div>
          <span className="eyebrow">PRIVATE AI SECURITY SESSION</span>
          <h1>Secure AI Chat Console</h1>
          <p>Prompts are analyzed before they reach the assistant.</p>
        </div>
        <div className="chat-header-actions">
          <button className="chat-clear-button" onClick={clearChat} disabled={loading || messages.length <= 1} aria-label="Start a new chat">
            <Trash2 size={15} /> New chat
          </button>
        </div>
      </header>

      {chatStatus.consecutive_count >= chatStatus.warning_threshold && !isChatBlocked && (
        <div className="chat-threat-warning" role="alert">
          <ShieldAlert size={17} />
          <span><strong>Security Warning: {chatStatus.consecutive_count} consecutive malicious prompts detected.</strong> Admin has been notified. Further attempts may temporarily restrict chat access.</span>
        </div>
      )}

      {isChatBlocked && (
        <div className="chat-block-banner" role="alert">
          <ShieldX size={20} />
          <div>
            <strong>Chat Temporarily Blocked</strong>
            <span>{chatStatus.consecutive_count} consecutive malicious prompts were detected. Your chat access has been temporarily restricted.</span>
            <CountdownTimer until={chatStatus.blocked_until} onExpire={onBlockExpired} />
          </div>
        </div>
      )}

      {openingConversation && <LoadingState label="Opening conversation..." compact />}

      {messages.map((msg, idx) => (
        <div key={idx} style={{ width: '100%', display: 'flex', flexDirection: 'column' }}>
          {msg.role === 'user' && (
            editState?.index === idx ? (
              // Inline edit mode
              <div className="chat-bubble user" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <textarea
                  autoFocus
                  value={editState.value}
                  onChange={e => setEditState(s => ({ ...s, value: e.target.value }))}
                  onKeyDown={onEditKey}
                  rows={Math.min(6, editState.value.split('\n').length + 1)}
                  style={{
                    width: '100%', background: 'transparent', border: '1px solid var(--accent-gold)',
                    borderRadius: 6, color: 'var(--text-primary)', fontFamily: 'inherit',
                    fontSize: 'inherit', padding: '6px 8px', resize: 'vertical', outline: 'none',
                  }}
                />
                <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                  <button
                    onClick={confirmEdit}
                    disabled={!editState.value.trim()}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px', fontSize: '0.75rem', background: 'var(--accent-gold)', color: '#000', border: 'none', borderRadius: 5, cursor: 'pointer', fontWeight: 600 }}
                  >
                    <Check size={13} /> Send
                  </button>
                  <button
                    onClick={cancelEdit}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '4px 10px', fontSize: '0.75rem', background: 'transparent', color: 'var(--text-secondary)', border: '1px solid var(--border-color)', borderRadius: 5, cursor: 'pointer' }}
                  >
                    <X size={13} /> Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ position: 'relative', alignSelf: 'flex-end', maxWidth: '80%' }}>
                <div className="chat-bubble user">{msg.content}</div>
                {!loading && (
                  <button
                    onClick={() => startEdit(idx, msg.content)}
                    title="Edit message"
                    style={{
                      position: 'absolute', bottom: -4, right: 0,
                      background: 'none', border: 'none', cursor: 'pointer',
                      color: 'var(--text-secondary)', opacity: 0.6, padding: '2px 4px',
                      display: 'flex', alignItems: 'center', gap: 3, fontSize: '0.68rem',
                    }}
                    onMouseEnter={e => e.currentTarget.style.opacity = '1'}
                    onMouseLeave={e => e.currentTarget.style.opacity = '0.6'}
                  >
                    <Pencil size={11} /> Edit
                  </button>
                )}
              </div>
            )
          )}

          {msg.role === 'assistant' && (
            <div style={{ alignSelf: 'flex-start', maxWidth: '80%' }}>
              <div className={`chat-bubble ai${msg.isError ? ' error' : ''}`}>
                {msg.isError && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#ef4444', fontSize: '0.8rem', marginBottom: '8px' }}>
                    <ShieldAlert size={15} /> REQUEST FAILED
                  </div>
                )}
                {msg.content}
              </div>
              {msg.prompt && !msg._blocked && (
                <button className="chat-retry-button" onClick={() => sendMessage(msg.prompt, true)} disabled={loading}>
                  <RotateCcw size={13} /> {msg.isError ? 'Retry prompt' : 'Regenerate response'}
                </button>
              )}
            </div>
          )}
        </div>
      ))}

      {loading && (
        <div className="chat-scan-state" role="status" aria-live="polite">
          <div className="chat-bubble ai scan-bubble">
            <LoadingState label="SENTINEL is analyzing..." compact />
            <div className="scan-steps">
              {['Scanning content', 'Checking intent', 'Evaluating risk'].map((step, index) => (
                <span className={scanStep === index ? 'scan-step-active' : ''} key={step}><i /> {step}</span>
              ))}
            </div>
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
          disabled={loading || isChatBlocked || openingConversation || editState !== null}
        />
        {loading ? (
          <button
            className="send-btn"
            onClick={stopGeneration}
            title="Stop generation"
            aria-label="Stop generation"
            style={{ background: 'rgba(239,68,68,0.15)', borderColor: '#ef4444' }}
          >
            <Square size={16} fill="currentColor" color="#ef4444" />
          </button>
        ) : (
          <button
            className="send-btn"
            onClick={sendMessage}
            disabled={isChatBlocked || openingConversation || !input.trim() || editState !== null}
          >
            <Send size={18} />
          </button>
        )}
      </div>
    </div>
  );
}
