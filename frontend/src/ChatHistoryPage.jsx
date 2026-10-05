import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { ArrowLeft, ArrowRight, MessageSquare, Pencil, Plus, Search, ShieldAlert, ShieldCheck, ShieldX, Trash2, X } from 'lucide-react';
import LoadingState from './LoadingState';

const API = 'http://127.0.0.1:8000';

function SecurityMark({ status }) {
  const config = {
    SAFE: { icon: ShieldCheck, label: 'Safe', className: 'safe' },
    SUSPICIOUS: { icon: ShieldAlert, label: 'Suspicious', className: 'suspicious' },
    MALICIOUS: { icon: ShieldX, label: 'Malicious', className: 'malicious' },
  }[status] || { icon: ShieldCheck, label: 'Safe', className: 'safe' };
  const Icon = config.icon;
  return <span className={`conversation-security conversation-security-${config.className}`}><Icon size={13} /> {config.label}</span>;
}

export default function ChatHistoryPage() {
  const navigate = useNavigate();
  const [conversations, setConversations] = useState([]);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState(null);
  const [editingId, setEditingId] = useState('');
  const [editTitle, setEditTitle] = useState('');
  const [loading, setLoading] = useState(true);
  const [opening, setOpening] = useState(false);
  const [error, setError] = useState('');

  const loadConversations = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/api/user/conversations`);
      setConversations(response.data);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Chat history could not be loaded.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadConversations(); }, []);

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return conversations;
    return conversations.filter(item => `${item.title} ${item.first_prompt_preview}`.toLowerCase().includes(term));
  }, [conversations, query]);

  const openConversation = async id => {
    setSelectedId(id);
    setOpening(true);
    setDetail(null);
    setError('');
    try {
      const response = await axios.get(`${API}/api/user/conversations/${encodeURIComponent(id)}`);
      setDetail(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'This conversation could not be opened.');
    } finally {
      setOpening(false);
    }
  };

  const saveRename = async id => {
    const title = editTitle.trim();
    if (!title) return;
    try {
      const response = await axios.patch(`${API}/api/user/conversations/${encodeURIComponent(id)}`, { title });
      setConversations(items => items.map(item => item.conversation_id === id ? { ...item, title: response.data.title } : item));
      if (detail?.conversation.conversation_id === id) setDetail(current => ({ ...current, conversation: response.data }));
      setEditingId('');
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'The conversation could not be renamed.');
    }
  };

  const removeConversation = async item => {
    if (!window.confirm(`Delete “${item.title}” and its messages?`)) return;
    try {
      await axios.delete(`${API}/api/user/conversations/${encodeURIComponent(item.conversation_id)}`);
      setConversations(items => items.filter(conversation => conversation.conversation_id !== item.conversation_id));
      if (selectedId === item.conversation_id) {
        setSelectedId('');
        setDetail(null);
      }
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'The conversation could not be deleted.');
    }
  };

  return (
    <div className="role-dashboard chat-history-page">
      <header className="role-page-heading">
        <div><span className="eyebrow">PRIVATE CONVERSATIONS</span><h1>Chat History</h1><p>Your saved conversations and message-level security analysis.</p></div>
        <button className="btn-primary history-new-chat" onClick={() => navigate('/')}><Plus size={15} /> Start New Chat</button>
      </header>
      {error && <div className="auth-error" role="alert"><span>{error}</span><button className="icon-button" onClick={() => selectedId ? openConversation(selectedId) : loadConversations()} aria-label="Retry loading chat history">Retry</button></div>}
      <div className="conversation-layout">
        <section className="card conversation-list-panel" aria-label="Saved conversations">
          <label className="conversation-search"><Search size={15} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search conversations" aria-label="Search conversations" /></label>
          {loading ? <div className="conversation-skeletons">{[1, 2, 3, 4].map(item => <div className="conversation-skeleton" key={item} />)}</div> : filtered.length === 0 ? <div className="conversation-empty"><MessageSquare size={22} /><strong>{query ? 'No matching conversations' : 'No conversations yet'}</strong><span>{query ? 'Try a different search.' : 'Start a secure chat to build your history.'}</span>{!query && <button className="text-action" onClick={() => navigate('/')}>Open Secure Chat <ArrowRight size={13} /></button>}</div> : filtered.map(item => (
            <article className={`conversation-list-item${selectedId === item.conversation_id ? ' conversation-list-item-active' : ''}`} key={item.conversation_id}>
              <button className="conversation-open" onClick={() => openConversation(item.conversation_id)}>
                <span className="conversation-item-top"><strong>{item.title || 'New Chat'}</strong><SecurityMark status={item.security_status} /></span>
                <span className="conversation-preview">{item.first_prompt_preview || 'No messages yet'}</span>
                <span className="conversation-item-meta">{item.message_count} messages · {new Date(item.updated_at).toLocaleString()}</span>
              </button>
              {editingId === item.conversation_id ? <div className="conversation-edit-row"><input autoFocus value={editTitle} onChange={event => setEditTitle(event.target.value)} onKeyDown={event => event.key === 'Enter' && saveRename(item.conversation_id)} aria-label="Conversation title" /><button onClick={() => saveRename(item.conversation_id)} aria-label="Save title"><ArrowRight size={14} /></button><button onClick={() => setEditingId('')} aria-label="Cancel rename"><X size={14} /></button></div> : <div className="conversation-item-actions"><button onClick={() => { setEditingId(item.conversation_id); setEditTitle(item.title); }} title="Rename conversation" aria-label={`Rename ${item.title}`}><Pencil size={13} /></button><button onClick={() => removeConversation(item)} title="Delete conversation" aria-label={`Delete ${item.title}`}><Trash2 size={13} /></button></div>}
            </article>
          ))}
        </section>

        <section className="card conversation-detail-panel" aria-label="Conversation messages">
          {!selectedId ? <div className="conversation-detail-empty"><MessageSquare size={28} /><strong>Select a conversation</strong><span>Open a saved conversation to review its messages and security analysis.</span></div> : opening ? <LoadingState label="Opening conversation..." compact /> : detail ? <>
            <header className="conversation-detail-header"><div><span className="eyebrow">{detail.messages.length} MESSAGES</span><h2>{detail.conversation.title}</h2></div><div className="conversation-detail-actions"><button className="btn-secondary" onClick={() => navigate(`/?conversation=${encodeURIComponent(selectedId)}`)}><ArrowRight size={14} /> Continue chat</button><button className="icon-button" onClick={() => { setSelectedId(''); setDetail(null); }} aria-label="Close conversation"><X size={17} /></button></div></header>
            <div className="conversation-message-list">{detail.messages.map(message => <article className="saved-message" key={message.message_id}>
              <div className="saved-message-user"><span>You</span><p>{message.prompt}</p><time>{new Date(message.timestamp).toLocaleString()}</time></div>
              <div className="saved-message-assistant"><span>SENTINEL</span><p>{message.response}</p><div className="saved-message-analysis"><SecurityMark status={message.classification} /><span>{message.threat_type}</span><span>{message.severity}</span><span>{typeof message.confidence === 'number' ? `${Math.round(message.confidence * 100)}% confidence` : 'Confidence unavailable'}</span><span>Action: {message.action}</span></div>{message.reason && <small>{message.reason}</small>}</div>
            </article>)}</div>
          </> : <div className="conversation-detail-empty"><MessageSquare size={28} /><strong>Conversation unavailable</strong><span>It may have been deleted. Refresh the history list and try again.</span><button className="text-action" onClick={loadConversations}><ArrowLeft size={13} /> Refresh history</button></div>}
        </section>
      </div>
    </div>
  );
}