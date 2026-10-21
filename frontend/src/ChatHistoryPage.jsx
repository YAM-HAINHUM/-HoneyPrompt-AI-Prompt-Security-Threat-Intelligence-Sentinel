import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { ArrowLeft, ArrowRight, MessageSquare, Pencil, Plus, Search, ShieldAlert, ShieldCheck, ShieldX, Trash2, UserRound, X } from 'lucide-react';
import LoadingState from './LoadingState';
import MarkdownMessage from './MarkdownMessage';
import { useAuth } from './AuthContext';

const API = 'http://127.0.0.1:8000';
const authH = () => { const t = localStorage.getItem('hp_token'); return t ? { Authorization: `Bearer ${t}` } : {}; };

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
  const { user } = useAuth();
  const isAdmin = user?.role?.toLowerCase() === 'admin';
  const [conversations, setConversations] = useState([]);
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminUsername, setAdminUsername] = useState('');
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState(null);
  const [adminConversationRefresh, setAdminConversationRefresh] = useState(0);
  const [editingId, setEditingId] = useState('');
  const [editTitle, setEditTitle] = useState('');
  const [loading, setLoading] = useState(true);
  const [opening, setOpening] = useState(false);
  const [error, setError] = useState('');

  const loadConversations = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/api/user/conversations`, { headers: authH() });
      setConversations(response.data);
      setError('');
    } catch (requestError) {
      if (requestError.response?.status !== 401)
        setError(requestError.response?.data?.detail || 'Chat history could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAdminUsers = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/api/admin/users`, { headers: authH() });
      setAdminUsers(response.data);
      setError('');
    } catch (requestError) {
      if (requestError.response?.status !== 401)
        setError(requestError.response?.data?.detail || 'User accounts could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAdmin) {
      loadAdminUsers();
    } else {
      loadConversations();
      // Auto-refresh user conversation list every 15s so new messages appear
      const id = window.setInterval(loadConversations, 15000);
      const onNewChat = () => loadConversations();
      window.addEventListener('hp-data-refresh', onNewChat);
      return () => {
        window.clearInterval(id);
        window.removeEventListener('hp-data-refresh', onNewChat);
      };
    }
  }, [isAdmin, loadAdminUsers, loadConversations]);

  // Refresh admin user list on new security events
  useEffect(() => {
    if (!isAdmin) return undefined;
    const onRefresh = () => loadAdminUsers();
    window.addEventListener('hp-data-refresh', onRefresh);
    window.addEventListener('hp-admin-alert', onRefresh);
    return () => {
      window.removeEventListener('hp-data-refresh', onRefresh);
      window.removeEventListener('hp-admin-alert', onRefresh);
    };
  }, [isAdmin, loadAdminUsers]);

  useEffect(() => {
    if (!isAdmin || !adminUsername) return undefined;
    let active = true;
    const loadAdminConversations = async () => {
      setLoading(true);
      try {
            const response = await axios.get(`${API}/api/admin/users/${encodeURIComponent(adminUsername)}/conversations`, { headers: authH() });
        if (!active) return;
        const items = response.data.map(conversation => {
          const messages = conversation.messages || [];
          const classifications = messages.map(message => message.classification || 'SAFE');
          return {
            ...conversation,
            messages,
            first_prompt_preview: messages[0]?.prompt || '',
            message_count: messages.length,
            security_status: classifications.includes('MALICIOUS')
              ? 'MALICIOUS'
              : classifications.includes('SUSPICIOUS') ? 'SUSPICIOUS' : 'SAFE',
          };
        });
        setConversations(items);
        setDetail(current => {
          if (!current) return current;
          const updated = items.find(item => item.conversation_id === current.conversation.conversation_id);
          return updated ? { conversation: updated, messages: updated.messages } : current;
        });
        setError('');
      } catch (requestError) {
        if (active) setError(requestError.response?.data?.detail || 'Conversations could not be refreshed.');
      } finally {
        if (active) setLoading(false);
      }
    };
    loadAdminConversations();
    const intervalId = window.setInterval(loadAdminConversations, 15000);
    return () => {
      active = false;
      window.clearInterval(intervalId);
    };
  }, [isAdmin, adminUsername, adminConversationRefresh]);

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return conversations;
    return conversations.filter(item => `${item.title} ${item.first_prompt_preview}`.toLowerCase().includes(term));
  }, [conversations, query]);

  const openConversation = async id => {
    setSelectedId(id);
    if (isAdmin) {
      const conversation = conversations.find(item => item.conversation_id === id);
      if (conversation) setDetail({ conversation, messages: conversation.messages });
      return;
    }
    setOpening(true);
    setDetail(null);
    setError('');
    try {
      const response = await axios.get(`${API}/api/user/conversations/${encodeURIComponent(id)}`, { headers: authH() });
      setDetail(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'This conversation could not be opened.');
    } finally {
      setOpening(false);
    }
  };

  // Keep open user conversation detail in sync with list refreshes
  useEffect(() => {
    if (isAdmin || !selectedId || !detail) return undefined;
    const refreshDetail = async () => {
      try {
        const response = await axios.get(`${API}/api/user/conversations/${encodeURIComponent(selectedId)}`, { headers: authH() });
        setDetail(response.data);
      } catch { /* silent */ }
    };
    const onNewChat = () => refreshDetail();
    window.addEventListener('hp-data-refresh', onNewChat);
    return () => window.removeEventListener('hp-data-refresh', onNewChat);
  }, [isAdmin, selectedId, detail]);

  const saveRename = async id => {
    if (isAdmin) return;
    const title = editTitle.trim();
    if (!title) return;
    try {
      const response = await axios.patch(`${API}/api/user/conversations/${encodeURIComponent(id)}`, { title }, { headers: authH() });
      setConversations(items => items.map(item => item.conversation_id === id ? { ...item, title: response.data.title } : item));
      if (detail?.conversation.conversation_id === id) setDetail(current => ({ ...current, conversation: response.data }));
      setEditingId('');
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'The conversation could not be renamed.');
    }
  };

  const removeConversation = async item => {
    if (isAdmin) return;
    if (!window.confirm(`Delete “${item.title}” and its messages?`)) return;
    try {
      await axios.delete(`${API}/api/user/conversations/${encodeURIComponent(item.conversation_id)}`, { headers: authH() });
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
        <div><span className="eyebrow">{isAdmin ? 'AUTHORIZED ADMIN REVIEW' : 'PRIVATE CONVERSATIONS'}</span><h1>Chat History</h1><p>{isAdmin ? 'Review saved conversations for user accounts.' : 'Your saved conversations and message-level security analysis.'}</p></div>
        {!isAdmin && <button className="btn-primary history-new-chat" onClick={() => navigate('/')}><Plus size={15} /> Start New Chat</button>}
      </header>
      {error && <div className="auth-error" role="alert"><span>{error}</span><button className="icon-button" onClick={() => isAdmin ? adminUsername ? setAdminConversationRefresh(value => value + 1) : loadAdminUsers() : selectedId ? openConversation(selectedId) : loadConversations()} aria-label="Retry loading chat history">Retry</button></div>}
      <div className="conversation-layout">
        <section className="card conversation-list-panel" aria-label="Saved conversations">
          {isAdmin && <label className="conversation-search"><UserRound size={15} /><select value={adminUsername} onChange={event => { setAdminUsername(event.target.value); setSelectedId(''); setDetail(null); }} aria-label="Choose a user to review"><option value="">Select a user</option>{adminUsers.map(account => <option key={account.username} value={account.username}>{account.full_name ? `${account.full_name} · ` : ''}{account.username}</option>)}</select></label>}
          <label className="conversation-search"><Search size={15} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search conversations" aria-label="Search conversations" /></label>
          {loading ? <div className="conversation-skeletons">{[1, 2, 3, 4].map(item => <div className="conversation-skeleton" key={item} />)}</div> : isAdmin && !adminUsername ? <div className="conversation-empty"><UserRound size={22} /><strong>Select a user</strong><span>Choose an account above to review its saved conversations.</span></div> : filtered.length === 0 ? <div className="conversation-empty"><MessageSquare size={22} /><strong>{query ? 'No matching conversations' : isAdmin ? 'No saved conversations' : 'No conversations yet'}</strong><span>{query ? 'Try a different search.' : isAdmin ? 'No saved chats are available for this account.' : 'Start a secure chat to build your history.'}</span>{!query && !isAdmin && <button className="text-action" onClick={() => navigate('/')}>Open Secure Chat <ArrowRight size={13} /></button>}</div> : filtered.map(item => (
            <article className={`conversation-list-item${selectedId === item.conversation_id ? ' conversation-list-item-active' : ''}`} key={item.conversation_id}>
              <button className="conversation-open" onClick={() => openConversation(item.conversation_id)}>
                <span className="conversation-item-top"><strong>{item.title || 'New Chat'}</strong><SecurityMark status={item.security_status} /></span>
                <span className="conversation-preview">{item.first_prompt_preview || 'No messages yet'}</span>
                <span className="conversation-item-meta">{item.message_count} messages · {new Date(item.updated_at).toLocaleString()}</span>
              </button>
              {!isAdmin && (editingId === item.conversation_id ? <div className="conversation-edit-row"><input autoFocus value={editTitle} onChange={event => setEditTitle(event.target.value)} onKeyDown={event => event.key === 'Enter' && saveRename(item.conversation_id)} aria-label="Conversation title" /><button onClick={() => saveRename(item.conversation_id)} aria-label="Save title"><ArrowRight size={14} /></button><button onClick={() => setEditingId('')} aria-label="Cancel rename"><X size={14} /></button></div> : <div className="conversation-item-actions"><button onClick={() => { setEditingId(item.conversation_id); setEditTitle(item.title); }} title="Rename conversation" aria-label={`Rename ${item.title}`}><Pencil size={13} /></button><button onClick={() => removeConversation(item)} title="Delete conversation" aria-label={`Delete ${item.title}`}><Trash2 size={13} /></button></div>)}
            </article>
          ))}
        </section>

        <section className="card conversation-detail-panel" aria-label="Conversation messages">
          {!selectedId ? <div className="conversation-detail-empty"><MessageSquare size={28} /><strong>Select a conversation</strong><span>Open a saved conversation to review its messages and security analysis.</span></div> : opening ? <LoadingState label="Opening conversation..." compact /> : detail ? <>
            <header className="conversation-detail-header"><div><span className="eyebrow">{isAdmin ? `${adminUsername} · ` : ''}{detail.messages.length} MESSAGES</span><h2>{detail.conversation.title}</h2></div><div className="conversation-detail-actions">{!isAdmin && <button className="btn-secondary" onClick={() => navigate(`/?conversation=${encodeURIComponent(selectedId)}`)}><ArrowRight size={14} /> Continue chat</button>}<button className="icon-button" onClick={() => { setSelectedId(''); setDetail(null); }} aria-label="Close conversation"><X size={17} /></button></div></header>
            <div className="conversation-message-list">{detail.messages.map(message => <article className="saved-message" key={message.message_id}>
              <div className="saved-message-user"><span>You</span><p>{message.prompt}</p><time>{new Date(message.timestamp).toLocaleString()}</time></div>
              <div className="saved-message-assistant"><span>SENTINEL</span><div className="markdown-content"><MarkdownMessage content={message.response} /></div><div className="saved-message-analysis"><SecurityMark status={message.classification} /><span>{message.threat_type}</span><span>{message.severity}</span><span>{typeof message.confidence === 'number' ? `${Math.round(message.confidence * 100)}% confidence` : 'Confidence unavailable'}</span><span>Action: {message.action}</span></div>{message.reason && <small>{message.reason}</small>}</div>
            </article>)}</div>
          </> : <div className="conversation-detail-empty"><MessageSquare size={28} /><strong>Conversation unavailable</strong><span>It may have been deleted. Refresh the history list and try again.</span><button className="text-action" onClick={loadConversations}><ArrowLeft size={13} /> Refresh history</button></div>}
        </section>
      </div>
    </div>
  );
}