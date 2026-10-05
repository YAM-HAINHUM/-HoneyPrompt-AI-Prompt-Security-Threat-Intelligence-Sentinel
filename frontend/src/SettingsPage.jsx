import { useState, useEffect } from 'react';
import axios from 'axios';
import { Link, useNavigate } from 'react-router-dom';
import { useTheme } from './ThemeContext';
import { useAuth } from './AuthContext';
import { Moon, Sun, Shield, User, Server, Bell, Activity, SlidersHorizontal, MessageSquare, LogOut, ArrowRight, Save, ShieldAlert } from 'lucide-react';
import LoadingState from './LoadingState';
import CountdownTimer from './CountdownTimer';

const defaultPreferences = { inAppAlerts: true, compactChat: false, sendOnEnter: true };

function getUserPreferences(username) {
  try {
    return { ...defaultPreferences, ...JSON.parse(localStorage.getItem(`hp_user_preferences_${username}`) || '{}') };
  } catch {
    return defaultPreferences;
  }
}

export default function SettingsPage() {
  const { theme, toggle } = useTheme();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const isAdmin = user?.role?.toLowerCase() === 'admin';
  const [preferences, setPreferences] = useState(() => getUserPreferences(user?.username || 'guest'));
  const [status, setStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [securitySettings, setSecuritySettings] = useState({ warning_threshold: 3, block_threshold: 5, block_cooldown_minutes: 15 });
  const [chatActivity, setChatActivity] = useState([]);
  const [blockDurations, setBlockDurations] = useState({});
  const [activityLoading, setActivityLoading] = useState(true);
  const [activityError, setActivityError] = useState('');
  const [blockReasons, setBlockReasons] = useState({});
  const [selectedChatUser, setSelectedChatUser] = useState(null);
  const [adminConversations, setAdminConversations] = useState([]);
  const [conversationsLoading, setConversationsLoading] = useState(false);

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/status').then(r => setStatus(r.data)).catch(() => setStatus(null)).finally(() => setStatusLoading(false));
  }, []);

  useEffect(() => {
    if (!isAdmin) return undefined;
    Promise.all([
      axios.get('http://127.0.0.1:8000/api/admin/security-settings'),
      axios.get('http://127.0.0.1:8000/api/admin/chat-activity'),
    ]).then(([settingsResponse, activityResponse]) => {
      setSecuritySettings(settingsResponse.data);
      setChatActivity(activityResponse.data);
      setActivityError('');
    }).catch(error => setActivityError(error.response?.data?.detail || 'Repeated activity controls could not be loaded.'))
      .finally(() => setActivityLoading(false));
    return undefined;
  }, [isAdmin]);

  const updatePreference = (name, value) => {
    const next = { ...preferences, [name]: value };
    setPreferences(next);
    localStorage.setItem(`hp_user_preferences_${user?.username || 'guest'}`, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent('hp-user-preferences', { detail: next }));
  };

  const signOut = async () => { await logout(); navigate('/login', { replace: true }); };

  const saveSecuritySettings = async event => {
    event.preventDefault();
    try {
      const response = await axios.patch('http://127.0.0.1:8000/api/admin/security-settings', securitySettings);
      setSecuritySettings(response.data);
      setActivityError('Protection thresholds saved.');
    } catch (error) {
      setActivityError(error.response?.data?.detail || 'Security thresholds could not be saved.');
    }
  };

  const updateChatBlock = async (target, durationMinutes, reason = '') => {
    try {
      const response = await axios.patch(`http://127.0.0.1:8000/api/admin/users/${encodeURIComponent(target.username)}/chat-block`, { duration_minutes: durationMinutes, reason });
      setChatActivity(items => items.map(item => item.username === target.username ? { ...item, ...response.data } : item));
      setActivityError(durationMinutes === 0 ? `${target.username} was unblocked.` : `Chat restriction updated for ${target.username}.`);
    } catch (error) {
      setActivityError(error.response?.data?.detail || 'Chat restriction could not be updated.');
    }
  };

  const refreshChatActivity = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/admin/chat-activity');
      setChatActivity(response.data);
    } catch (error) {
      setActivityError(error.response?.data?.detail || 'Chat block status could not be refreshed.');
    }
  };

  const viewCompleteChats = async target => {
    if (selectedChatUser?.username === target.username) {
      setSelectedChatUser(null);
      setAdminConversations([]);
      return;
    }
    setSelectedChatUser(target);
    setAdminConversations([]);
    setConversationsLoading(true);
    setActivityError('');
    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/admin/users/${encodeURIComponent(target.username)}/conversations`);
      setAdminConversations(response.data);
    } catch (error) {
      setActivityError(error.response?.data?.detail || 'Complete conversations could not be loaded.');
    } finally {
      setConversationsLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', maxWidth: isAdmin ? '1440px' : '700px' }}>

      {/* Appearance */}
      <div className="card">
        <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {theme === 'dark' ? <Moon size={15} /> : <Sun size={15} />} Appearance
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ color: 'var(--text-primary)', fontWeight: '500' }}>Theme</div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>Current: {theme === 'dark' ? '🌙 Dark' : '☀️ Light'}</div>
          </div>
          <button onClick={toggle} style={{ padding: '8px 20px', borderRadius: '8px', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', color: 'var(--text-primary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.9rem' }}>
            {theme === 'dark' ? <><Sun size={15} /> Switch to Light</> : <><Moon size={15} /> Switch to Dark</>}
          </button>
        </div>
      </div>

      {/* Account */}
      <div className="card">
        <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <User size={15} /> Account
        </h3>
        {user && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 20px', fontSize: '0.85rem', marginBottom: '20px' }}>
            {[['Full Name', user.full_name], ['Username', user.username], ['Email', user.email], ['Role', user.role], ['Last Login', user.last_login ? new Date(user.last_login).toLocaleString() : 'N/A']].map(([k, v]) => (
              <div key={k}>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginBottom: '2px' }}>{k}</div>
                <div style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{v}</div>
              </div>
            ))}
          </div>
        )}
        <div className="settings-account-actions"><Link to="/profile" className="text-action">Manage profile and password <ArrowRight size={14} /></Link><button type="button" className="settings-logout" onClick={signOut}><LogOut size={14} /> Sign out</button></div>
      </div>

      <div className="card settings-policy-card">
        <h3><SlidersHorizontal size={15} /> Detection &amp; notifications</h3>
        {[
          ['Detection engine', 'Active', 'Live prompt classification is enabled'],
          ['Detection sensitivity', 'System managed', 'Uses the active server-side detection rules'],
          ['Threat notifications', 'In-app', 'Security alerts appear in your authorized notification feed'],
        ].map(([label, value, description]) => <div className="settings-policy-row" key={label}>
          <div><strong>{label}</strong><span>{description}</span></div><span className="policy-state"><Bell size={13} /> {value}</span>
        </div>)}
      </div>

      <div className="card settings-preferences-card">
        <h3><Bell size={15} /> Personal preferences</h3>
        <label className="settings-toggle-row"><span><strong>In-app security alerts</strong><small>Show your private Sentinel alert feed and unread count.</small></span><input type="checkbox" checked={preferences.inAppAlerts} onChange={event => updatePreference('inAppAlerts', event.target.checked)} /></label>
        <label className="settings-toggle-row"><span><strong>Compact chat layout</strong><small>Reduce message spacing in Secure Chat.</small></span><input type="checkbox" checked={preferences.compactChat} onChange={event => updatePreference('compactChat', event.target.checked)} /></label>
        <label className="settings-toggle-row"><span><strong>Send with Enter</strong><small>Press Enter to send, or turn off to use the send button only.</small></span><input type="checkbox" checked={preferences.sendOnEnter} onChange={event => updatePreference('sendOnEnter', event.target.checked)} /></label>
        <p className="settings-local-note"><MessageSquare size={13} /> These display preferences are stored on this device; detection and enforcement remain server-managed.</p>
      </div>

      {isAdmin && <>
      <section className="card repeated-protection-card">
        <h3><ShieldAlert size={15} /> Continuous malicious activity protection</h3>
        <form className="protection-settings-form" onSubmit={saveSecuritySettings}>
          <label>Warning threshold<input type="number" min="1" max="20" value={securitySettings.warning_threshold} onChange={event => setSecuritySettings(current => ({ ...current, warning_threshold: Number(event.target.value) }))} /></label>
          <label>Block threshold<input type="number" min="2" max="25" value={securitySettings.block_threshold} onChange={event => setSecuritySettings(current => ({ ...current, block_threshold: Number(event.target.value) }))} /></label>
          <label>Block duration (minutes)<input type="number" min="1" max="1440" value={securitySettings.block_cooldown_minutes} onChange={event => setSecuritySettings(current => ({ ...current, block_cooldown_minutes: Number(event.target.value) }))} /></label>
          <button className="btn-primary" type="submit"><Save size={14} /> Save protection settings</button>
        </form>
        <p className="settings-local-note">A safe or non-malicious prompt resets the per-user consecutive count. Block threshold must exceed warning threshold.</p>
      </section>

      <section className="card repeated-activity-card">
        <div className="panel-heading"><div><span className="eyebrow">ADMIN SECURITY RESPONSE</span><h2>Repeated malicious activity</h2></div><span className="panel-count">{chatActivity.length} user accounts</span></div>
        {activityError && <div className="dashboard-notice" role="status"><span>{activityError}</span></div>}
        {activityLoading ? <LoadingState label="Loading repeated activity..." compact /> : chatActivity.length === 0 ? <p className="empty-state">No user accounts are available.</p> : <div className="table-scroll"><table className="role-table repeated-activity-table"><thead><tr><th>Account</th><th>Consecutive threats</th><th>Chat status</th><th>Block reason</th><th>Block timeline</th><th>Threat history</th><th>Complete chats</th><th>Controls</th></tr></thead><tbody>
          {chatActivity.map(target => <tr key={target.user_id}>
            <td><strong>{target.username}</strong><span>{target.email || target.user_id}</span><span>ID: {target.user_id}</span></td>
            <td><span className={target.consecutive_count >= securitySettings.warning_threshold ? 'activity-count-alert' : ''}>{target.consecutive_count}</span></td>
            <td><span className={`account-state${target.is_chat_blocked ? ' account-state-blocked' : ''}`}>{target.is_chat_blocked ? 'Temporarily blocked' : 'Available'}</span></td>
            <td>{target.is_chat_blocked ? <div className="admin-block-reason"><strong>{target.block_reason || 'Reason not recorded'}</strong><span>{target.block_source === 'automatic' ? 'Automatic protection' : `Manual · ${target.blocked_by || 'Administrator'}`}</span></div> : '—'}</td>
            <td>{target.blocked_until ? <div className="admin-block-timeline"><strong>Until {new Date(target.blocked_until).toLocaleString()}</strong><span>Started {target.blocked_at ? new Date(target.blocked_at).toLocaleString() : 'time unavailable'}</span>{target.is_chat_blocked && <CountdownTimer key={`${target.user_id}-${target.blocked_until}`} until={target.blocked_until} onExpire={refreshChatActivity} />}</div> : '—'}</td>
            <td><details className="activity-history-details"><summary>{target.threat_history.length} malicious events</summary>{target.threat_history.slice(0, 5).map(event => <div className="activity-history-event" key={event.request_id}><strong>{event.consecutive_count || 1} consecutive · {event.threat_type}</strong><span>{event.latest_prompt_preview || event.prompt_preview}</span><small>{event.severity} · {Math.round((event.confidence || 0) * 100)}% · {event.current_action || event.action} · {new Date(event.timestamp).toLocaleString()}</small></div>)}</details></td>
            <td><button className="text-action" onClick={() => viewCompleteChats(target)}>{selectedChatUser?.username === target.username ? 'Close chats' : 'View complete chats'} <ArrowRight size={13} /></button></td>
            <td><div className="activity-admin-controls"><input aria-label={`Block duration for ${target.username}`} type="number" min="1" max="1440" value={blockDurations[target.username] ?? securitySettings.block_cooldown_minutes} onChange={event => setBlockDurations(current => ({ ...current, [target.username]: Number(event.target.value) }))} /><input aria-label={`Block reason for ${target.username}`} placeholder="Reason for restriction" value={blockReasons[target.username] || ''} onChange={event => setBlockReasons(current => ({ ...current, [target.username]: event.target.value }))} /><button className="btn-secondary" onClick={() => updateChatBlock(target, blockDurations[target.username] ?? securitySettings.block_cooldown_minutes, blockReasons[target.username] || '')}>{target.is_chat_blocked ? 'Extend / reduce' : 'Restrict'}</button>{target.is_chat_blocked && <button className="activity-unblock-button" onClick={() => updateChatBlock(target, 0)}>Unblock</button>}</div></td>
          </tr>)}
        </tbody></table></div>}
      </section>

      {selectedChatUser && <section className="card admin-chat-transcripts">
        <div className="panel-heading"><div><span className="eyebrow">AUTHORIZED SECURITY REVIEW</span><h2>Complete chats · {selectedChatUser.username}</h2></div><button className="icon-button" onClick={() => { setSelectedChatUser(null); setAdminConversations([]); }} aria-label="Close complete chats">×</button></div>
        {conversationsLoading ? <LoadingState label="Loading complete conversations..." compact /> : adminConversations.length === 0 ? <p className="empty-state">No saved conversations are available for this account.</p> : <div className="admin-chat-transcript-list">{adminConversations.map(conversation => <article className="admin-chat-transcript" key={conversation.conversation_id}>
          <header><div><strong>{conversation.title}</strong><span>{conversation.messages.length} messages · Last activity {new Date(conversation.updated_at).toLocaleString()}</span></div><span className="transcript-conversation-id">{conversation.conversation_id}</span></header>
          {conversation.messages.map(message => <section className="admin-transcript-message" key={message.message_id}>
            <div><span>User prompt</span><p>{message.prompt}</p></div>
            <div><span>SENTINEL response</span><p>{message.response}</p></div>
            <footer><strong>{message.classification}</strong><span>{message.threat_type}</span><span>{message.severity}</span><span>{Math.round((message.confidence || 0) * 100)}% confidence</span><span>Action: {message.action}</span><time>{new Date(message.timestamp).toLocaleString()}</time>{message.reason && <span>Reason: {message.reason}</span>}</footer>
          </section>)}
        </article>)}</div>}
      </section>}
      {/* Security Settings */}
      <div className="card">
        <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={15} /> Security Settings
        </h3>
        {[
          { label: 'Automatic Blocking', desc: 'Block MALICIOUS prompts before reaching LLM', value: true },
          { label: 'Suspicious Monitoring', desc: 'Log and monitor SUSPICIOUS prompts', value: true },
          { label: 'Audit Logging', desc: 'Log all requests to audit trail', value: true },
        ].map(s => (
          <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border-color)' }}>
            <div>
              <div style={{ color: 'var(--text-primary)', fontSize: '0.9rem' }}>{s.label}</div>
              <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{s.desc}</div>
            </div>
            <span className="policy-state policy-enforced"><Activity size={13} /> ENFORCED</span>
          </div>
        ))}
      </div>
      </>}

      {/* System Status */}
      <div className="card">
        <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Server size={15} /> System Status
        </h3>
        {statusLoading ? <LoadingState label="Checking HoneyPrompt services..." compact /> : <>
        {[
          { label: 'Backend API', value: status ? '● Online' : '● Offline', color: status ? '#10b981' : '#ef4444' },
          { label: 'LLM Provider', value: status?.provider || 'Unknown', color: 'var(--text-primary)' },
          { label: 'LLM Key', value: status?.llm_key_configured ? '● Configured' : '● Missing', color: status?.llm_key_configured ? '#10b981' : '#ef4444' },
          { label: 'Detection Engine', value: '● Active', color: '#10b981' },
        ].map(s => (
          <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.85rem' }}>
            <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
            <span style={{ color: s.color, fontWeight: '500' }}>{s.value}</span>
          </div>
        ))}
        </>}
      </div>

    </div>
  );
}
