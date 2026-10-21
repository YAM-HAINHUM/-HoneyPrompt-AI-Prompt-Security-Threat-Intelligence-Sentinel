import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SevBadge, StatusBadge, SocPagination, SocNotice, fmtTime, fmtPct, SEV_COLOR } from './socUtils';
import { Megaphone, Pencil, Trash2, Send, RefreshCw, X } from 'lucide-react';

const STATUSES = ['', 'NEW', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'];
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const PRIORITIES = ['info', 'warning', 'danger', 'success'];
const PRIORITY_COLOR = { info: '#3b82f6', warning: '#f59e0b', danger: '#ef4444', success: '#10b981' };

const authH = () => {
  const t = localStorage.getItem('hp_token');
  return t ? { Authorization: `Bearer ${t}` } : {};
};

// ─── Security Alerts tab (unchanged logic) ───────────────────────────────────
function AlertsTab() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [expanded, setExpanded] = useState(null);
  const [noteText, setNoteText] = useState('');
  const [updating, setUpdating] = useState('');

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ page, page_size: 50, exclude_test: true });
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);
      if (userFilter) params.set('user', userFilter);
      const res = await axios.get(`${API}/api/soc/alerts?${params}`, { headers: authH() });
      setItems(res.data.items || []);
      setTotal(res.data.total || 0);
      setNotice({ msg: '', type: 'info' });
    } catch (e) {
      if (e.response?.status !== 401)
        setNotice({ msg: e.response?.data?.detail || 'Failed to load alerts', type: 'error' });
    } finally { setLoading(false); }
  }, [page, severity, status, userFilter]);

  useEffect(() => {
    setLoading(true);
    load();
    const id = setInterval(load, 8000);
    const onNew = () => { setLoading(true); load(); };
    window.addEventListener('hp-data-refresh', onNew);
    window.addEventListener('hp-admin-alert', onNew);
    const onVisible = () => { if (document.visibilityState === 'visible') { setLoading(true); load(); } };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(id);
      window.removeEventListener('hp-data-refresh', onNew);
      window.removeEventListener('hp-admin-alert', onNew);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [load]);

  const updateStatus = async (alertId, newStatus) => {
    setUpdating(alertId);
    try {
      await axios.patch(`${API}/api/soc/alerts/${alertId}`, { status: newStatus, note: noteText }, { headers: authH() });
      setNotice({ msg: `Alert marked as ${newStatus}`, type: 'success' });
      setNoteText(''); setExpanded(null); load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Update failed', type: 'error' });
    } finally { setUpdating(''); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      <SocCard style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
          <input className="search-input" placeholder="Filter by user..." value={userFilter}
            onChange={e => { setUserFilter(e.target.value); setPage(1); }} style={{ minWidth: 180 }} />
          <select className="search-input" value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
          </select>
          <select className="search-input" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}>
            {STATUSES.map(s => <option key={s} value={s}>{s || 'All Statuses'}</option>)}
          </select>
          <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{total} alerts</span>
        </div>
      </SocCard>

      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? <LoadingState label="Loading security alerts..." compact /> :
          items.length === 0 ? <p style={{ padding: 24, color: 'var(--text-secondary)', margin: 0 }}>No alerts match the current filters.</p> :
          items.map(a => (
            <div key={a.alert_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', cursor: 'pointer' }}
                onClick={() => setExpanded(expanded === a.alert_id ? null : a.alert_id)}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0, background: SEV_COLOR[a.severity] || '#64748b', boxShadow: `0 0 8px ${SEV_COLOR[a.severity] || '#64748b'}` }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <strong style={{ fontSize: '0.82rem' }}>{a.threat_type}</strong>
                    <SevBadge severity={a.severity} /><StatusBadge status={a.status} />
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                    {a.alert_id} · User: <b style={{ color: 'var(--text-primary)' }}>{a.user}</b> · {fmtPct(a.confidence)} · Risk: {a.risk_score} · {fmtTime(a.timestamp)}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.prompt_preview}</div>
                </div>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>{expanded === a.alert_id ? '▲' : '▼'}</span>
              </div>

              {expanded === a.alert_id && (
                <div style={{ padding: '0 18px 18px', background: 'var(--bg-deeper, var(--bg-dark))' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 14 }}>
                    {[['Alert ID', a.alert_id], ['Request ID', a.request_id], ['Session', a.session_id || '—'],
                      ['Action', a.action], ['Reason', a.reason], ['Categories', (a.categories || []).join(', ') || '—']
                    ].map(([k, v]) => (
                      <div key={k}>
                        <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 3 }}>{k}</div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>{v}</div>
                      </div>
                    ))}
                  </div>
                  {a.notes?.length > 0 && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 6, textTransform: 'uppercase' }}>Investigation Notes</div>
                      {a.notes.map((n, i) => (
                        <div key={i} style={{ padding: '6px 10px', background: 'var(--bg-card)', borderRadius: 6, marginBottom: 4, fontSize: '0.74rem' }}>
                          <span style={{ color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)', fontSize: '0.62rem' }}>{n.admin} · {fmtTime(n.ts)}</span>
                          <p style={{ margin: '3px 0 0', color: 'var(--text-primary)' }}>{n.note}</p>
                        </div>
                      ))}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    <input className="search-input" placeholder="Add investigation note..." value={noteText}
                      onChange={e => setNoteText(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
                    {['INVESTIGATING', 'RESOLVED', 'DISMISSED'].map(s => (
                      <button key={s} className="btn-secondary" disabled={updating === a.alert_id || a.status === s}
                        onClick={() => updateStatus(a.alert_id, s)} style={{ fontSize: '0.72rem', padding: '7px 12px' }}>{s}</button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        }
      </SocCard>
      <SocPagination page={page} total={total} pageSize={50} onPage={setPage} />
    </div>
  );
}

// ─── Notifications Manager tab ────────────────────────────────────────────────
function NotificationsTab() {
  const [notifs, setNotifs] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [users, setUsers] = useState([]);

  // compose form
  const [targetUser, setTargetUser] = useState('__all__');
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [priority, setPriority] = useState('info');
  const [sending, setSending] = useState(false);

  // edit state
  const [editId, setEditId] = useState(null);
  const [editTitle, setEditTitle] = useState('');
  const [editMessage, setEditMessage] = useState('');
  const [editPriority, setEditPriority] = useState('info');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [nr, ur] = await Promise.all([
        axios.get(`${API}/api/admin/notifications?page=1&page_size=100`, { headers: authH() }),
        axios.get(`${API}/api/admin/users`, { headers: authH() }),
      ]);
      setNotifs(nr.data.items || []);
      setTotal(nr.data.total || 0);
      setUsers((ur.data || []).filter(u => u.role?.toLowerCase() !== 'admin'));
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load', type: 'error' });
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const send = async () => {
    if (!title.trim() || !message.trim()) {
      setNotice({ msg: 'Title and message are required.', type: 'error' }); return;
    }
    setSending(true);
    try {
      await axios.post(`${API}/api/admin/notifications`, { target_user: targetUser, title, message, priority }, { headers: authH() });
      setNotice({ msg: `Notification sent to ${targetUser === '__all__' ? 'all users' : targetUser}.`, type: 'success' });
      setTitle(''); setMessage(''); setPriority('info'); setTargetUser('__all__');
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Send failed', type: 'error' });
    } finally { setSending(false); }
  };

  const startEdit = (n) => {
    setEditId(n.notification_id);
    setEditTitle(n.title);
    setEditMessage(n.message);
    setEditPriority(n.priority);
  };

  const saveEdit = async () => {
    setSaving(true);
    try {
      await axios.patch(`${API}/api/admin/notifications/${editId}`,
        { title: editTitle, message: editMessage, priority: editPriority }, { headers: authH() });
      setNotice({ msg: 'Notification updated.', type: 'success' });
      setEditId(null); load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Update failed', type: 'error' });
    } finally { setSaving(false); }
  };

  const del = async (id) => {
    if (!window.confirm('Delete this notification?')) return;
    try {
      await axios.delete(`${API}/api/admin/notifications/${id}`, { headers: authH() });
      setNotice({ msg: 'Notification deleted.', type: 'success' });
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Delete failed', type: 'error' });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {/* Compose */}
      <SocCard style={{ padding: '18px 20px', borderTop: '3px solid var(--accent-gold)' }}>
        <div className="eyebrow" style={{ marginBottom: 12 }}>SEND NEW NOTIFICATION</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>TARGET USER</label>
            <select className="search-input" value={targetUser} onChange={e => setTargetUser(e.target.value)} style={{ width: '100%' }}>
              <option value="__all__">📢 Broadcast to all users</option>
              {users.map(u => <option key={u.username} value={u.username}>{u.username} ({u.email})</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>PRIORITY</label>
            <select className="search-input" value={priority} onChange={e => setPriority(e.target.value)} style={{ width: '100%' }}>
              {PRIORITIES.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
            </select>
          </div>
        </div>
        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>TITLE</label>
          <input className="search-input" placeholder="Notification title..." value={title}
            onChange={e => setTitle(e.target.value)} style={{ width: '100%' }} />
        </div>
        <div style={{ marginBottom: 14 }}>
          <label style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>MESSAGE</label>
          <textarea className="search-input" placeholder="Write your message..." value={message}
            onChange={e => setMessage(e.target.value)}
            style={{ width: '100%', minHeight: 80, resize: 'vertical', fontFamily: 'inherit', fontSize: '0.82rem' }} />
        </div>
        <button className="btn-primary" onClick={send} disabled={sending}
          style={{ width: 'auto', padding: '9px 22px', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
          <Send size={14} /> {sending ? 'Sending...' : 'Send Notification'}
        </button>
      </SocCard>

      {/* Sent notifications list */}
      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="eyebrow">SENT NOTIFICATIONS ({total})</span>
          <button className="btn-secondary" onClick={load} style={{ padding: '5px 10px', fontSize: '0.7rem' }}>
            <RefreshCw size={12} style={{ marginRight: 4 }} /> Refresh
          </button>
        </div>

        {loading ? <LoadingState label="Loading notifications..." compact /> :
          notifs.length === 0 ? <p style={{ padding: 20, color: 'var(--text-secondary)', margin: 0 }}>No notifications sent yet.</p> :
          notifs.map(n => (
            <div key={n.notification_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
              {editId === n.notification_id ? (
                /* ── inline edit form ── */
                <div style={{ padding: '14px 18px', background: 'var(--bg-deeper, var(--bg-dark))' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                    <div>
                      <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 3 }}>TITLE</label>
                      <input className="search-input" value={editTitle} onChange={e => setEditTitle(e.target.value)} style={{ width: '100%' }} />
                    </div>
                    <div>
                      <label style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', display: 'block', marginBottom: 3 }}>PRIORITY</label>
                      <select className="search-input" value={editPriority} onChange={e => setEditPriority(e.target.value)} style={{ width: '100%' }}>
                        {PRIORITIES.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
                      </select>
                    </div>
                  </div>
                  <textarea className="search-input" value={editMessage} onChange={e => setEditMessage(e.target.value)}
                    style={{ width: '100%', minHeight: 70, resize: 'vertical', fontFamily: 'inherit', fontSize: '0.82rem', marginBottom: 10 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-primary" onClick={saveEdit} disabled={saving}
                      style={{ width: 'auto', padding: '7px 16px', fontSize: '0.78rem' }}>
                      {saving ? 'Saving...' : 'Save Changes'}
                    </button>
                    <button className="btn-secondary" onClick={() => setEditId(null)} style={{ padding: '7px 14px', fontSize: '0.78rem' }}>
                      <X size={13} style={{ marginRight: 4 }} /> Cancel
                    </button>
                  </div>
                </div>
              ) : (
                /* ── read row ── */
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, padding: '13px 18px' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: PRIORITY_COLOR[n.priority] || '#64748b', flexShrink: 0, marginTop: 6 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 3 }}>
                      <strong style={{ fontSize: '0.82rem' }}>{n.title}</strong>
                      <span style={{ fontSize: '0.6rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: PRIORITY_COLOR[n.priority], color: '#fff' }}>
                        {n.priority.toUpperCase()}
                      </span>
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                        → {n.target_user === '__all__' ? 'All Users' : n.target_user}
                      </span>
                    </div>
                    <p style={{ margin: '0 0 4px', fontSize: '0.76rem', color: 'var(--text-secondary)' }}>{n.message}</p>
                    <div style={{ fontSize: '0.62rem', color: 'var(--text-secondary)' }}>
                      {n.notification_id} · Sent {fmtTime(n.created_at)}
                      {n.updated_at && <span> · edited {fmtTime(n.updated_at)}</span>}
                      · Read by {n.read_by?.length || 0} · Dismissed by {n.dismissed_by?.length || 0}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button onClick={() => startEdit(n)} title="Edit"
                      style={{ background: 'none', border: '1px solid var(--border-color)', borderRadius: 5, padding: '5px 8px', cursor: 'pointer', color: 'var(--accent-gold)' }}>
                      <Pencil size={13} />
                    </button>
                    <button onClick={() => del(n.notification_id)} title="Delete"
                      style={{ background: 'none', border: '1px solid var(--border-color)', borderRadius: 5, padding: '5px 8px', cursor: 'pointer', color: '#ef4444' }}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))
        }
      </SocCard>
    </div>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────
export default function SOCAlerts() {
  const [tab, setTab] = useState('alerts');

  const tabBtn = (id, label, icon) => (
    <button onClick={() => setTab(id)} style={{
      padding: '8px 18px', borderRadius: 6, cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600,
      display: 'flex', alignItems: 'center', gap: 6,
      border: `1px solid ${tab === id ? 'var(--accent-gold)' : 'var(--border-color)'}`,
      background: tab === id ? 'color-mix(in srgb, var(--accent-gold) 12%, var(--bg-card))' : 'var(--bg-card)',
      color: tab === id ? 'var(--accent-gold)' : 'var(--text-secondary)',
    }}>{icon}{label}</button>
  );

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🚨" title="Alerts & Notifications" subtitle="Manage security alerts and send notifications to users" />

      <div style={{ display: 'flex', gap: 8 }}>
        {tabBtn('alerts', 'Security Alerts', '🛡️ ')}
        {tabBtn('notifications', 'Notifications Manager', <Megaphone size={14} />)}
      </div>

      {tab === 'alerts' && <AlertsTab />}
      {tab === 'notifications' && <NotificationsTab />}
    </div>
  );
}
