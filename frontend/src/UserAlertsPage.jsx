import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { Bell, CheckCheck, ShieldAlert, ShieldCheck, TriangleAlert, X, Megaphone, RefreshCw } from 'lucide-react';
import LoadingState from './LoadingState';

const API = 'http://127.0.0.1:8000';

const authH = () => {
  const t = localStorage.getItem('hp_token');
  return t ? { Authorization: `Bearer ${t}` } : {};
};

const PRIORITY_STYLE = {
  info:    { bg: 'rgba(59,130,246,0.10)', border: '#3b82f6', icon: '#3b82f6', label: 'INFO' },
  warning: { bg: 'rgba(245,158,11,0.10)', border: '#f59e0b', icon: '#f59e0b', label: 'NOTICE' },
  danger:  { bg: 'rgba(239,68,68,0.10)',  border: '#ef4444', icon: '#ef4444', label: 'URGENT' },
  success: { bg: 'rgba(16,185,129,0.10)', border: '#10b981', icon: '#10b981', label: 'UPDATE' },
};

function alertIcon(cls) {
  if (cls === 'MALICIOUS') return ShieldAlert;
  if (cls === 'SUSPICIOUS') return TriangleAlert;
  return ShieldCheck;
}

export default function UserAlertsPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState('notifications');

  // Notifications state
  const [notifs, setNotifs] = useState([]);
  const [nLoading, setNLoading] = useState(true);

  // Security alerts state
  const [alerts, setAlerts] = useState([]);
  const [aLoading, setALoading] = useState(true);
  const [error, setError] = useState('');

  const loadNotifs = useCallback(async () => {
    setNLoading(true);
    try {
      const res = await axios.get(`${API}/api/user/notifications`, { headers: authH() });
      setNotifs(res.data || []);
    } catch { setNotifs([]); }
    finally { setNLoading(false); }
  }, []);

  const loadAlerts = useCallback(async () => {
    setALoading(true);
    try {
      const res = await axios.get(`${API}/api/user/alerts`, { headers: authH() });
      setAlerts(res.data || []);
      setError('');
    } catch (e) {
      setError(e.response?.data?.detail || 'Could not load security alerts.');
    } finally { setALoading(false); }
  }, []);

  useEffect(() => {
    loadNotifs();
    loadAlerts();
    const id = setInterval(() => { loadNotifs(); loadAlerts(); }, 15000);
    const onRefresh = () => { loadNotifs(); loadAlerts(); };
    window.addEventListener('hp-data-refresh', onRefresh);
    const onVisible = () => { if (document.visibilityState === 'visible') { loadNotifs(); loadAlerts(); } };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(id);
      window.removeEventListener('hp-data-refresh', onRefresh);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [loadNotifs, loadAlerts]);

  const dismissNotif = async (id) => {
    try {
      await axios.post(`${API}/api/user/notifications/${id}/dismiss`, {}, { headers: authH() });
      setNotifs(prev => prev.filter(n => n.notification_id !== id));
    } catch { /* silent */ }
  };

  const readNotif = async (id) => {
    try {
      await axios.post(`${API}/api/user/notifications/${id}/read`, {}, { headers: authH() });
      setNotifs(prev => prev.map(n => n.notification_id === id ? { ...n, is_read: true } : n));
    } catch { /* silent */ }
  };

  const markAlertRead = async (alert) => {
    if (alert.is_read) return;
    try {
      await axios.post(`${API}/api/user/alerts/${encodeURIComponent(alert.request_id)}/read`, {}, { headers: authH() });
      setAlerts(prev => prev.map(a => a.request_id === alert.request_id ? { ...a, is_read: true } : a));
    } catch (e) { setError(e.response?.data?.detail || 'Could not mark alert as read.'); }
  };

  const markAllAlertsRead = async () => {
    const unread = alerts.filter(a => !a.is_read);
    await Promise.allSettled(unread.map(a =>
      axios.post(`${API}/api/user/alerts/${encodeURIComponent(a.request_id)}/read`, {}, { headers: authH() })
    ));
    setAlerts(prev => prev.map(a => ({ ...a, is_read: true })));
  };

  const unreadNotifs = notifs.filter(n => !n.is_read).length;
  const unreadAlerts = alerts.filter(a => !a.is_read).length;

  return (
    <div className="role-dashboard user-alerts-page">
      <header className="role-page-heading">
        <div>
          <span className="eyebrow">PERSONAL SECURITY FEED</span>
          <h1>Alerts & Notifications</h1>
          <p>Admin messages and security events for your account.</p>
        </div>
        <span className="role-label role-label-user">
          <Bell size={14} /> {unreadNotifs + unreadAlerts} UNREAD
        </span>
      </header>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => setTab('notifications')}
          style={{
            padding: '8px 18px', borderRadius: 6, border: `1px solid ${tab === 'notifications' ? 'var(--accent-gold)' : 'var(--border-color)'}`,
            background: tab === 'notifications' ? 'color-mix(in srgb, var(--accent-gold) 12%, var(--bg-card))' : 'var(--bg-card)',
            color: tab === 'notifications' ? 'var(--accent-gold)' : 'var(--text-secondary)',
            cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6,
          }}
        >
          <Megaphone size={14} /> Admin Notifications
          {unreadNotifs > 0 && (
            <span style={{ background: 'var(--accent-gold)', color: '#000', borderRadius: 10, padding: '1px 7px', fontSize: '0.65rem', fontWeight: 700 }}>
              {unreadNotifs}
            </span>
          )}
        </button>
        <button
          onClick={() => setTab('alerts')}
          style={{
            padding: '8px 18px', borderRadius: 6, border: `1px solid ${tab === 'alerts' ? 'var(--accent-gold)' : 'var(--border-color)'}`,
            background: tab === 'alerts' ? 'color-mix(in srgb, var(--accent-gold) 12%, var(--bg-card))' : 'var(--bg-card)',
            color: tab === 'alerts' ? 'var(--accent-gold)' : 'var(--text-secondary)',
            cursor: 'pointer', fontSize: '0.8rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6,
          }}
        >
          <ShieldAlert size={14} /> Security Alerts
          {unreadAlerts > 0 && (
            <span style={{ background: '#ef4444', color: '#fff', borderRadius: 10, padding: '1px 7px', fontSize: '0.65rem', fontWeight: 700 }}>
              {unreadAlerts}
            </span>
          )}
        </button>
      </div>

      {/* ── NOTIFICATIONS TAB ── */}
      {tab === 'notifications' && (
        <section className="card alerts-list-card">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">FROM ADMIN</span>
              <h2>Admin Notifications</h2>
            </div>
            <button className="btn-secondary" onClick={loadNotifs} style={{ padding: '6px 12px', fontSize: '0.72rem' }}>
              <RefreshCw size={13} style={{ marginRight: 5 }} /> Refresh
            </button>
          </div>

          {nLoading ? (
            <LoadingState label="Loading notifications..." compact />
          ) : notifs.length === 0 ? (
            <p className="empty-state">No notifications from admin.</p>
          ) : (
            notifs.map(n => {
              const ps = PRIORITY_STYLE[n.priority] || PRIORITY_STYLE.info;
              return (
                <div
                  key={n.notification_id}
                  onClick={() => !n.is_read && readNotif(n.notification_id)}
                  style={{
                    display: 'flex', gap: 14, padding: '14px 16px', marginBottom: 10,
                    background: ps.bg, border: `1px solid ${ps.border}`,
                    borderLeft: `4px solid ${ps.border}`, borderRadius: 8,
                    opacity: n.is_read ? 0.7 : 1, cursor: n.is_read ? 'default' : 'pointer',
                    transition: 'opacity 0.2s',
                  }}
                >
                  <Megaphone size={18} style={{ color: ps.icon, flexShrink: 0, marginTop: 2 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{n.title}</strong>
                      <span style={{ fontSize: '0.6rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: ps.border, color: '#fff' }}>
                        {ps.label}
                      </span>
                      {!n.is_read && (
                        <span style={{ fontSize: '0.6rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: 'var(--accent-gold)', color: '#000' }}>
                          NEW
                        </span>
                      )}
                    </div>
                    <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{n.message}</p>
                    <div style={{ marginTop: 6, fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                      From <b style={{ color: 'var(--text-primary)' }}>{n.sent_by}</b> · {new Date(n.created_at).toLocaleString()}
                      {n.updated_at && <span> · edited {new Date(n.updated_at).toLocaleString()}</span>}
                    </div>
                  </div>
                  <button
                    onClick={e => { e.stopPropagation(); dismissNotif(n.notification_id); }}
                    title="Dismiss"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', padding: 4, flexShrink: 0, alignSelf: 'flex-start' }}
                  >
                    <X size={15} />
                  </button>
                </div>
              );
            })
          )}
        </section>
      )}

      {/* ── SECURITY ALERTS TAB ── */}
      {tab === 'alerts' && (
        <section className="card alerts-list-card">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">YOUR NOTIFICATIONS</span>
              <h2>Recent security events</h2>
            </div>
            {unreadAlerts > 0 && (
              <button className="btn-secondary" onClick={markAllAlertsRead}>
                <CheckCheck size={14} /> Mark all read
              </button>
            )}
          </div>

          {error && <div className="auth-error" role="alert">{error}</div>}

          {aLoading ? (
            <LoadingState label="Loading security alerts..." compact />
          ) : alerts.length === 0 ? (
            <p className="empty-state">No security alerts for your account.</p>
          ) : (
            alerts.map(alert => {
              const Icon = alertIcon(alert.classification);
              return (
                <article
                  key={alert.request_id}
                  className={`personal-alert-row${alert.is_read ? ' alert-is-read' : ' alert-is-unread'}`}
                >
                  <span className={`event-icon event-icon-${alert.classification?.toLowerCase()}`}>
                    <Icon size={17} />
                  </span>
                  <div className="event-details">
                    <strong>
                      {alert.classification === 'MALICIOUS' ? 'Malicious prompt blocked'
                        : alert.classification === 'SUSPICIOUS' ? 'Suspicious activity detected'
                        : 'Security notification'}
                    </strong>
                    <span>
                      {alert.threat_type} · {alert.severity} · {Math.round((alert.confidence || 0) * 100)}% confidence · {new Date(alert.timestamp).toLocaleString()}
                    </span>
                    <p>{alert.reason || `Prompt classified ${alert.classification} and ${alert.action?.toLowerCase()} by Sentinel.`}</p>
                  </div>
                  <button
                    className="alert-read-control"
                    disabled={alert.is_read}
                    onClick={() => markAlertRead(alert)}
                  >
                    {alert.is_read ? <><CheckCheck size={14} /> Read</> : 'Mark read'}
                  </button>
                </article>
              );
            })
          )}
        </section>
      )}
    </div>
  );
}
