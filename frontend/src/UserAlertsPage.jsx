import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { Bell, CheckCheck, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react';
import LoadingState from './LoadingState';

function alertIcon(classification) {
  if (classification === 'MALICIOUS') return ShieldAlert;
  if (classification === 'SUSPICIOUS') return TriangleAlert;
  return ShieldCheck;
}

export default function UserAlertsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role?.toLowerCase() === 'admin';
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const endpoint = isAdmin ? '/api/admin/alerts' : '/api/user/alerts';
      const response = await axios.get(`http://127.0.0.1:8000${endpoint}`);
      setAlerts(response.data);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Security alerts could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    const timer = window.setTimeout(refresh, 0);
    const intervalId = window.setInterval(refresh, 15000);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(intervalId);
    };
  }, [refresh]);

  const markRead = async alert => {
    if (isAdmin || alert.is_read) return;
    try {
      await axios.post(`http://127.0.0.1:8000/api/user/alerts/${encodeURIComponent(alert.request_id)}/read`);
      setAlerts(current => current.map(item => item.request_id === alert.request_id ? { ...item, is_read: true } : item));
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'This alert could not be marked as read.');
    }
  };

  const markAllRead = async () => {
    const unread = alerts.filter(alert => !alert.is_read);
    const results = await Promise.allSettled(unread.map(alert => axios.post(`http://127.0.0.1:8000/api/user/alerts/${encodeURIComponent(alert.request_id)}/read`)));
    const completed = new Set(unread.filter((_, index) => results[index].status === 'fulfilled').map(alert => alert.request_id));
    setAlerts(current => current.map(alert => completed.has(alert.request_id) ? { ...alert, is_read: true } : alert));
    if (results.some(result => result.status === 'rejected')) setError('Some alerts could not be marked as read.');
  };

  const unreadCount = alerts.filter(alert => !alert.is_read).length;
  const maliciousAlerts = alerts.filter(alert => alert.classification === 'MALICIOUS');

  return (
    <div className="role-dashboard user-alerts-page">
      <header className="role-page-heading"><div><span className="eyebrow">PERSONAL SECURITY FEED</span><h1>Security Alerts</h1><p>Threat events detected in your own prompt activity.</p></div><span className="role-label role-label-user"><Bell size={14} /> {unreadCount} UNREAD</span></header>
      {error && <div className="auth-error" role="alert">{error}</div>}
      <section className="card alerts-list-card">
        <div className="panel-heading"><div><span className="eyebrow">YOUR NOTIFICATIONS</span><h2>Recent security events</h2></div>{!isAdmin && unreadCount > 0 && <button className="btn-secondary" onClick={markAllRead}><CheckCheck size={14} /> Mark all read</button>}</div>
        {loading ? <LoadingState label="Loading your security alerts..." compact /> : alerts.length === 0 ? <p className="empty-state">No security alerts for your account.</p> : <>
          {maliciousAlerts.length >= 3 && <article className="personal-alert-row multiple-attempts-alert">
            <span className="event-icon event-icon-danger"><ShieldAlert size={17} /></span>
            <div className="event-details"><strong>Multiple attack attempts detected</strong><span>{maliciousAlerts.length} malicious prompts were blocked in your recent activity.</span><p>Sentinel blocked these requests before they reached the AI assistant.</p></div>
            {!isAdmin && maliciousAlerts.some(alert => !alert.is_read) && <button className="alert-read-control" onClick={markAllRead}>Mark read</button>}
          </article>}
          {alerts.map(alert => {
          const Icon = alertIcon(alert.classification);
          return <article className={`personal-alert-row${alert.is_read ? ' alert-is-read' : ' alert-is-unread'}`} key={alert.request_id}>
            <span className={`event-icon event-icon-${alert.classification?.toLowerCase()}`}><Icon size={17} /></span>
            <div className="event-details"><strong>{alert.classification === 'MALICIOUS' ? 'Malicious prompt blocked' : alert.classification === 'SUSPICIOUS' ? 'Suspicious activity detected' : 'Security notification'}</strong><span>{alert.threat_type} · {alert.severity} · {Math.round((alert.confidence || 0) * 100)}% confidence · {new Date(alert.timestamp).toLocaleString()}</span><p>{alert.reason || `Prompt classified ${alert.classification} and ${alert.action?.toLowerCase()} by Sentinel.`}</p></div>
            {!isAdmin && <button className="alert-read-control" disabled={alert.is_read} onClick={() => markRead(alert)}>{alert.is_read ? <><CheckCheck size={14} /> Read</> : 'Mark read'}</button>}
          </article>;
          })}
        </>}
      </section>
    </div>
  );
}