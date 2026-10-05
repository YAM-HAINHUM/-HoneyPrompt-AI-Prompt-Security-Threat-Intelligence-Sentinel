import { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertTriangle, ShieldCheck, ShieldX, Activity, Shield, Eye, Users, LockKeyhole, UserCheck, ShieldAlert, Check, ArrowUpRight } from 'lucide-react';
import { useAuth } from './AuthContext';
import LoadingState from './LoadingState';

const CLF_COLOR = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' };
const CLF_ICON = { SAFE: '🟢', SUSPICIOUS: '🟡', MALICIOUS: '🔴' };

function StatCard({ label, value, color, icon: Icon, loading = false }) {
  return (
    <div className="card stat-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>{label}</div>
          <div style={{ fontSize: '2rem', fontWeight: 'bold', color: color || 'var(--text-primary)' }}>{loading ? <i className="stat-value-skeleton" /> : value}</div>
        </div>
        {Icon && <Icon size={28} color={color || 'var(--text-secondary)'} style={{ opacity: 0.6 }} />}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { user } = useAuth();
  const isAdmin = user?.role?.toLowerCase() === 'admin';
  const [stats, setStats] = useState({ total: 0, safe: 0, suspicious: 0, malicious: 0, blocked: 0, critical: 0, high: 0, medium: 0 });
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedUserLogs, setSelectedUserLogs] = useState([]);
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const [sRes, lRes, aRes] = await Promise.all([
          axios.get(`http://127.0.0.1:8000${isAdmin ? '/api/admin/stats' : '/api/user/stats'}`),
          isAdmin ? axios.get('http://127.0.0.1:8000/api/logs') : axios.get('http://127.0.0.1:8000/api/user/history', { params: { page: 1, page_size: 100 } }),
          axios.get(`http://127.0.0.1:8000${isAdmin ? '/api/admin/alerts' : '/api/user/alerts'}`),
        ]);
        setStats(sRes.data);
        setLogs(isAdmin ? lRes.data.slice().reverse().slice(0, 20) : lRes.data.items);
        setAlerts(aRes.data.slice(0, 8));
        if (isAdmin) {
          const usersResponse = await axios.get('http://127.0.0.1:8000/api/admin/users');
          setUsers(usersResponse.data);
        }
      } catch (error) {
        setNotice(error.response?.data?.detail || 'Dashboard data could not be refreshed.');
      } finally {
        setLoading(false);
      }
    };
    fetchDashboard();
    const id = setInterval(fetchDashboard, 10000);
    return () => clearInterval(id);
  }, [isAdmin]);

  const updateUserAccess = async (target, field) => {
    try {
      const nextValue = field === 'is_active' ? target.is_active === false : !target.is_blocked;
      const response = await axios.patch(`http://127.0.0.1:8000/api/admin/users/${encodeURIComponent(target.username)}/access`, { [field]: nextValue });
      setUsers(current => current.map(item => item.username === target.username ? response.data : item));
    } catch (error) {
      setNotice(error.response?.data?.detail || 'Could not update account access.');
    }
  };

  const viewUserActivity = async (target) => {
    setSelectedUser(target);
    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/admin/users/${encodeURIComponent(target.username)}/logs`);
      setSelectedUserLogs(response.data);
    } catch (error) {
      setNotice(error.response?.data?.detail || 'Could not load account security history.');
    }
  };

  const reportFalsePositive = async (entry) => {
    try {
      await axios.post(`http://127.0.0.1:8000/api/user/logs/${encodeURIComponent(entry.request_id)}/false-positive`, { reason: 'Reported from personal security history' });
      setLogs(current => current.map(log => log.request_id === entry.request_id ? { ...log, false_positive_report: { reported_at: new Date().toISOString() } } : log));
      setNotice('False-positive report sent to the security team.');
    } catch (error) {
      setNotice(error.response?.data?.detail || 'Could not submit the report.');
    }
  };

  const threatLevel = stats.malicious > 0 ? 'ATTENTION REQUIRED' : 'PROTECTED';
  const threatColor = stats.malicious > 0 ? '#ef4444' : '#10b981';
  const averageConfidence = logs.length ? logs.reduce((sum, entry) => sum + (entry.confidence || 0), 0) / logs.length : 0;
  const safeRate = stats.total ? stats.safe / stats.total : 1;
  const suspiciousRate = stats.total ? stats.suspicious / stats.total : 0;
  const maliciousRate = stats.total ? stats.malicious / stats.total : 0;
  const securityScore = Math.max(0, Math.min(100, Math.round(safeRate * 100 - suspiciousRate * 10 - maliciousRate * 25)));
  const activityDays = Array.from({ length: 7 }, (_, index) => {
    const date = new Date();
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - 6 + index);
    const dayEvents = logs.filter(entry => new Date(entry.timestamp).toDateString() === date.toDateString());
    return { date, total: dayEvents.length, malicious: dayEvents.filter(entry => entry.classification === 'MALICIOUS').length, suspicious: dayEvents.filter(entry => entry.classification === 'SUSPICIOUS').length };
  });
  const maxActivity = Math.max(1, ...activityDays.map(day => day.total));

  return (
    <div className={`role-dashboard ${isAdmin ? 'admin-dashboard' : 'user-dashboard'}`}>
      <header className="role-page-heading">
        <div><span className="eyebrow">{isAdmin ? 'SYSTEM-WIDE VISIBILITY' : `PERSONAL SECURITY / ${user?.username || 'USER'}`}</span><h1>{isAdmin ? 'Admin Security Overview' : 'Your security overview'}</h1><p>{isAdmin ? 'Monitor platform activity, account access and active threats.' : 'A private view of your prompt activity and security events.'}</p></div>
        <span className={`role-label ${isAdmin ? 'role-label-admin' : 'role-label-user'}`}>{isAdmin ? <><Shield size={14} /> ADMIN PANEL</> : <><UserCheck size={14} /> USER PANEL</>}</span>
      </header>

      <div className="status-banner card">
        <span className={`status-emblem ${stats.malicious > 0 ? 'status-alert' : ''}`}>{stats.malicious > 0 ? <ShieldAlert size={21} /> : <ShieldCheck size={21} />}</span>
        <div><span className="eyebrow">{isAdmin ? 'PLATFORM POSTURE' : 'PERSONAL SECURITY STATUS'}</span><strong style={{ color: loading ? 'var(--text-secondary)' : threatColor }}>{loading ? 'ASSESSING...' : threatLevel}</strong></div>
        <span className="status-updated">LAST ACTIVITY {logs[0]?.timestamp ? new Date(logs[0].timestamp).toLocaleString() : 'NO PROMPTS YET'}</span>
      </div>

      <div className="role-stat-grid">
        {isAdmin && <StatCard label="Total Users" value={stats.total_users || 0} icon={Users} />}
        {isAdmin && <StatCard label="Active Users" value={stats.active_users || 0} color="#10b981" icon={UserCheck} />}
        <StatCard label={isAdmin ? 'Total Prompts' : 'Prompts Submitted'} value={stats.total} icon={Activity} loading={loading} />
        <StatCard label="Safe" value={stats.safe} color="#10b981" icon={ShieldCheck} loading={loading} />
        <StatCard label="Suspicious" value={stats.suspicious} color="#f59e0b" icon={Eye} loading={loading} />
        <StatCard label="Malicious" value={stats.malicious} color="#ef4444" icon={ShieldX} loading={loading} />
        <StatCard label="Blocked" value={stats.blocked} color="#ef4444" icon={AlertTriangle} loading={loading} />
        {!isAdmin && <StatCard label="Avg. Detection Confidence" value={logs.length ? `${(averageConfidence * 100).toFixed(1)}%` : '—'} color="#d7ad22" icon={ShieldCheck} loading={loading} />}
      </div>

      {notice && <div className="dashboard-notice" role="status"><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss message">×</button></div>}

      {isAdmin ? <>
        <div className="dashboard-content-grid">
          <section className="card security-events-panel">
            <div className="panel-heading"><div><span className="eyebrow">LIVE SECURITY</span><h2>Recent security alerts</h2></div><span className="panel-count">{alerts.length} recent</span></div>
            {alerts.length === 0 ? <p className="empty-state">No malicious activity recorded.</p> : alerts.slice(0, 5).map(alert => (
              <article className={`security-event-row${alert.repeated_malicious_activity ? ' multiple-attempts-alert' : ''}`} key={alert.request_id}>
                <span className="event-icon event-icon-danger"><ShieldX size={16} /></span>
                <div className="event-details"><strong>{alert.repeated_malicious_activity ? `Repeated malicious activity · ${alert.consecutive_count} consecutive` : alert.threat_type}</strong><span>{alert.user} · {alert.severity} · {new Date(alert.timestamp).toLocaleString()}</span>{alert.repeated_malicious_activity && <p>{alert.latest_prompt_preview} · {alert.current_action}</p>}</div>
                <span className="event-severity">{alert.severity}</span>
              </article>
            ))}
          </section>
          <section className="card analytics-summary-panel">
            <div className="panel-heading"><div><span className="eyebrow">THREAT ANALYTICS</span><h2>Prompt classification</h2></div></div>
            {[['Safe', stats.safe, '#10b981'], ['Suspicious', stats.suspicious, '#f59e0b'], ['Malicious', stats.malicious, '#ef4444']].map(([label, value, color]) => <div className="mini-metric" key={label}><div><span>{label}</span><strong>{value}</strong></div><div className="mini-track"><i style={{ width: `${stats.total ? Math.max(2, value / stats.total * 100) : 0}%`, background: color }} /></div></div>)}
          </section>
        </div>

        <section className="card user-management-panel">
          <div className="panel-heading"><div><span className="eyebrow">ACCESS GOVERNANCE</span><h2>User management</h2></div><span className="panel-count">{users.length} accounts</span></div>
          <div className="table-scroll"><table className="role-table"><thead><tr><th>Account</th><th>Role</th><th>Status</th><th>Activity</th><th>Controls</th></tr></thead><tbody>
            {users.map(target => <tr key={target.username}>
              <td><strong>{target.full_name || target.username}</strong><span>{target.email}</span></td>
              <td>{target.role}</td>
              <td><span className={`account-state${target.is_blocked || target.is_active === false ? ' account-state-blocked' : ''}`}>{target.is_blocked ? 'Blocked' : target.is_active === false ? 'Inactive' : 'Active'}</span></td>
              <td><button className="text-action" onClick={() => viewUserActivity(target)}>View history <ArrowUpRight size={13} /></button></td>
              <td>{target.role?.toLowerCase() === 'admin' ? <span className="protected-label"><LockKeyhole size={13} /> Protected</span> : <div className="access-actions">
                <button onClick={() => updateUserAccess(target, 'is_active')} aria-label={`${target.is_active === false ? 'Activate' : 'Deactivate'} ${target.username}`}>{target.is_active === false ? 'Activate' : 'Deactivate'}</button>
                <button onClick={() => updateUserAccess(target, 'is_blocked')} aria-label={`${target.is_blocked ? 'Unblock' : 'Block'} ${target.username}`}>{target.is_blocked ? 'Unblock' : 'Block'}</button>
              </div>}</td>
            </tr>)}
          </tbody></table></div>
        </section>

        {selectedUser && <section className="card selected-user-history">
          <div className="panel-heading"><div><span className="eyebrow">ACCOUNT SECURITY HISTORY</span><h2>{selectedUser.full_name || selectedUser.username}</h2></div><button className="icon-button" onClick={() => setSelectedUser(null)} aria-label="Close user history">×</button></div>
          {selectedUserLogs.length ? selectedUserLogs.slice(0, 8).map(entry => <div className="security-event-row" key={entry.request_id}><span className={`event-icon event-icon-${entry.classification?.toLowerCase()}`}><Activity size={15} /></span><div className="event-details"><strong>{entry.classification} · {entry.threat_type}</strong><span>{new Date(entry.timestamp).toLocaleString()} · {entry.action} · {entry.confidence ? `${Math.round(entry.confidence * 100)}% confidence` : 'confidence unavailable'}</span></div></div>) : <p className="empty-state">No activity recorded for this account.</p>}
        </section>}

        <section className="card security-events-panel"><div className="panel-heading"><div><span className="eyebrow">SYSTEM AUDIT</span><h2>Latest prompt activity</h2></div><span className="panel-count">Recent events</span></div>
          {logs.length ? logs.slice(0, 8).map(entry => <div className="security-event-row" key={entry.request_id}><span className={`event-icon event-icon-${entry.classification?.toLowerCase()}`}><Activity size={15} /></span><div className="event-details"><strong>{entry.classification} · {entry.threat_type}</strong><span>{entry.user} · {new Date(entry.timestamp).toLocaleString()}</span></div><span className="event-severity">{entry.action}</span></div>) : <p className="empty-state">Waiting for prompt activity.</p>}
        </section>
      </> : <>
        <div className="personal-insights-grid">
          <section className="card security-score-card">
            <div className="panel-heading"><div><span className="eyebrow">PERSONAL POSTURE</span><h2>Security score</h2></div></div>
            {loading ? <LoadingState label="Calculating your score..." compact /> : <>
              <div className="score-dial" style={{ '--score-angle': `${securityScore * 3.6}deg` }} role="img" aria-label={`Informational security score ${securityScore} out of 100`}><div><strong>{securityScore}</strong><span>/ 100</span></div></div>
              <p className="score-disclaimer">An informational snapshot of your recent prompt classifications, not a judgment of you.</p>
              <div className="score-factors"><span><i className="factor-safe" /> Safe interaction rate <b>{Math.round(safeRate * 100)}%</b></span><span><i className="factor-suspicious" /> Suspicious attempts <b>{stats.suspicious}</b></span><span><i className="factor-malicious" /> Blocked malicious prompts <b>{stats.blocked}</b></span></div>
            </>}
          </section>
          <section className="card personal-activity-chart">
            <div className="panel-heading"><div><span className="eyebrow">YOUR ACTIVITY</span><h2>Last 7 days</h2></div></div>
            {loading ? <LoadingState label="Loading your activity..." compact /> : <>
              <div className="personal-chart-bars" role="img" aria-label="Personal prompt activity over the last seven days">
                {activityDays.map(day => <div className="personal-chart-day" key={day.date.toISOString()} title={`${day.total} prompts`}><span>{day.total || ''}</span><div><i className="personal-bar-safe" style={{ height: `${day.total ? (day.total - day.malicious - day.suspicious) / maxActivity * 100 : 0}%` }} /><i className="personal-bar-suspicious" style={{ height: `${day.suspicious / maxActivity * 100}%` }} /><i className="personal-bar-malicious" style={{ height: `${day.malicious / maxActivity * 100}%` }} /></div><small>{day.date.toLocaleDateString(undefined, { weekday: 'short' })}</small></div>)}
              </div>
              <div className="personal-chart-legend"><span><i className="personal-bar-safe" /> Safe</span><span><i className="personal-bar-suspicious" /> Suspicious</span><span><i className="personal-bar-malicious" /> Malicious</span></div>
              <p className="personal-last-activity">Last activity: {logs[0]?.timestamp ? new Date(logs[0].timestamp).toLocaleString() : 'No prompts submitted yet'}</p>
            </>}
          </section>
        </div>
        <section className="card security-events-panel personal-history-panel">
          <div className="panel-heading"><div><span className="eyebrow">PRIVATE ACTIVITY</span><h2>Your prompt history</h2></div><span className="panel-count">{logs.length} recent</span></div>
          {loading ? <LoadingState label="Loading your prompt history..." compact /> : logs.length === 0 ? <p className="empty-state">Your prompt history will appear here after your first secure chat.</p> : logs.slice(0, 5).map(entry => <article className="personal-history-row" key={entry.request_id}>
            <span className={`event-icon event-icon-${entry.classification?.toLowerCase()}`}><Activity size={15} /></span>
            <div className="event-details"><strong>{entry.threat_type || 'Unclassified'} <span className={`classification-label classification-${entry.classification?.toLowerCase() || 'unclassified'}`}>{entry.classification || 'UNCLASSIFIED'}</span></strong><span>{new Date(entry.timestamp).toLocaleString()} · {entry.action || '—'} · {entry.severity || '—'} · {entry.confidence ? `${Math.round(entry.confidence * 100)}% confidence` : 'confidence unavailable'}</span><p>{entry.prompt_preview}</p>{entry.reason && <small>Reason: {entry.reason}</small>}</div>
            {entry.classification !== 'SAFE' && <button className="report-button" onClick={() => reportFalsePositive(entry)} disabled={Boolean(entry.false_positive_report)}>{entry.false_positive_report ? <><Check size={14} /> Reported</> : 'Report false positive'}</button>}
          </article>)}
        </section>
        <section className="card personal-alerts-panel"><div className="panel-heading"><div><span className="eyebrow">PERSONAL ALERTS</span><h2>Recent security alerts</h2></div></div>
          {loading ? <LoadingState label="Loading your alerts..." compact /> : alerts.length === 0 ? <p className="empty-state">No recent threats detected in your activity.</p> : alerts.slice(0, 5).map(alert => <article className="security-event-row" key={alert.request_id}><span className="event-icon event-icon-danger"><ShieldAlert size={15} /></span><div className="event-details"><strong>{alert.threat_type}</strong><span>{alert.severity} · {Math.round((alert.confidence || 0) * 100)}% confidence · {new Date(alert.timestamp).toLocaleString()}</span></div><span className="event-severity">{alert.action}</span></article>)}
        </section>
      </>}
    </div>
  );
}
