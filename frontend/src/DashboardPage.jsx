import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { AlertTriangle, ShieldCheck, ShieldX, Activity, Shield, Eye, Users, UserCheck, ShieldAlert, Check, ArrowUpRight } from 'lucide-react';
import { useAuth } from './AuthContext';
import LoadingState from './LoadingState';

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
  const [stats, setStats] = useState({ total: 0, safe: 0, suspicious: 0, malicious: 0, blocked: 0 });
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        const [sRes, lRes, aRes] = await Promise.all([
          axios.get(`http://127.0.0.1:8000${isAdmin ? '/api/admin/stats' : '/api/user/stats'}`),
          isAdmin
            ? axios.get('http://127.0.0.1:8000/api/logs')
            : axios.get('http://127.0.0.1:8000/api/user/history', { params: { page: 1, page_size: 20 } }),
          axios.get(`http://127.0.0.1:8000${isAdmin ? '/api/admin/alerts' : '/api/user/alerts'}`),
        ]);
        setStats(sRes.data);
        setLogs(isAdmin ? lRes.data.slice().reverse().slice(0, 10) : lRes.data.items);
        setAlerts(aRes.data.slice(0, 4));
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

  const reportFalsePositive = async (entry) => {
    try {
      await axios.post(`http://127.0.0.1:8000/api/user/logs/${encodeURIComponent(entry.request_id)}/false-positive`, { reason: 'Reported from dashboard' });
      setLogs(current => current.map(log => log.request_id === entry.request_id ? { ...log, false_positive_report: { reported_at: new Date().toISOString() } } : log));
      setNotice('False-positive report sent to the security team.');
    } catch (error) {
      setNotice(error.response?.data?.detail || 'Could not submit the report.');
    }
  };

  const threatLevel = stats.malicious > 0 ? 'ATTENTION REQUIRED' : 'PROTECTED';
  const threatColor = stats.malicious > 0 ? '#ef4444' : '#10b981';
  const averageConfidence = logs.length ? logs.reduce((sum, e) => sum + (e.confidence || 0), 0) / logs.length : 0;
  const safeRate = stats.total ? stats.safe / stats.total : 1;
  const suspiciousRate = stats.total ? stats.suspicious / stats.total : 0;
  const maliciousRate = stats.total ? stats.malicious / stats.total : 0;
  const securityScore = Math.max(0, Math.min(100, Math.round(safeRate * 100 - suspiciousRate * 10 - maliciousRate * 25)));
  const activityDays = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - 6 + i);
    const dayEvents = logs.filter(e => new Date(e.timestamp).toDateString() === date.toDateString());
    return { date, total: dayEvents.length, malicious: dayEvents.filter(e => e.classification === 'MALICIOUS').length, suspicious: dayEvents.filter(e => e.classification === 'SUSPICIOUS').length };
  });
  const maxActivity = Math.max(1, ...activityDays.map(d => d.total));

  return (
    <div className={`role-dashboard ${isAdmin ? 'admin-dashboard' : 'user-dashboard'}`}>
      <header className="role-page-heading">
        <div>
          <span className="eyebrow">{isAdmin ? 'SYSTEM-WIDE VISIBILITY' : `PERSONAL SECURITY / ${user?.username || 'USER'}`}</span>
          <h1>{isAdmin ? 'Admin Security Overview' : 'Your security overview'}</h1>
          <p>{isAdmin ? 'Monitor platform activity and active threats.' : 'A private view of your prompt activity and security events.'}</p>
        </div>
        <span className={`role-label ${isAdmin ? 'role-label-admin' : 'role-label-user'}`}>
          {isAdmin ? <><Shield size={14} /> ADMIN PANEL</> : <><UserCheck size={14} /> USER PANEL</>}
        </span>
      </header>

      <div className="status-banner card">
        <span className={`status-emblem ${stats.malicious > 0 ? 'status-alert' : ''}`}>
          {stats.malicious > 0 ? <ShieldAlert size={21} /> : <ShieldCheck size={21} />}
        </span>
        <div>
          <span className="eyebrow">{isAdmin ? 'PLATFORM POSTURE' : 'PERSONAL SECURITY STATUS'}</span>
          <strong style={{ color: loading ? 'var(--text-secondary)' : threatColor }}>{loading ? 'ASSESSING...' : threatLevel}</strong>
        </div>
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
        {!isAdmin && <StatCard label="Avg. Confidence" value={logs.length ? `${(averageConfidence * 100).toFixed(1)}%` : '—'} color="#d7ad22" icon={ShieldCheck} loading={loading} />}
      </div>

      {notice && (
        <div className="dashboard-notice" role="status">
          <span>{notice}</span>
          <button onClick={() => setNotice('')} aria-label="Dismiss">×</button>
        </div>
      )}

      {isAdmin ? (
        <>
          <div className="dashboard-content-grid">
            <section className="card security-events-panel">
              <div className="panel-heading">
                <div><span className="eyebrow">LIVE SECURITY</span><h2>Recent alerts</h2></div>
                <span className="panel-count">{alerts.length} recent</span>
              </div>
              {alerts.length === 0
                ? <p className="empty-state">No malicious activity recorded.</p>
                : alerts.map(alert => (
                  <article className={`security-event-row${alert.repeated_malicious_activity ? ' multiple-attempts-alert' : ''}`} key={alert.request_id}>
                    <span className="event-icon event-icon-danger"><ShieldX size={16} /></span>
                    <div className="event-details">
                      <strong>{alert.repeated_malicious_activity ? `Repeated · ${alert.consecutive_count}×` : alert.threat_type}</strong>
                      <span>{alert.user} · {alert.severity} · {new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                    <span className="event-severity">{alert.severity}</span>
                  </article>
                ))
              }
            </section>
            <section className="card analytics-summary-panel">
              <div className="panel-heading"><div><span className="eyebrow">CLASSIFICATION</span><h2>Prompt breakdown</h2></div></div>
              {[['Safe', stats.safe, '#10b981'], ['Suspicious', stats.suspicious, '#f59e0b'], ['Malicious', stats.malicious, '#ef4444']].map(([label, value, color]) => (
                <div className="mini-metric" key={label}>
                  <div><span>{label}</span><strong>{value}</strong></div>
                  <div className="mini-track"><i style={{ width: `${stats.total ? Math.max(2, value / stats.total * 100) : 0}%`, background: color }} /></div>
                </div>
              ))}
            </section>
          </div>

          <div className="dash-quicklinks">
            {[
              ['SOC Command Center', '/soc', 'Full threat overview & live feed'],
              ['Alerts', '/soc/alerts', 'Manage & investigate alerts'],
              ['User Risk', '/soc/user-risk', 'Risk scores & account controls'],
              ['Threat Intel', '/soc/threat-intel', '24h / 7d / 30d analytics'],
              ['Audit Logs', '/soc/audit', 'Immutable admin audit trail'],
              ['Security Testing', '/soc/testing', 'Test prompts safely'],
            ].map(([label, href, desc]) => (
              <Link key={href} to={href} className="dash-quicklink card">
                <strong>{label}</strong>
                <span>{desc}</span>
                <ArrowUpRight size={14} className="dash-quicklink-arrow" />
              </Link>
            ))}
          </div>
        </>
      ) : (
        <>
          <div className="personal-insights-grid">
            <section className="card security-score-card">
              <div className="panel-heading"><div><span className="eyebrow">PERSONAL POSTURE</span><h2>Security score</h2></div></div>
              {loading ? <LoadingState label="Calculating your score..." compact /> : <>
                <div className="score-dial" style={{ '--score-angle': `${securityScore * 3.6}deg` }} role="img" aria-label={`Security score ${securityScore} out of 100`}>
                  <div><strong>{securityScore}</strong><span>/ 100</span></div>
                </div>
                <p className="score-disclaimer">An informational snapshot of your recent prompt classifications.</p>
                <div className="score-factors">
                  <span><i className="factor-safe" /> Safe rate <b>{Math.round(safeRate * 100)}%</b></span>
                  <span><i className="factor-suspicious" /> Suspicious <b>{stats.suspicious}</b></span>
                  <span><i className="factor-malicious" /> Blocked <b>{stats.blocked}</b></span>
                </div>
              </>}
            </section>
            <section className="card personal-activity-chart">
              <div className="panel-heading"><div><span className="eyebrow">YOUR ACTIVITY</span><h2>Last 7 days</h2></div></div>
              {loading ? <LoadingState label="Loading your activity..." compact /> : <>
                <div className="personal-chart-bars" role="img" aria-label="Personal prompt activity over the last seven days">
                  {activityDays.map(day => (
                    <div className="personal-chart-day" key={day.date.toISOString()} title={`${day.total} prompts`}>
                      <span>{day.total || ''}</span>
                      <div>
                        <i className="personal-bar-safe" style={{ height: `${day.total ? (day.total - day.malicious - day.suspicious) / maxActivity * 100 : 0}%` }} />
                        <i className="personal-bar-suspicious" style={{ height: `${day.suspicious / maxActivity * 100}%` }} />
                        <i className="personal-bar-malicious" style={{ height: `${day.malicious / maxActivity * 100}%` }} />
                      </div>
                      <small>{day.date.toLocaleDateString(undefined, { weekday: 'short' })}</small>
                    </div>
                  ))}
                </div>
                <div className="personal-chart-legend">
                  <span><i className="personal-bar-safe" /> Safe</span>
                  <span><i className="personal-bar-suspicious" /> Suspicious</span>
                  <span><i className="personal-bar-malicious" /> Malicious</span>
                </div>
                <p className="personal-last-activity">Last activity: {logs[0]?.timestamp ? new Date(logs[0].timestamp).toLocaleString() : 'No prompts yet'}</p>
              </>}
            </section>
          </div>

          <section className="card security-events-panel personal-history-panel">
            <div className="panel-heading">
              <div><span className="eyebrow">RECENT ACTIVITY</span><h2>Latest prompts</h2></div>
              <span className="panel-count">{logs.length} recent</span>
            </div>
            {loading
              ? <LoadingState label="Loading..." compact />
              : logs.length === 0
                ? <p className="empty-state">Your prompt history will appear here after your first secure chat.</p>
                : logs.slice(0, 3).map(entry => (
                  <article className="personal-history-row" key={entry.request_id}>
                    <span className={`event-icon event-icon-${entry.classification?.toLowerCase()}`}><Activity size={15} /></span>
                    <div className="event-details">
                      <strong>
                        {entry.threat_type || 'Unclassified'}
                        <span className={`classification-label classification-${entry.classification?.toLowerCase() || 'unclassified'}`}> {entry.classification || 'UNCLASSIFIED'}</span>
                      </strong>
                      <span>{new Date(entry.timestamp).toLocaleString()} · {entry.action || '—'} · {entry.confidence ? `${Math.round(entry.confidence * 100)}% confidence` : 'n/a'}</span>
                    </div>
                    {entry.classification !== 'SAFE' && (
                      <button className="report-button" onClick={() => reportFalsePositive(entry)} disabled={Boolean(entry.false_positive_report)}>
                        {entry.false_positive_report ? <><Check size={14} /> Reported</> : 'Report FP'}
                      </button>
                    )}
                  </article>
                ))
            }
          </section>

          <div className="dash-quicklinks">
            {[
              ['Full Prompt History', '/history', 'Search & filter all your prompts'],
              ['Security Alerts', '/alerts', 'View all your security alerts'],
              ['Chat', '/', 'Start a new secure conversation'],
            ].map(([label, href, desc]) => (
              <Link key={href} to={href} className="dash-quicklink card">
                <strong>{label}</strong>
                <span>{desc}</span>
                <ArrowUpRight size={14} className="dash-quicklink-arrow" />
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
