import { useState, useEffect } from 'react';
import axios from 'axios';

const CLF_COLOR = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' };
const SEV_COLOR = { CRITICAL: '#dc2626', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#10b981', NONE: '#64748b' };

function Bar({ label, value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>{value}</span>
      </div>
      <div style={{ height: '8px', background: 'var(--bg-dark)', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: '4px', transition: 'width 0.5s ease' }} />
      </div>
    </div>
  );
}

export default function AnalyticsPage() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    const fetch = async () => {
      try {
        const [lRes, sRes] = await Promise.all([
          axios.get('http://127.0.0.1:8000/api/logs'),
          axios.get('http://127.0.0.1:8000/api/stats'),
        ]);
        setLogs(lRes.data);
        setStats(sRes.data);
        setLoadError('');
      } catch (error) {
        setLoadError(error.response?.data?.detail || 'Analytics data could not be loaded.');
      }
    };
    fetch();
  }, []);

  // Threat type distribution
  const threatCounts = {};
  logs.forEach(l => {
    const k = l.threat_type || 'Unclassified';
    threatCounts[k] = (threatCounts[k] || 0) + 1;
  });
  const sortedThreats = Object.entries(threatCounts).sort((a, b) => b[1] - a[1]);
  const maxThreat = sortedThreats[0]?.[1] || 1;

  // Severity distribution
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
  logs.forEach(l => { if (l.severity in sevCounts) sevCounts[l.severity]++; });

  const dailyActivity = Array.from({ length: 7 }, (_, index) => {
    const date = new Date();
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - (6 - index));
    const dayLogs = logs.filter(log => new Date(log.timestamp).toDateString() === date.toDateString());
    return {
      date,
      safe: dayLogs.filter(log => log.classification === 'SAFE').length,
      suspicious: dayLogs.filter(log => log.classification === 'SUSPICIOUS').length,
      malicious: dayLogs.filter(log => log.classification === 'MALICIOUS').length,
      blocked: dayLogs.filter(log => log.action === 'BLOCKED').length,
    };
  });
  const maxDailyActivity = Math.max(1, ...dailyActivity.map(day => day.safe + day.suspicious + day.malicious));
  const maxDailyBlocked = Math.max(1, ...dailyActivity.map(day => day.blocked));

  const total = logs.length || 1;
  const blockRate = stats.total > 0 ? ((stats.blocked / stats.total) * 100).toFixed(1) : '0.0';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {loadError && <div className="auth-error" role="alert">{loadError}</div>}

      {/* KPI Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '14px' }}>
        {[
          { label: 'Total Analyzed', value: stats.total || 0 },
          { label: 'Block Rate', value: `${blockRate}%`, color: '#ef4444' },
          { label: 'Safe Rate', value: `${stats.total > 0 ? ((stats.safe / stats.total) * 100).toFixed(1) : 0}%`, color: '#10b981' },
          { label: 'Threat Rate', value: `${stats.total > 0 ? (((stats.suspicious + stats.malicious) / stats.total) * 100).toFixed(1) : 0}%`, color: '#f59e0b' },
        ].map(k => (
          <div key={k.label} className="card" style={{ padding: '16px 20px' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>{k.label}</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: k.color || 'var(--text-primary)' }}>{k.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>

        {/* Activity Over Time */}
        <div className="card analytics-time-card">
          <h3 className="analytics-card-title">Threats Over Time <span>LAST 7 DAYS</span></h3>
          <div className="timeline-columns" role="img" aria-label="Daily safe, suspicious, and malicious prompt counts over the last seven days">
            {dailyActivity.map(day => {
              const total = day.safe + day.suspicious + day.malicious;
              return <div className="timeline-day" key={day.date.toISOString()}>
                <span className="timeline-total">{total}</span>
                <div className="timeline-bar" title={`${day.safe} safe, ${day.suspicious} suspicious, ${day.malicious} malicious`}>
                  <i className="timeline-safe" style={{ height: `${day.safe / maxDailyActivity * 100}%` }} />
                  <i className="timeline-suspicious" style={{ height: `${day.suspicious / maxDailyActivity * 100}%` }} />
                  <i className="timeline-malicious" style={{ height: `${day.malicious / maxDailyActivity * 100}%` }} />
                </div>
                <span className="timeline-date">{day.date.toLocaleDateString(undefined, { weekday: 'short' })}</span>
              </div>;
            })}
          </div>
          <div className="analytics-legend"><span><i className="timeline-safe" /> Safe</span><span><i className="timeline-suspicious" /> Suspicious</span><span><i className="timeline-malicious" /> Malicious</span></div>
        </div>

        {/* Classification Breakdown */}
        <div className="card">
          <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px' }}>Classification Breakdown</h3>
          {Object.entries(CLF_COLOR).map(([clf, color]) => (
            <Bar key={clf} label={clf} value={stats[clf.toLowerCase()] || 0} max={total} color={color} />
          ))}
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px' }}>Severity Distribution</h3>
          {Object.entries(sevCounts).map(([sev, count]) => (
            <Bar key={sev} label={sev} value={count} max={total} color={SEV_COLOR[sev]} />
          ))}
        </div>

      </div>

      <div className="card blocked-requests-card">
        <h3 className="analytics-card-title">Blocked Requests <span>LAST 7 DAYS</span></h3>
        {dailyActivity.map(day => <Bar key={day.date.toISOString()} label={day.date.toLocaleDateString(undefined, { weekday: 'long' })} value={day.blocked} max={maxDailyBlocked} color="#ef4444" />)}
      </div>

      {/* Top Threat Types */}
      <div className="card">
        <h3 style={{ color: 'var(--text-secondary)', margin: '0 0 16px 0', fontSize: '0.82rem', textTransform: 'uppercase', letterSpacing: '1px' }}>Most Common Attack Types</h3>
        {sortedThreats.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>No data yet.</div>
        ) : sortedThreats.slice(0, 8).map(([type, count]) => (
          <Bar key={type} label={type} value={count} max={maxThreat} color="#f59e0b" />
        ))}
      </div>

    </div>
  );
}
