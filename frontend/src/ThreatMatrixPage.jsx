import { useState, useEffect } from 'react';
import axios from 'axios';

const SEV_COLOR = { CRITICAL: '#dc2626', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#10b981', NONE: '#64748b' };

export default function ThreatMatrixPage() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState('newest');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [loadError, setLoadError] = useState('');

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await axios.get('http://127.0.0.1:8000/api/logs');
        setLogs(res.data.slice().reverse());
        setLoadError('');
      } catch (error) {
        setLoadError(error.response?.data?.detail || 'Threat events could not be loaded.');
      }
    };
    fetch();
    const id = setInterval(fetch, 5000);
    return () => clearInterval(id);
  }, []);

  const FILTERS = ['All', 'Safe', 'Suspicious', 'Malicious', 'Critical', 'High', 'Medium', 'Blocked'];

  const filtered = logs.filter(log => {
    const matchFilter = filter === 'All' ||
      (filter === 'Safe' && log.classification === 'SAFE') ||
      (filter === 'Suspicious' && log.classification === 'SUSPICIOUS') ||
      (filter === 'Malicious' && log.classification === 'MALICIOUS') ||
      (filter === 'Critical' && log.severity === 'CRITICAL') ||
      (filter === 'High' && log.severity === 'HIGH') ||
      (filter === 'Medium' && log.severity === 'MEDIUM') ||
      (filter === 'Blocked' && log.action === 'BLOCKED');
    const searchTarget = `${log.threat_type || ''} ${log.user || ''} ${log.prompt_preview || ''}`.toLowerCase();
    const matchSearch = !search || searchTarget.includes(search.toLowerCase());
    const timestamp = new Date(log.timestamp).getTime();
    const matchStart = !dateFrom || timestamp >= new Date(`${dateFrom}T00:00:00`).getTime();
    const matchEnd = !dateTo || timestamp <= new Date(`${dateTo}T23:59:59.999`).getTime();
    return matchFilter && matchSearch && matchStart && matchEnd;
  }).sort((a, b) => {
    if (sort === 'confidence') return (b.confidence || 0) - (a.confidence || 0);
    if (sort === 'oldest') return new Date(a.timestamp) - new Date(b.timestamp);
    return new Date(b.timestamp) - new Date(a.timestamp);
  });

  const total = logs.length;
  const critical = logs.filter(l => l.severity === 'CRITICAL').length;
  const high = logs.filter(l => l.severity === 'HIGH').length;
  const blocked = logs.filter(l => l.action === 'BLOCKED').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px' }}>
        {[
          { label: 'Total Threats', value: total, color: 'var(--text-primary)' },
          { label: 'Critical', value: critical, color: '#dc2626' },
          { label: 'High', value: high, color: '#ef4444' },
          { label: 'Blocked', value: blocked, color: '#ef4444' },
          { label: 'Safe', value: logs.filter(l => l.classification === 'SAFE').length, color: '#10b981' },
          { label: 'Suspicious', value: logs.filter(l => l.classification === 'SUSPICIOUS').length, color: '#f59e0b' },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: '14px 18px' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px' }}>{s.label}</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 'bold', color: s.color }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Filters + Search */}
      <div className="threat-controls">
        {FILTERS.map(f => (
          <button key={f} onClick={() => setFilter(f)} aria-pressed={filter === f}
            style={{ padding: '6px 14px', borderRadius: '20px', border: `1px solid ${filter === f ? 'var(--accent-gold)' : 'var(--border-color)'}`, background: filter === f ? 'rgba(245,158,11,0.1)' : 'transparent', color: filter === f ? 'var(--accent-gold)' : 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.8rem' }}>
            {f}
          </button>
        ))}
        <input aria-label="Search threat events" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events or users..." className="threat-search" />
        <label className="date-filter">From<input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)} aria-label="Filter from date" /></label>
        <label className="date-filter">To<input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)} aria-label="Filter to date" /></label>
        <label className="sort-filter">Sort<select value={sort} onChange={e => setSort(e.target.value)} aria-label="Sort threat events"><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="confidence">Confidence</option></select></label>
      </div>

      {loadError && <div className="auth-error" role="alert">{loadError}</div>}

      {/* Table */}
      <div className="card threat-table-card">
        <div className="table-scroll"><table className="role-table threat-table">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', background: 'var(--bg-dark)' }}>
              {['Timestamp', 'Threat Type', 'Severity', 'Confidence', 'User', 'Action', 'Status'].map(h => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="empty-table-cell">No threat events match these filters.</td></tr>
            ) : filtered.map(log => (
              <tr key={log.request_id}>
                <td><time dateTime={log.timestamp}>{new Date(log.timestamp).toLocaleString()}</time></td>
                <td><strong>{log.threat_type || '—'}</strong><small>#{log.request_id || 'N/A'}</small></td>
                <td><span className={`severity-chip severity-${(log.severity || 'none').toLowerCase()}`}>{log.severity || 'NONE'}</span></td>
                <td>{log.confidence ? `${(log.confidence * 100).toFixed(1)}%` : '—'}</td>
                <td>{log.user || 'anonymous'}</td>
                <td>{log.action || '—'}</td>
                <td><span className={`classification-chip classification-${(log.classification || 'unclassified').toLowerCase()}`}>{log.classification || 'UNCLASSIFIED'}</span></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </div>
    </div>
  );
}
