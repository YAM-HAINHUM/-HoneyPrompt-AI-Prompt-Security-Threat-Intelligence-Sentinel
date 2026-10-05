import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { ChevronDown, RefreshCw } from 'lucide-react';

const CLF_COLOR = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' };
const SEV_COLOR = { CRITICAL: '#dc2626', HIGH: '#ef4444', MEDIUM: '#f59e0b', LOW: '#10b981', NONE: '#64748b' };

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('http://127.0.0.1:8000/api/logs');
      setLogs(res.data.slice().reverse());
      setLoadError('');
    } catch (error) {
      setLoadError(error.response?.data?.detail || 'Audit events could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initialLoad = window.setTimeout(fetchLogs, 0);
    return () => window.clearTimeout(initialLoad);
  }, [fetchLogs]);

  const filtered = logs.filter(l => {
    const matchFilter = filter === 'All' || l.classification === filter.toUpperCase();
    const matchSearch = !search || l.prompt_preview?.toLowerCase().includes(search.toLowerCase()) || l.threat_type?.toLowerCase().includes(search.toLowerCase()) || l.user?.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Controls */}
      <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
        {['All', 'Safe', 'Suspicious', 'Malicious'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={{ padding: '6px 14px', borderRadius: '20px', border: `1px solid ${filter === f ? 'var(--accent-gold)' : 'var(--border-color)'}`, background: filter === f ? 'rgba(245,158,11,0.1)' : 'transparent', color: filter === f ? 'var(--accent-gold)' : 'var(--text-secondary)', cursor: 'pointer', fontSize: '0.8rem' }}>
            {f}
          </button>
        ))}
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search logs..."
          style={{ background: 'var(--bg-panel)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '6px 14px', color: 'var(--text-primary)', fontSize: '0.85rem', outline: 'none', minWidth: '220px' }} />
        <button onClick={fetchLogs} style={{ marginLeft: 'auto', background: 'transparent', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '6px 12px', color: 'var(--text-secondary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>
      {loadError && <div className="auth-error" role="alert">{loadError}</div>}

      {/* Log Entries */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {filtered.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '40px' }}>No log entries found.</div>
        ) : filtered.map((log, i) => (
          <div key={i} className="card" style={{ padding: '16px 20px', borderLeft: `3px solid ${CLF_COLOR[log.classification] || 'var(--border-color)'}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{new Date(log.timestamp).toLocaleString()}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', background: 'var(--bg-dark)', padding: '2px 8px', borderRadius: '4px' }}>#{log.request_id || 'N/A'}</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>User: <strong style={{ color: 'var(--text-primary)' }}>{log.user || 'anonymous'}</strong></span>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', background: `${CLF_COLOR[log.classification]}22`, color: CLF_COLOR[log.classification] || 'var(--text-secondary)' }}>
                  {log.classification}
                </span>
                <span style={{ padding: '3px 10px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold', background: `${SEV_COLOR[log.severity]}22`, color: SEV_COLOR[log.severity] || 'var(--text-secondary)' }}>
                  {log.severity}
                </span>
                {log.false_positive_report && <span className="false-positive-tag">FALSE-POSITIVE REPORT</span>}
                <button type="button" className="audit-expand-button" aria-expanded={expandedId === (log.request_id || String(i))} aria-controls={`audit-details-${log.request_id || i}`} onClick={() => setExpandedId(current => current === (log.request_id || String(i)) ? null : (log.request_id || String(i)))}>
                  {expandedId === (log.request_id || String(i)) ? 'Hide details' : 'Details'} <ChevronDown size={14} />
                </button>
              </div>
            </div>

            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '10px', fontStyle: 'italic', background: 'var(--bg-dark)', padding: '8px 12px', borderRadius: '6px' }}>
              "{log.prompt_preview}"
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '6px 20px', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Threat: <strong style={{ color: 'var(--text-primary)' }}>{log.threat_type}</strong></span>
              <span style={{ color: 'var(--text-secondary)' }}>Confidence: <strong style={{ color: 'var(--text-primary)' }}>{log.confidence ? `${(log.confidence * 100).toFixed(1)}%` : '—'}</strong></span>
              <span style={{ color: 'var(--text-secondary)' }}>Action: <strong style={{ color: CLF_COLOR[log.classification] }}>{log.action}</strong></span>
              <span style={{ color: 'var(--text-secondary)' }}>LLM: <strong style={{ color: 'var(--text-primary)' }}>{log.llm_status || '—'}</strong></span>
            </div>

            {log.reason && log.classification !== 'SAFE' && (
              <div style={{ marginTop: '8px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Reason: {log.reason}</div>
            )}
            {expandedId === (log.request_id || String(i)) && <div className="audit-expanded-details" id={`audit-details-${log.request_id || i}`}>
              <div><span>Risk score</span><strong>{log.risk_score ?? '—'}</strong></div>
              <div><span>Categories</span><strong>{log.categories?.length ? log.categories.join(', ') : 'None recorded'}</strong></div>
              <div><span>LLM status</span><strong>{log.llm_status || '—'}</strong></div>
              <div><span>Response preview</span><strong>{log.response_preview || 'No response preview recorded'}</strong></div>
              {log.false_positive_report && <div><span>False-positive report</span><strong>{log.false_positive_report.reason || 'Review requested'} · {new Date(log.false_positive_report.reported_at).toLocaleString()}</strong></div>}
            </div>}
          </div>
        ))}
      </div>
    </div>
  );
}
