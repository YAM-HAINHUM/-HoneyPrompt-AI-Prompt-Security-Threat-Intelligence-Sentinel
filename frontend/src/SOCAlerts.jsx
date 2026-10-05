import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SocBadge, SevBadge, StatusBadge, SocPagination, SocNotice, fmtTime, fmtPct, SEV_COLOR } from './socUtils';

const STATUSES = ['', 'NEW', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'];
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function SOCAlerts() {
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
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, page_size: 50, exclude_test: true });
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);
      if (userFilter) params.set('user', userFilter);
      const res = await axios.get(`${API}/api/soc/alerts?${params}`);
      setItems(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load alerts', type: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, severity, status, userFilter]);

  useEffect(() => { load(); const id = setInterval(load, 10000); return () => clearInterval(id); }, [load]);

  const updateStatus = async (alertId, newStatus) => {
    setUpdating(alertId);
    try {
      await axios.patch(`${API}/api/soc/alerts/${alertId}`, { status: newStatus, note: noteText });
      setNotice({ msg: `Alert marked as ${newStatus}`, type: 'success' });
      setNoteText('');
      setExpanded(null);
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Update failed', type: 'error' });
    } finally {
      setUpdating('');
    }
  };

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🚨" title="Security Alerts Center" subtitle="Manage and investigate security alerts" />

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {/* Filters */}
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
          <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
            {total} alerts
          </span>
        </div>
      </SocCard>

      {/* Alert list */}
      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <div className="hp-loading"><span>Loading alerts...</span></div>
        ) : items.length === 0 ? (
          <p style={{ padding: 24, color: 'var(--text-secondary)', margin: 0 }}>No alerts match the current filters.</p>
        ) : items.map(a => (
          <div key={a.alert_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', cursor: 'pointer' }}
              onClick={() => setExpanded(expanded === a.alert_id ? null : a.alert_id)}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', flexShrink: 0, background: SEV_COLOR[a.severity] || '#64748b', boxShadow: `0 0 8px ${SEV_COLOR[a.severity] || '#64748b'}` }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                  <strong style={{ fontSize: '0.82rem' }}>{a.threat_type}</strong>
                  <SevBadge severity={a.severity} />
                  <StatusBadge status={a.status} />
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                  {a.alert_id} · User: <b style={{ color: 'var(--text-primary)' }}>{a.user}</b> · Confidence: {fmtPct(a.confidence)} · Risk: {a.risk_score} · {fmtTime(a.timestamp)}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.prompt_preview}
                </div>
              </div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>{expanded === a.alert_id ? '▲' : '▼'}</span>
            </div>

            {expanded === a.alert_id && (
              <div style={{ padding: '0 18px 18px', background: 'var(--bg-deeper, var(--bg-dark))' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 14 }}>
                  {[
                    ['Alert ID', a.alert_id], ['Request ID', a.request_id], ['Session', a.session_id || '—'],
                    ['Action', a.action], ['Reason', a.reason], ['Categories', (a.categories || []).join(', ') || '—'],
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
                      onClick={() => updateStatus(a.alert_id, s)}
                      style={{ fontSize: '0.72rem', padding: '7px 12px' }}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </SocCard>

      <SocPagination page={page} total={total} pageSize={50} onPage={setPage} />
    </div>
  );
}
