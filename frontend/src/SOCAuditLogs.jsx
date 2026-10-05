import { useState, useEffect } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SocNotice, SocPagination, fmtTime } from './socUtils';

export default function SOCAuditLogs() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, page_size: 50 });
      if (actionFilter) params.set('action', actionFilter);
      const res = await axios.get(`${API}/api/soc/audit?${params}`);
      setItems(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch (e) {
      setNotice(e.response?.data?.detail || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [page, actionFilter]);

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="📜" title="Admin Audit Log" subtitle="Immutable record of all security-sensitive admin actions" />
      <SocNotice msg={notice} onDismiss={() => setNotice('')} type="error" />

      <SocCard style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <input className="search-input" placeholder="Filter by action..." value={actionFilter}
            onChange={e => { setActionFilter(e.target.value); setPage(1); }} style={{ minWidth: 220 }} />
          <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
            {total} records
          </span>
        </div>
      </SocCard>

      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table className="hp-table" style={{ minWidth: 800 }}>
            <thead>
              <tr>
                <th>Audit ID</th>
                <th>Timestamp</th>
                <th>Admin</th>
                <th>Action</th>
                <th>Target</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="empty-table-cell">Loading...</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan={6} className="empty-table-cell">No audit records found.</td></tr>
              ) : items.map(a => (
                <tr key={a.audit_id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-secondary)' }}>{a.audit_id}</td>
                  <td style={{ fontSize: '0.72rem', whiteSpace: 'nowrap' }}>{fmtTime(a.timestamp)}</td>
                  <td style={{ fontSize: '0.76rem', fontWeight: 600, color: 'var(--accent-gold)' }}>{a.admin}</td>
                  <td>
                    <span style={{ padding: '3px 8px', borderRadius: 4, fontSize: '0.65rem', fontFamily: 'var(--font-mono)', fontWeight: 700, background: 'rgba(245,197,24,0.08)', color: 'var(--accent-gold)', border: '1px solid rgba(245,197,24,0.2)' }}>
                      {a.action}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.72rem', color: 'var(--text-primary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.target || '—'}</td>
                  <td style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SocCard>

      <SocPagination page={page} total={total} pageSize={50} onPage={setPage} />
    </div>
  );
}
