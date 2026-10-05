import { useState, useEffect } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SevBadge, StatusBadge, SocNotice, SocPagination, fmtTime } from './socUtils';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINMENT', 'RESOLVED'];

export default function SOCIncidents() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [expanded, setExpanded] = useState(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: '', severity: 'HIGH', description: '' });
  const [noteText, setNoteText] = useState('');
  const [updating, setUpdating] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, page_size: 50 });
      if (statusFilter) params.set('status', statusFilter);
      const res = await axios.get(`${API}/api/soc/incidents?${params}`);
      setItems(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load incidents', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [page, statusFilter]);

  const createIncident = async () => {
    if (!form.title.trim() || !form.description.trim()) {
      setNotice({ msg: 'Title and description are required', type: 'error' });
      return;
    }
    try {
      await axios.post(`${API}/api/soc/incidents`, form);
      setNotice({ msg: 'Incident created', type: 'success' });
      setCreating(false);
      setForm({ title: '', severity: 'HIGH', description: '' });
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Create failed', type: 'error' });
    }
  };

  const updateIncident = async (id, updates) => {
    setUpdating(id);
    try {
      await axios.patch(`${API}/api/soc/incidents/${id}`, updates);
      setNotice({ msg: 'Incident updated', type: 'success' });
      setNoteText('');
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Update failed', type: 'error' });
    } finally {
      setUpdating('');
    }
  };

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="📋" title="Incident Management" subtitle="Track and resolve security incidents">
        <button className="btn-primary" onClick={() => setCreating(c => !c)} style={{ width: 'auto', padding: '9px 18px' }}>
          {creating ? '✕ Cancel' : '+ New Incident'}
        </button>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {creating && (
        <SocCard>
          <div className="eyebrow" style={{ marginBottom: 12 }}>CREATE INCIDENT</div>
          <div style={{ display: 'grid', gap: 12 }}>
            <input className="search-input" placeholder="Incident title..." value={form.title}
              onChange={e => setForm(f => ({ ...f, title: e.target.value }))} style={{ width: '100%' }} />
            <select className="search-input" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Describe the incident..."
              style={{ width: '100%', minHeight: 80, padding: '10px 14px', background: 'var(--bg-dark)', border: '1px solid var(--border-color)', borderRadius: 8, color: 'var(--text-primary)', fontSize: '0.86rem', fontFamily: 'inherit', resize: 'vertical', outline: 'none', boxSizing: 'border-box' }} />
            <button className="btn-primary" onClick={createIncident} style={{ width: 'auto', padding: '9px 20px' }}>Create Incident</button>
          </div>
        </SocCard>
      )}

      <SocCard style={{ padding: '14px 18px' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <select className="search-input" value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}>
            <option value="">All Statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            <option value="RESOLVED">RESOLVED</option>
          </select>
          <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{total} incidents</span>
        </div>
      </SocCard>

      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? <div className="hp-loading"><span>Loading incidents...</span></div>
          : items.length === 0 ? <p style={{ padding: 24, color: 'var(--text-secondary)', margin: 0 }}>No incidents found.</p>
          : items.map(inc => (
            <div key={inc.incident_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', cursor: 'pointer' }}
                onClick={() => setExpanded(expanded === inc.incident_id ? null : inc.incident_id)}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <strong style={{ fontSize: '0.84rem' }}>{inc.title}</strong>
                    <SevBadge severity={inc.severity} />
                    <StatusBadge status={inc.status} />
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                    {inc.incident_id} · Created by {inc.created_by} · {fmtTime(inc.created_at)}
                    {inc.resolved_at && ` · Resolved: ${fmtTime(inc.resolved_at)}`}
                  </div>
                </div>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>{expanded === inc.incident_id ? '▲' : '▼'}</span>
              </div>

              {expanded === inc.incident_id && (
                <div style={{ padding: '0 18px 18px', background: 'var(--bg-deeper, var(--bg-dark))' }}>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-primary)', margin: '0 0 14px', lineHeight: 1.6 }}>{inc.description}</p>

                  {inc.notes?.length > 0 && (
                    <div style={{ marginBottom: 14 }}>
                      <div className="eyebrow" style={{ marginBottom: 8 }}>INVESTIGATION NOTES</div>
                      {inc.notes.map((n, i) => (
                        <div key={i} style={{ padding: '8px 12px', background: 'var(--bg-card)', borderRadius: 6, marginBottom: 6, fontSize: '0.74rem' }}>
                          <span style={{ color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)', fontSize: '0.62rem' }}>{n.admin} · {fmtTime(n.ts)}</span>
                          <p style={{ margin: '4px 0 0', color: 'var(--text-primary)' }}>{n.note}</p>
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                    <input className="search-input" placeholder="Add note..." value={noteText}
                      onChange={e => setNoteText(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
                    {STATUSES.concat(['RESOLVED']).map(s => (
                      <button key={s} className="btn-secondary" disabled={updating === inc.incident_id || inc.status === s}
                        onClick={() => updateIncident(inc.incident_id, { status: s, note: noteText })}
                        style={{ fontSize: '0.7rem', padding: '6px 10px' }}>
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
