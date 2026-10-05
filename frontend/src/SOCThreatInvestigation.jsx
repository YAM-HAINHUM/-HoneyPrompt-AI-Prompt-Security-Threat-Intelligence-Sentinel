import { useState, useEffect } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SevBadge, ClfBadge, SocNotice, SocPagination, fmtTime, fmtPct } from './socUtils';

export default function SOCThreatInvestigation() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [clf, setClf] = useState('');
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [notice, setNotice] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, page_size: 50 });
      if (search) params.set('search', search);
      if (clf) params.set('classification', clf);
      // Use admin logs endpoint with pagination
      const res = await axios.get(`${API}/api/logs`);
      let all = (res.data || []).filter(l => !l.is_test).reverse();
      if (clf) all = all.filter(l => l.classification === clf);
      if (search) all = all.filter(l => JSON.stringify(l).toLowerCase().includes(search.toLowerCase()));
      setTotal(all.length);
      const offset = (page - 1) * 50;
      setLogs(all.slice(offset, offset + 50));
    } catch (e) {
      setNotice(e.response?.data?.detail || 'Failed to load threat logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [page, clf]);
  const handleSearch = (e) => { e.preventDefault(); setPage(1); load(); };

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🔍" title="Threat Investigation" subtitle="Detailed analysis of every security event" />
      <SocNotice msg={notice} onDismiss={() => setNotice('')} type="error" />

      <SocCard style={{ padding: '14px 18px' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <input className="search-input" placeholder="Search prompts, threat types, users..." value={search}
            onChange={e => setSearch(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
          <select className="search-input" value={clf} onChange={e => { setClf(e.target.value); setPage(1); }}>
            <option value="">All Classifications</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="SAFE">Safe</option>
          </select>
          <button type="submit" className="btn-secondary" style={{ padding: '7px 14px' }}>Search</button>
          <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', marginLeft: 'auto' }}>{total} events</span>
        </form>
      </SocCard>

      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? <div className="hp-loading"><span>Loading events...</span></div>
          : logs.length === 0 ? <p style={{ padding: 24, color: 'var(--text-secondary)', margin: 0 }}>No events found.</p>
          : logs.map(l => (
            <div key={l.request_id} style={{ borderBottom: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 18px', cursor: 'pointer' }}
                onClick={() => setExpanded(expanded === l.request_id ? null : l.request_id)}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <ClfBadge classification={l.classification} />
                    <SevBadge severity={l.severity} />
                    <span style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-primary)' }}>{l.threat_type}</span>
                  </div>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                    {l.request_id} · {l.user} · {fmtTime(l.timestamp)} · Confidence: {fmtPct(l.confidence)} · Risk: {l.risk_score}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {l.prompt_preview}
                  </div>
                </div>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>{expanded === l.request_id ? '▲' : '▼'}</span>
              </div>

              {expanded === l.request_id && (
                <div style={{ padding: '0 18px 18px', background: 'var(--bg-deeper, var(--bg-dark))' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 14 }}>
                    {[
                      ['Request ID', l.request_id],
                      ['Session ID', l.session_id || '—'],
                      ['User', l.user],
                      ['Timestamp', fmtTime(l.timestamp)],
                      ['Classification', l.classification],
                      ['Threat Type', l.threat_type],
                      ['Severity', l.severity],
                      ['Confidence', fmtPct(l.confidence)],
                      ['Risk Score', l.risk_score],
                      ['Action', l.action],
                      ['LLM Status', l.llm_status || '—'],
                      ['Categories', (l.categories || []).join(', ') || '—'],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 3 }}>{k}</div>
                        <div style={{ fontSize: '0.74rem', color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>REASON</div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-primary)', padding: '8px 12px', background: 'var(--bg-card)', borderRadius: 6, border: '1px solid var(--border-color)' }}>{l.reason || '—'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>SANITIZED PROMPT PREVIEW</div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-primary)', padding: '8px 12px', background: 'var(--bg-card)', borderRadius: 6, border: '1px solid rgba(239,68,68,0.2)', fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>
                      {l.prompt_preview}
                    </div>
                  </div>
                  {l.false_positive_report && (
                    <div style={{ marginTop: 10, padding: '8px 12px', background: 'rgba(245,197,24,0.06)', border: '1px solid rgba(245,197,24,0.2)', borderRadius: 6, fontSize: '0.72rem' }}>
                      <span style={{ color: 'var(--accent-gold)' }}>⚠ False positive reported</span>
                      <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{fmtTime(l.false_positive_report.reported_at)}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
      </SocCard>

      <SocPagination page={page} total={total} pageSize={50} onPage={setPage} />
    </div>
  );
}
