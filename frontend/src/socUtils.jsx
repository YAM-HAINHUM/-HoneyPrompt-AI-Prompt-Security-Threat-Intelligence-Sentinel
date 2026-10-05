// Shared SOC utilities
import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

export const API = 'http://127.0.0.1:8000';

export const SEV_COLOR = {
  CRITICAL: '#dc2626', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981', NONE: '#64748b',
};
export const SEV_BG = {
  CRITICAL: 'rgba(220,38,38,0.1)', HIGH: 'rgba(249,115,22,0.1)',
  MEDIUM: 'rgba(245,158,11,0.1)', LOW: 'rgba(16,185,129,0.1)', NONE: 'rgba(100,116,139,0.1)',
};
export const CLF_COLOR = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' };
export const STATUS_COLOR = {
  NEW: '#ef4444', INVESTIGATING: '#f59e0b', RESOLVED: '#10b981', DISMISSED: '#64748b',
  OPEN: '#ef4444', CLOSED: '#10b981',
};

export function sevBadge(sev) {
  const s = (sev || 'NONE').toUpperCase();
  return { color: SEV_COLOR[s] || '#64748b', background: SEV_BG[s] || 'rgba(100,116,139,0.1)' };
}

export function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export function fmtPct(v) {
  if (v == null) return '—';
  return `${(v * 100).toFixed(1)}%`;
}

export function useSOCFetch(url, deps = [], interval = 0) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetch = useCallback(async () => {
    try {
      const res = await axios.get(`${API}${url}`);
      setData(res.data);
      setError('');
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }, [url]);

  useEffect(() => {
    fetch();
    if (interval > 0) {
      const id = setInterval(fetch, interval);
      return () => clearInterval(id);
    }
  }, [fetch, ...deps]);

  return { data, loading, error, refetch: fetch };
}

export function SocPageHeader({ icon, title, subtitle, children }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16, marginBottom: 20 }}>
      <div>
        <div className="eyebrow" style={{ marginBottom: 4 }}>{icon} SOC · ADMIN</div>
        <h1 style={{ margin: '0 0 4px', fontSize: '1.4rem', fontWeight: 700 }}>{title}</h1>
        {subtitle && <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

export function SocCard({ children, style, className = '' }) {
  return <div className={`card ${className}`} style={style}>{children}</div>;
}

export function SocBadge({ label, color, bg }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '3px 8px',
      borderRadius: 4, fontSize: '0.68rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
      color: color || 'var(--text-secondary)', background: bg || 'rgba(100,116,139,0.1)',
      border: `1px solid ${color || '#64748b'}44`,
    }}>{label}</span>
  );
}

export function SevBadge({ severity }) {
  const s = (severity || 'NONE').toUpperCase();
  return <SocBadge label={s} color={SEV_COLOR[s]} bg={SEV_BG[s]} />;
}

export function ClfBadge({ classification }) {
  const c = (classification || 'SAFE').toUpperCase();
  const colors = { SAFE: '#10b981', SUSPICIOUS: '#f59e0b', MALICIOUS: '#ef4444' };
  const bgs = { SAFE: 'rgba(16,185,129,0.1)', SUSPICIOUS: 'rgba(245,158,11,0.1)', MALICIOUS: 'rgba(239,68,68,0.1)' };
  return <SocBadge label={c} color={colors[c]} bg={bgs[c]} />;
}

export function StatusBadge({ status }) {
  const s = (status || '').toUpperCase();
  return <SocBadge label={s} color={STATUS_COLOR[s] || '#64748b'} />;
}

export function SocTable({ cols, rows, emptyMsg = 'No data', loading }) {
  if (loading) return <div className="hp-loading hp-loading-compact"><span>Loading...</span></div>;
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="hp-table">
        <thead><tr>{cols.map(c => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>
          {rows.length === 0
            ? <tr><td colSpan={cols.length} className="empty-table-cell">{emptyMsg}</td></tr>
            : rows}
        </tbody>
      </table>
    </div>
  );
}

export function SocPagination({ page, total, pageSize, onPage }) {
  const totalPages = Math.ceil(total / pageSize);
  if (totalPages <= 1) return null;
  return (
    <div className="history-pagination">
      <button className="btn-secondary" onClick={() => onPage(page - 1)} disabled={page <= 1}>← Prev</button>
      <span>Page {page} of {totalPages} · {total} total</span>
      <button className="btn-secondary" onClick={() => onPage(page + 1)} disabled={page >= totalPages}>Next →</button>
    </div>
  );
}

export function SocNotice({ msg, onDismiss, type = 'info' }) {
  if (!msg) return null;
  const colors = { info: 'var(--accent-gold)', error: 'var(--accent-red)', success: 'var(--accent-green)' };
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10,
      padding: '10px 14px', borderRadius: 7, marginBottom: 12, fontSize: '0.8rem',
      background: `${colors[type]}11`, border: `1px solid ${colors[type]}44`, color: 'var(--text-primary)',
    }}>
      <span>{msg}</span>
      {onDismiss && <button onClick={onDismiss} style={{ background: 'none', border: 0, cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '1.1rem' }}>×</button>}
    </div>
  );
}

export function MiniStat({ label, value, color, sub }) {
  return (
    <div className="card" style={{ padding: '14px 16px', minWidth: 110 }}>
      <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: '1.7rem', fontWeight: 800, color: color || 'var(--text-primary)', lineHeight: 1.1 }}>{value ?? '—'}</div>
      {sub && <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}
