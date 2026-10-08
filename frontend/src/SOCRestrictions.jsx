import { useState, useEffect } from 'react';
import axios from 'axios';
import LoadingState from './LoadingState';
import CountdownTimer from './CountdownTimer';
import { API, SocPageHeader, SocCard, SocNotice, fmtTime } from './socUtils';

export default function SOCRestrictions() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });

  const load = async () => {
    try {
      const res = await axios.get(`${API}/api/soc/restrictions`);
      setItems(res.data || []);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load restrictions', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  const lift = async (username) => {
    try {
      await axios.patch(`${API}/api/admin/users/${encodeURIComponent(username)}/chat-block`, {
        duration_minutes: 0,
        reason: 'Lifted from Active Restrictions panel',
      });
      setNotice({ msg: `Chat restriction lifted for ${username}`, type: 'success' });
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to lift restriction', type: 'error' });
    }
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🚫" title="Active Restrictions" subtitle="Users currently blocked from system access">
        <span style={{ color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontSize: '0.65rem' }}>
          <i style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', marginRight: 6 }} />
          LIVE SYNC 10s
        </span>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      <SocCard style={{ padding: 0, overflow: 'hidden' }}>
        {loading ? (
          <LoadingState label="Loading active restrictions..." compact />
        ) : items.length === 0 ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-secondary)' }}>
            <div style={{ fontSize: '2rem', marginBottom: 8 }}>✅</div>
            <strong style={{ color: 'var(--text-primary)' }}>No active restrictions</strong>
            <p style={{ margin: '6px 0 0', fontSize: '0.8rem' }}>All users currently have full chat access.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="hp-table" style={{ minWidth: 750 }}>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Blocked At</th>
                  <th>Blocked Until</th>
                  <th>Source</th>
                  <th>Consecutive</th>
                  <th>Reason</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {items.map(r => (
                  <tr key={r.username}>
                    <td>
                      <strong style={{ color: 'var(--text-primary)', fontSize: '0.82rem' }}>{r.username}</strong>
                      {r.email && <span style={{ display: 'block', fontSize: '0.64rem', color: 'var(--text-secondary)' }}>{r.email}</span>}
                    </td>
                    <td style={{ fontSize: '0.72rem' }}>{fmtTime(r.blocked_at)}</td>
                    <td style={{ fontSize: '0.74rem', color: '#ef4444', fontFamily: 'var(--font-mono)' }}>
                      {r.blocked_until && r.blocked_until.includes('2099') ? (
                        <span style={{ color: '#ef4444', fontWeight: 700 }}>Indefinite / Permanent</span>
                      ) : r.blocked_until ? (
                        <div>
                          <div>{fmtTime(r.blocked_until)}</div>
                          <div style={{ fontSize: '0.65rem', opacity: 0.85 }}>
                            <CountdownTimer until={r.blocked_until} onExpire={load} />
                          </div>
                        </div>
                      ) : (
                        'Account Blocked'
                      )}
                    </td>
                    <td>
                      <span
                        style={{
                          padding: '3px 7px',
                          borderRadius: 4,
                          fontSize: '0.62rem',
                          fontFamily: 'var(--font-mono)',
                          background: r.block_source === 'manual' ? 'rgba(245,197,24,0.1)' : 'rgba(239,68,68,0.1)',
                          color: r.block_source === 'manual' ? 'var(--accent-gold)' : '#ef4444',
                          border: `1px solid ${r.block_source === 'manual' ? 'rgba(245,197,24,0.3)' : 'rgba(239,68,68,0.3)'}`,
                        }}
                      >
                        {r.block_source || 'automatic'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: '#f97316', fontWeight: 700 }}>
                      {r.consecutive_count}
                    </td>
                    <td style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.block_reason || '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-secondary"
                        onClick={() => lift(r.username)}
                        style={{ fontSize: '0.68rem', padding: '5px 10px', color: '#10b981', borderColor: 'rgba(16,185,129,0.3)' }}
                      >
                        Lift Restriction
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SocCard>
    </div>
  );
}
