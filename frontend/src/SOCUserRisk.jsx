import { useState, useEffect } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SocBadge, SocNotice, fmtTime, SEV_COLOR } from './socUtils';

const RISK_COLOR = { CRITICAL: '#dc2626', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' };

export default function SOCUserRisk() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [search, setSearch] = useState('');

  const load = async () => {
    try {
      const res = await axios.get(`${API}/api/soc/user-risk`);
      setUsers(res.data || []);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load user risk', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const loadProfile = async (username) => {
    setSelected(username);
    setProfileLoading(true);
    try {
      const res = await axios.get(`${API}/api/soc/user-risk/${encodeURIComponent(username)}`);
      setProfile(res.data);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load profile', type: 'error' });
    } finally {
      setProfileLoading(false);
    }
  };

  const resetRisk = async (username) => {
    try {
      await axios.post(`${API}/api/soc/user-risk/${encodeURIComponent(username)}/reset`);
      setNotice({ msg: `Risk score reset for ${username}`, type: 'success' });
      load();
      if (selected === username) loadProfile(username);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Reset failed', type: 'error' });
    }
  };

  const blockUser = async (username, block) => {
    try {
      await axios.patch(`${API}/api/admin/users/${encodeURIComponent(username)}/access`, { is_blocked: block });
      setNotice({ msg: `User ${block ? 'blocked' : 'unblocked'}: ${username}`, type: 'success' });
      load();
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Action failed', type: 'error' });
    }
  };

  const filtered = users.filter(u => !search || u.username?.toLowerCase().includes(search.toLowerCase()));

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="👤" title="User Risk Monitoring" subtitle="Risk scores and security profiles for all users" />
      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 1.4fr' : '1fr', gap: 16 }}>
        {/* User list */}
        <SocCard style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)' }}>
            <input className="search-input" placeholder="Search users..." value={search}
              onChange={e => setSearch(e.target.value)} style={{ width: '100%' }} />
          </div>
          {loading ? <div className="hp-loading"><span>Loading...</span></div>
            : filtered.length === 0 ? <p style={{ padding: 20, color: 'var(--text-secondary)', margin: 0 }}>No user risk data yet.</p>
            : filtered.map(u => {
              const rc = RISK_COLOR[u.risk_level] || '#64748b';
              return (
                <div key={u.username} onClick={() => loadProfile(u.username)}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 18px', borderBottom: '1px solid var(--border-color)', cursor: 'pointer', background: selected === u.username ? 'rgba(245,197,24,0.05)' : 'transparent', transition: 'background 0.15s' }}>
                  <div style={{ width: 38, height: 38, borderRadius: '50%', display: 'grid', placeItems: 'center', background: `${rc}15`, border: `2px solid ${rc}44`, flexShrink: 0 }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 800, color: rc, fontFamily: 'var(--font-mono)' }}>{u.risk_score}</span>
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{u.username}</div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                      {u.malicious_count} malicious · {u.suspicious_count} suspicious · {u.consecutive_attacks} consecutive
                    </div>
                  </div>
                  <SocBadge label={u.risk_level || 'LOW'} color={rc} />
                </div>
              );
            })}
        </SocCard>

        {/* User profile */}
        {selected && (
          <SocCard>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <div className="eyebrow" style={{ marginBottom: 3 }}>USER SECURITY PROFILE</div>
                <strong style={{ fontSize: '1rem' }}>{selected}</strong>
              </div>
              <button className="btn-secondary" onClick={() => { setSelected(null); setProfile(null); }}>✕ Close</button>
            </div>

            {profileLoading ? <div className="hp-loading"><span>Loading profile...</span></div>
              : profile && <>
                {/* Risk score */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 10, marginBottom: 16 }}>
                  {[
                    ['Risk Score', `${profile.risk?.risk_score ?? 0}/100`, RISK_COLOR[profile.risk?.risk_level] || '#64748b'],
                    ['Risk Level', profile.risk?.risk_level || 'LOW', RISK_COLOR[profile.risk?.risk_level] || '#64748b'],
                    ['Malicious', profile.risk?.malicious_count ?? 0, '#ef4444'],
                    ['Suspicious', profile.risk?.suspicious_count ?? 0, '#f59e0b'],
                    ['Consecutive', profile.risk?.consecutive_attacks ?? 0, '#f97316'],
                    ['Total Prompts', profile.risk?.total_prompts ?? 0, 'var(--text-primary)'],
                  ].map(([l, v, c]) => (
                    <div key={l} style={{ padding: '10px 12px', background: 'var(--bg-dark)', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                      <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 4 }}>{l}</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 700, color: c }}>{v}</div>
                    </div>
                  ))}
                </div>

                {/* Last threat */}
                {profile.risk?.last_threat && (
                  <div style={{ padding: '10px 14px', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, marginBottom: 14, fontSize: '0.76rem' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Last threat: </span>
                    <strong style={{ color: '#ef4444' }}>{profile.risk.last_threat_type}</strong>
                    <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>{fmtTime(profile.risk.last_threat)}</span>
                  </div>
                )}

                {/* Admin controls */}
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
                  <button className="btn-secondary" onClick={() => resetRisk(selected)} style={{ fontSize: '0.72rem' }}>Reset Risk Score</button>
                  <button className="btn-secondary" onClick={() => blockUser(selected, true)}
                    style={{ fontSize: '0.72rem', color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)' }}>Block User</button>
                  <button className="btn-secondary" onClick={() => blockUser(selected, false)}
                    style={{ fontSize: '0.72rem', color: '#10b981', borderColor: 'rgba(16,185,129,0.3)' }}>Unblock User</button>
                </div>

                {/* Recent logs */}
                <div className="eyebrow" style={{ marginBottom: 8 }}>RECENT SECURITY EVENTS</div>
                {(profile.recent_logs || []).slice(0, 8).map(l => (
                  <div key={l.request_id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderTop: '1px solid var(--border-color)' }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, background: l.classification === 'MALICIOUS' ? '#ef4444' : l.classification === 'SUSPICIOUS' ? '#f59e0b' : '#10b981' }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.threat_type}</div>
                      <div style={{ fontSize: '0.62rem', color: 'var(--text-secondary)' }}>{l.severity} · {Math.round((l.confidence || 0) * 100)}% · {fmtTime(l.timestamp)}</div>
                    </div>
                    <span style={{ fontSize: '0.62rem', color: l.action === 'BLOCKED' ? '#ef4444' : '#64748b', fontFamily: 'var(--font-mono)' }}>{l.action}</span>
                  </div>
                ))}
                {(profile.recent_logs || []).length === 0 && <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', margin: 0 }}>No security events recorded.</p>}
              </>}
          </SocCard>
        )}
      </div>
    </div>
  );
}
