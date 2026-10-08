import { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertTriangle, ShieldCheck, UserX, UserCheck, ShieldAlert, RefreshCw, X, Clock, Lock, Unlock, Search } from 'lucide-react';
import LoadingState from './LoadingState';
import CountdownTimer from './CountdownTimer';
import { API, SocPageHeader, SocCard, SocBadge, SocNotice, fmtTime } from './socUtils';

const RISK_COLOR = { CRITICAL: '#dc2626', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981' };

const DURATION_OPTIONS = [
  { label: '15 Minutes', value: 15, desc: 'Short cooldown for minor violations' },
  { label: '1 Hour', value: 60, desc: 'Standard temporary restriction' },
  { label: '8 Hours', value: 480, desc: 'Extended shift restriction' },
  { label: '1 Week', value: 10080, desc: '7-day penalty for severe attacks' },
  { label: '1 Month', value: 43200, desc: '30-day security hold' },
  { label: 'Always / Until Manually Unblocked', value: -1, desc: 'Indefinite administrative block' },
];

export default function SOCUserRisk() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [profileLoading, setProfileLoading] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [search, setSearch] = useState('');

  // Modal States
  const [blockModalUser, setBlockModalUser] = useState(null);
  const [blockDuration, setBlockDuration] = useState(15);
  const [blockReason, setBlockReason] = useState('');
  const [confirmInput, setConfirmInput] = useState('');
  const [isSubmittingBlock, setIsSubmittingBlock] = useState(false);

  const [unblockModalUser, setUnblockModalUser] = useState(null);
  const [unblockReason, setUnblockReason] = useState('');
  const [isSubmittingUnblock, setIsSubmittingUnblock] = useState(false);

  const loadUsers = async () => {
    try {
      const res = await axios.get(`${API}/api/soc/user-risk`);
      setUsers(res.data || []);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load user risk profiles', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
    const interval = setInterval(loadUsers, 12000);
    return () => clearInterval(interval);
  }, []);

  const loadProfile = async (username) => {
    setSelectedUser(username);
    setProfileLoading(true);
    try {
      const res = await axios.get(`${API}/api/soc/user-risk/${encodeURIComponent(username)}`);
      setProfile(res.data);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load detailed profile', type: 'error' });
    } finally {
      setProfileLoading(false);
    }
  };

  const resetRisk = async (username) => {
    try {
      await axios.post(`${API}/api/soc/user-risk/${encodeURIComponent(username)}/reset`);
      setNotice({ msg: `Risk score reset for ${username}`, type: 'success' });
      loadUsers();
      if (selectedUser === username) loadProfile(username);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Reset failed', type: 'error' });
    }
  };

  const openBlockModal = (user, e) => {
    if (e) e.stopPropagation();
    setBlockModalUser(user);
    setBlockDuration(15);
    setBlockReason('Administrative security enforcement');
    setConfirmInput('');
  };

  const openUnblockModal = (user, e) => {
    if (e) e.stopPropagation();
    setUnblockModalUser(user);
    setUnblockReason('Restriction lifted by administrator');
  };

  const handleApplyBlock = async () => {
    if (confirmInput.trim() !== 'CONFIRM BLOCK' || !blockModalUser) return;
    setIsSubmittingBlock(true);
    try {
      await axios.patch(`${API}/api/admin/users/${encodeURIComponent(blockModalUser.username)}/chat-block`, {
        duration_minutes: blockDuration,
        reason: blockReason || 'Administrative security enforcement',
      });
      setNotice({
        msg: `Successfully applied block restriction to ${blockModalUser.username}`,
        type: 'success',
      });
      setBlockModalUser(null);
      loadUsers();
      if (selectedUser === blockModalUser.username) loadProfile(blockModalUser.username);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to apply restriction', type: 'error' });
    } finally {
      setIsSubmittingBlock(false);
    }
  };

  const handleApplyUnblock = async () => {
    if (!unblockModalUser) return;
    setIsSubmittingUnblock(true);
    try {
      await axios.patch(`${API}/api/admin/users/${encodeURIComponent(unblockModalUser.username)}/chat-block`, {
        duration_minutes: 0,
        reason: unblockReason || 'Restriction lifted by administrator',
      });
      setNotice({
        msg: `Successfully unblocked ${unblockModalUser.username}. Chat access restored.`,
        type: 'success',
      });
      setUnblockModalUser(null);
      loadUsers();
      if (selectedUser === unblockModalUser.username) loadProfile(unblockModalUser.username);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to lift restriction', type: 'error' });
    } finally {
      setIsSubmittingUnblock(false);
    }
  };

  const filteredUsers = users.filter(u => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      u.username?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.full_name?.toLowerCase().includes(q) ||
      u.role?.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 40 }}>
      <SocPageHeader icon="👤" title="User Risk & Access Control" subtitle="Monitor user risk scores, enforce temporary/permanent restrictions, and inspect telemetry">
        <button className="btn-secondary" onClick={loadUsers} style={{ fontSize: '0.78rem' }}>
          <RefreshCw size={14} /> Refresh Data
        </button>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {/* Main Content Area */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedUser ? '1.5fr 1fr' : '1fr', gap: 16 }}>
        
        {/* User Risk Table Card */}
        <SocCard style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', background: 'var(--bg-deeper)' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
              <Search size={15} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
              <input
                className="search-input"
                placeholder="Search users by name, email, role..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                style={{ width: '100%', paddingLeft: 34 }}
              />
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              Showing <strong>{filteredUsers.length}</strong> of {users.length} users
            </div>
          </div>

          {loading ? (
            <LoadingState label="Loading user security profiles..." compact />
          ) : filteredUsers.length === 0 ? (
            <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-secondary)' }}>
              No user profiles match your search criteria.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="hp-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Risk Score</th>
                    <th>Threat Telemetry</th>
                    <th>Restriction Status</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map(u => {
                    const rc = RISK_COLOR[u.risk_level] || '#64748b';
                    const isBlocked = Boolean(u.is_blocked || u.blocked_until);
                    const isAdminUser = u.role?.toLowerCase() === 'admin';

                    return (
                      <tr
                        key={u.username}
                        onClick={() => loadProfile(u.username)}
                        style={{
                          cursor: 'pointer',
                          background: selectedUser === u.username ? 'rgba(245,197,24,0.06)' : 'transparent',
                        }}
                      >
                        {/* User Identity */}
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                            <div
                              style={{
                                width: 34,
                                height: 34,
                                borderRadius: '50%',
                                display: 'grid',
                                placeItems: 'center',
                                background: `${rc}15`,
                                border: `2px solid ${rc}44`,
                                flexShrink: 0,
                                fontSize: '0.72rem',
                                fontWeight: 800,
                                color: rc,
                                fontFamily: 'var(--font-mono)',
                              }}
                            >
                              {u.risk_score}
                            </div>
                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.84rem', display: 'flex', alignItems: 'center', gap: 6 }}>
                                {u.username}
                                {isAdminUser && (
                                  <span style={{ fontSize: '0.58rem', padding: '1px 5px', borderRadius: 4, background: 'rgba(245,197,24,0.15)', color: 'var(--accent-gold)', border: '1px solid rgba(245,197,24,0.3)' }}>
                                    ADMIN
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                                {u.email || u.full_name || 'User Account'}
                              </div>
                            </div>
                          </div>
                        </td>

                        {/* Risk Level Badge */}
                        <td>
                          <SocBadge label={`${u.risk_level || 'LOW'} (${u.risk_score}/100)`} color={rc} />
                        </td>

                        {/* Telemetry */}
                        <td>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                            <span style={{ color: u.malicious_count > 0 ? '#ef4444' : 'inherit', fontWeight: u.malicious_count > 0 ? 600 : 400 }}>
                              {u.malicious_count} malicious
                            </span>{' '}
                            · {u.suspicious_count} suspicious · {u.consecutive_attacks} consec.
                          </div>
                        </td>

                        {/* Restriction Status */}
                        <td>
                          {isBlocked ? (
                            <div style={{ display: 'inline-flex', flexDirection: 'column', gap: 2 }}>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#ef4444', fontWeight: 700, fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                                <Lock size={12} /> RESTRICTED
                              </span>
                              {u.blocked_until && u.blocked_until.includes('2099') ? (
                                <span style={{ fontSize: '0.62rem', color: 'var(--text-secondary)' }}>Until Manually Unblocked</span>
                              ) : u.blocked_until ? (
                                <span style={{ fontSize: '0.64rem', color: '#ef4444', fontFamily: 'var(--font-mono)' }}>
                                  <CountdownTimer until={u.blocked_until} />
                                </span>
                              ) : (
                                <span style={{ fontSize: '0.62rem', color: 'var(--text-secondary)' }}>Account Access Suspended</span>
                              )}
                            </div>
                          ) : (
                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: '#10b981', fontSize: '0.72rem', fontWeight: 600 }}>
                              <ShieldCheck size={13} /> ACTIVE
                            </span>
                          )}
                        </td>

                        {/* Actions */}
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', alignItems: 'center' }} onClick={e => e.stopPropagation()}>
                            {isBlocked ? (
                              <button
                                className="btn-secondary"
                                onClick={e => openUnblockModal(u, e)}
                                style={{ fontSize: '0.7rem', padding: '4px 10px', color: '#10b981', borderColor: 'rgba(16,185,129,0.35)' }}
                              >
                                <Unlock size={12} /> Unblock
                              </button>
                            ) : (
                              <button
                                className="btn-secondary"
                                onClick={e => openBlockModal(u, e)}
                                disabled={isAdminUser}
                                title={isAdminUser ? 'Administrator accounts cannot be restricted' : 'Block user access'}
                                style={{
                                  fontSize: '0.7rem',
                                  padding: '4px 10px',
                                  color: isAdminUser ? 'var(--text-secondary)' : '#ef4444',
                                  borderColor: isAdminUser ? 'var(--border-color)' : 'rgba(239,68,68,0.35)',
                                  opacity: isAdminUser ? 0.5 : 1,
                                }}
                              >
                                <Lock size={12} /> Block User
                              </button>
                            )}

                            <button
                              className="btn-secondary"
                              onClick={e => {
                                e.stopPropagation();
                                resetRisk(u.username);
                              }}
                              title="Reset risk score"
                              style={{ fontSize: '0.7rem', padding: '4px 8px' }}
                            >
                              <RefreshCw size={11} /> Reset
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </SocCard>

        {/* User Profile Panel Side Drawer */}
        {selectedUser && (
          <SocCard>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div>
                <div className="eyebrow" style={{ marginBottom: 2 }}>SECURITY MONITOR</div>
                <strong style={{ fontSize: '1.05rem', color: 'var(--accent-gold)' }}>{selectedUser}</strong>
              </div>
              <button className="btn-secondary" onClick={() => { setSelectedUser(null); setProfile(null); }}>
                <X size={14} /> Close
              </button>
            </div>

            {profileLoading ? (
              <LoadingState label="Fetching telemetry..." compact />
            ) : profile ? (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))', gap: 8, marginBottom: 16 }}>
                  {[
                    ['Score', `${profile.risk?.risk_score ?? 0}/100`, RISK_COLOR[profile.risk?.risk_level] || '#64748b'],
                    ['Level', profile.risk?.risk_level || 'LOW', RISK_COLOR[profile.risk?.risk_level] || '#64748b'],
                    ['Malicious', profile.risk?.malicious_count ?? 0, '#ef4444'],
                    ['Suspicious', profile.risk?.suspicious_count ?? 0, '#f59e0b'],
                    ['Total Prompts', profile.risk?.total_prompts ?? 0, 'var(--text-primary)'],
                  ].map(([l, v, c]) => (
                    <div key={l} style={{ padding: '8px 10px', background: 'var(--bg-dark)', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                      <div style={{ fontSize: '0.58rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 2 }}>{l}</div>
                      <div style={{ fontSize: '1rem', fontWeight: 800, color: c }}>{v}</div>
                    </div>
                  ))}
                </div>

                {/* Status banner in profile */}
                <div style={{ padding: '10px 12px', background: 'var(--bg-dark)', border: '1px solid var(--border-color)', borderRadius: 8, marginBottom: 14, fontSize: '0.78rem' }}>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.65rem', uppercase: true, marginBottom: 4 }}>RESTRICTION DETAILS</div>
                  {profile.chat_activity?.blocked_until ? (
                    <div style={{ color: '#ef4444' }}>
                      <strong>Restricted until: </strong> {fmtTime(profile.chat_activity.blocked_until)}
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                        Reason: {profile.chat_activity.block_reason || 'No reason provided'}
                      </div>
                    </div>
                  ) : (
                    <div style={{ color: '#10b981' }}>✅ Full chat access active (No restrictions)</div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
                  <button className="btn-secondary" onClick={() => resetRisk(selectedUser)} style={{ fontSize: '0.72rem' }}>
                    Reset Risk Score
                  </button>
                  {profile.chat_activity?.blocked_until ? (
                    <button className="btn-secondary" onClick={e => openUnblockModal({ username: selectedUser }, e)} style={{ fontSize: '0.72rem', color: '#10b981', borderColor: 'rgba(16,185,129,0.3)' }}>
                      <Unlock size={12} /> Lift Restriction
                    </button>
                  ) : (
                    <button className="btn-secondary" onClick={e => openBlockModal({ username: selectedUser }, e)} style={{ fontSize: '0.72rem', color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)' }}>
                      <Lock size={12} /> Block Access
                    </button>
                  )}
                </div>

                <div className="eyebrow" style={{ marginBottom: 8 }}>RECENT THREAT telemetry</div>
                {(profile.recent_logs || []).slice(0, 6).map(l => (
                  <div key={l.request_id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0', borderTop: '1px solid var(--border-color)' }}>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, background: l.classification === 'MALICIOUS' ? '#ef4444' : l.classification === 'SUSPICIOUS' ? '#f59e0b' : '#10b981' }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {l.threat_type}
                      </div>
                      <div style={{ fontSize: '0.64rem', color: 'var(--text-secondary)' }}>
                        {l.severity} · {fmtTime(l.timestamp)}
                      </div>
                    </div>
                    <span style={{ fontSize: '0.62rem', color: l.action === 'BLOCKED' ? '#ef4444' : '#64748b', fontFamily: 'var(--font-mono)' }}>{l.action}</span>
                  </div>
                ))}
              </>
            ) : null}
          </SocCard>
        )}
      </div>

      {/* ========================================================================= */}
      {/* PROFESSIONAL BLOCK USER WARNING MODAL */}
      {/* ========================================================================= */}
      {blockModalUser && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)', display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 540,
              background: 'var(--bg-panel)',
              border: '1px solid rgba(239,68,68,0.4)',
              boxShadow: '0 10px 40px rgba(0,0,0,0.8)',
              borderRadius: 12,
              padding: 24,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.3)', display: 'grid', placeItems: 'center', color: '#ef4444' }}>
                  <ShieldAlert size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--text-primary)' }}>Confirm User Restriction</h3>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Apply security block to user account</div>
                </div>
              </div>
              <button onClick={() => setBlockModalUser(null)} style={{ background: 'none', border: 0, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            {/* Target Summary Card */}
            <div style={{ background: 'var(--bg-dark)', padding: '12px 14px', borderRadius: 8, border: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <strong style={{ fontSize: '0.9rem', color: 'var(--text-primary)' }}>{blockModalUser.username}</strong>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{blockModalUser.email || 'No email registered'}</div>
              </div>
              <SocBadge label={`Risk: ${blockModalUser.risk_score}/100`} color={RISK_COLOR[blockModalUser.risk_level] || '#ef4444'} />
            </div>

            {/* Duration Options */}
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
                Select Restriction Duration:
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {DURATION_OPTIONS.map(opt => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setBlockDuration(opt.value)}
                    style={{
                      padding: '10px 12px',
                      borderRadius: 8,
                      textAlign: 'left',
                      border: blockDuration === opt.value ? '1px solid var(--accent-gold)' : '1px solid var(--border-color)',
                      background: blockDuration === opt.value ? 'rgba(245,197,24,0.1)' : 'var(--bg-dark)',
                      color: blockDuration === opt.value ? 'var(--accent-gold)' : 'var(--text-primary)',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                  >
                    <div style={{ fontSize: '0.8rem', fontWeight: 700 }}>{opt.label}</div>
                    <div style={{ fontSize: '0.62rem', color: 'var(--text-secondary)', marginTop: 2 }}>{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Reason Textarea */}
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 6 }}>
                Reason for Blocking:
              </label>
              <textarea
                rows={2}
                value={blockReason}
                onChange={e => setBlockReason(e.target.value)}
                placeholder="Enter justification for audit log..."
                style={{
                  width: '100%',
                  background: 'var(--bg-dark)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 8,
                  padding: 10,
                  color: 'var(--text-primary)',
                  fontSize: '0.82rem',
                  outline: 'none',
                  resize: 'vertical',
                }}
              />
            </div>

            {/* Exact Confirmation Required */}
            <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.25)', padding: 12, borderRadius: 8 }}>
              <div style={{ fontSize: '0.75rem', color: '#ef4444', fontWeight: 700, marginBottom: 6 }}>
                ⚠️ VERIFICATION REQUIRED
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: 8 }}>
                To confirm this block action, type exactly <strong style={{ color: 'var(--text-primary)' }}>CONFIRM BLOCK</strong> in the field below:
              </div>
              <input
                type="text"
                value={confirmInput}
                onChange={e => setConfirmInput(e.target.value)}
                placeholder="CONFIRM BLOCK"
                style={{
                  width: '100%',
                  background: 'var(--bg-dark)',
                  border: confirmInput.trim() === 'CONFIRM BLOCK' ? '1px solid #10b981' : '1px solid var(--border-color)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)',
                  letterSpacing: '1px',
                  outline: 'none',
                }}
              />
            </div>

            {/* Footer Actions */}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 4 }}>
              <button className="btn-secondary" onClick={() => setBlockModalUser(null)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleApplyBlock}
                disabled={confirmInput.trim() !== 'CONFIRM BLOCK' || isSubmittingBlock}
                style={{
                  width: 'auto',
                  background: confirmInput.trim() === 'CONFIRM BLOCK' ? '#ef4444' : '#64748b',
                  color: '#fff',
                  opacity: confirmInput.trim() === 'CONFIRM BLOCK' ? 1 : 0.4,
                  cursor: confirmInput.trim() === 'CONFIRM BLOCK' ? 'pointer' : 'not-allowed',
                }}
              >
                {isSubmittingBlock ? 'Applying Restriction...' : 'Apply Block Restriction'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* UNBLOCK MODAL */}
      {/* ========================================================================= */}
      {unblockModalUser && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)', display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 460,
              background: 'var(--bg-panel)',
              border: '1px solid rgba(16,185,129,0.4)',
              boxShadow: '0 10px 40px rgba(0,0,0,0.8)',
              borderRadius: 12,
              padding: 24,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.3)', display: 'grid', placeItems: 'center', color: '#10b981' }}>
                  <Unlock size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--text-primary)' }}>Lift Access Restriction</h3>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Restore full chat access for user</div>
                </div>
              </div>
              <button onClick={() => setUnblockModalUser(null)} style={{ background: 'none', border: 0, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              Are you sure you want to restore full chat privileges for <strong>{unblockModalUser.username}</strong>?
            </p>

            <div>
              <label style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                Unblock Reason (recorded in audit trail):
              </label>
              <input
                type="text"
                value={unblockReason}
                onChange={e => setUnblockReason(e.target.value)}
                placeholder="Restriction lifted by administrator"
                style={{
                  width: '100%',
                  background: 'var(--bg-dark)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  color: 'var(--text-primary)',
                  fontSize: '0.84rem',
                  outline: 'none',
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 8 }}>
              <button className="btn-secondary" onClick={() => setUnblockModalUser(null)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={handleApplyUnblock}
                disabled={isSubmittingUnblock}
                style={{ width: 'auto', background: '#10b981', color: '#fff' }}
              >
                {isSubmittingUnblock ? 'Restoring...' : 'Confirm Unblock'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
