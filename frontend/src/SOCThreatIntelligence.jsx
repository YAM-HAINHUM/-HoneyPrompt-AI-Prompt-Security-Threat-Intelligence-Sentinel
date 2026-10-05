import { useState, useEffect } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtPct, SEV_COLOR } from './socUtils';

const RANGES = [{ label: '24H', hours: 24 }, { label: '7D', hours: 168 }, { label: '30D', hours: 720 }];

export default function SOCThreatIntelligence() {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');

  const load = async (h) => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/api/soc/threat-intelligence?hours=${h}`);
      setData(res.data);
    } catch (e) {
      setNotice(e.response?.data?.detail || 'Failed to load threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(hours); }, [hours]);

  const topTypes = Object.entries(data?.top_attack_types || {}).sort((a, b) => b[1] - a[1]);
  const topUsers = Object.entries(data?.top_targeted_users || {}).sort((a, b) => b[1] - a[1]);
  const sevDist = data?.severity_distribution || {};
  const maxType = Math.max(1, ...topTypes.map(([, v]) => v));
  const hourlyEntries = Object.entries(data?.hourly_trend || {}).slice(-24);
  const maxHourly = Math.max(1, ...hourlyEntries.map(([, v]) => (v.safe || 0) + (v.suspicious || 0) + (v.malicious || 0)));

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🔥" title="Threat Intelligence" subtitle="Attack patterns, trends and distribution">
        <div style={{ display: 'flex', gap: 6 }}>
          {RANGES.map(r => (
            <button key={r.label} className={`filter-pill${hours === r.hours ? ' active' : ''}`}
              onClick={() => setHours(r.hours)}>{r.label}</button>
          ))}
        </div>
      </SocPageHeader>

      <SocNotice msg={notice} onDismiss={() => setNotice('')} type="error" />

      {loading ? (
        <div className="hp-loading"><span>Loading threat intelligence...</span></div>
      ) : <>
        {/* Summary stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12 }}>
          <MiniStat label="Total Events" value={data?.total} />
          <MiniStat label="Safe" value={data?.safe} color="#10b981" />
          <MiniStat label="Suspicious" value={data?.suspicious} color="#f59e0b" />
          <MiniStat label="Malicious" value={data?.malicious} color="#ef4444" />
          <MiniStat label="Blocked" value={data?.blocked} color="#dc2626" />
          <MiniStat label="Block Rate" value={fmtPct(data?.block_rate)} color="#f97316" />
          <MiniStat label="FP Rate" value={fmtPct(data?.false_positive_rate)} color="#64748b" />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* Attack type distribution */}
          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>TOP ATTACK TYPES</div>
            {topTypes.length === 0 ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>No attacks in this window.</p>
              : topTypes.map(([type, count]) => (
                <div key={type} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: '0.76rem' }}>
                    <span style={{ color: 'var(--text-primary)' }}>{type}</span>
                    <strong style={{ color: '#ef4444', fontFamily: 'var(--font-mono)' }}>{count}</strong>
                  </div>
                  <div style={{ height: 5, background: 'var(--bg-dark)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(count / maxType) * 100}%`, background: '#ef4444', borderRadius: 3, transition: 'width 0.4s' }} />
                  </div>
                </div>
              ))}
          </SocCard>

          {/* Severity distribution */}
          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>SEVERITY DISTRIBUTION</div>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].map(sev => {
              const count = sevDist[sev] || 0;
              const total = Math.max(1, data?.total || 1);
              return (
                <div key={sev} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: '0.76rem' }}>
                    <span style={{ color: SEV_COLOR[sev] || '#64748b', fontWeight: 600 }}>{sev}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{count} ({Math.round(count / total * 100)}%)</span>
                  </div>
                  <div style={{ height: 5, background: 'var(--bg-dark)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(count / total) * 100}%`, background: SEV_COLOR[sev] || '#64748b', borderRadius: 3, transition: 'width 0.4s' }} />
                  </div>
                </div>
              );
            })}
          </SocCard>
        </div>

        {/* Hourly trend chart */}
        <SocCard>
          <div className="eyebrow" style={{ marginBottom: 12 }}>ATTACK FREQUENCY TREND (HOURLY)</div>
          {hourlyEntries.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>No hourly data available.</p>
          ) : (
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 100, padding: '0 4px', borderBottom: '1px solid var(--border-color)' }}>
              {hourlyEntries.map(([hour, v]) => {
                const total = (v.safe || 0) + (v.suspicious || 0) + (v.malicious || 0);
                const pct = total / maxHourly;
                return (
                  <div key={hour} title={`${hour}\nSafe: ${v.safe} Suspicious: ${v.suspicious} Malicious: ${v.malicious}`}
                    style={{ flex: 1, display: 'flex', flexDirection: 'column-reverse', height: `${Math.max(2, pct * 100)}%`, borderRadius: '2px 2px 0 0', overflow: 'hidden', cursor: 'default' }}>
                    <div style={{ flex: v.safe || 0, background: '#10b981', minHeight: v.safe ? 1 : 0 }} />
                    <div style={{ flex: v.suspicious || 0, background: '#f59e0b', minHeight: v.suspicious ? 1 : 0 }} />
                    <div style={{ flex: v.malicious || 0, background: '#ef4444', minHeight: v.malicious ? 1 : 0 }} />
                  </div>
                );
              })}
            </div>
          )}
          <div style={{ display: 'flex', gap: 16, marginTop: 10 }}>
            {[['Safe', '#10b981'], ['Suspicious', '#f59e0b'], ['Malicious', '#ef4444']].map(([l, c]) => (
              <span key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.65rem', color: 'var(--text-secondary)' }}>
                <i style={{ width: 8, height: 8, borderRadius: 2, background: c, display: 'inline-block' }} />{l}
              </span>
            ))}
          </div>
        </SocCard>

        {/* Top targeted users */}
        <SocCard>
          <div className="eyebrow" style={{ marginBottom: 12 }}>MOST TARGETED USERS</div>
          {topUsers.length === 0 ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>No user attack data.</p>
            : <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
              {topUsers.map(([user, count]) => (
                <div key={user} style={{ padding: '10px 14px', background: 'var(--bg-dark)', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                  <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{user}</div>
                  <div style={{ fontSize: '0.68rem', color: '#ef4444', fontFamily: 'var(--font-mono)' }}>{count} malicious attempts</div>
                </div>
              ))}
            </div>}
        </SocCard>
      </>}
    </div>
  );
}
