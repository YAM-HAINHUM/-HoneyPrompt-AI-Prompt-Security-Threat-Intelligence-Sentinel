import { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, ShieldAlert, ShieldCheck, Users, Activity, AlertTriangle, Zap, Clock, TrendingUp } from 'lucide-react';
import { API, SEV_COLOR, fmtTime, MiniStat, SocPageHeader, SocCard, SocNotice } from './socUtils';
import LoadingState from './LoadingState';

const STATUS_CFG = {
  NOMINAL: { color: '#10b981', label: '🟢 NOMINAL', icon: ShieldCheck },
  WARNING: { color: '#f59e0b', label: '🟡 WARNING', icon: AlertTriangle },
  CRITICAL: { color: '#ef4444', label: '🔴 CRITICAL', icon: ShieldAlert },
};

export default function SOCCommandCenter() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [recentAlerts, setRecentAlerts] = useState([]);

  const load = async () => {
    try {
      const [cc, al] = await Promise.all([
        axios.get(`${API}/api/soc/command-center`),
        axios.get(`${API}/api/soc/alerts?page=1&page_size=8&exclude_test=true`),
      ]);
      setData(cc.data);
      setRecentAlerts(al.data.items || []);
      setError('');
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load command center');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); const id = setInterval(load, 8000); return () => clearInterval(id); }, []);

  if (loading) return <LoadingState label="Loading Security Command Center..." fullScreen />;

  const cfg = STATUS_CFG[data?.system_status] || STATUS_CFG.NOMINAL;
  const StatusIcon = cfg.icon;

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18, paddingBottom: 30 }}>
      <SocPageHeader icon="🛡️" title="Security Command Center" subtitle="Real-time platform security overview">
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderRadius: 8, border: `1px solid ${cfg.color}44`, background: `${cfg.color}11`, color: cfg.color, fontFamily: 'var(--font-mono)', fontSize: '0.78rem', fontWeight: 700 }}>
          <StatusIcon size={15} /> {cfg.label}
        </span>
      </SocPageHeader>

      <SocNotice msg={error} onDismiss={() => setError('')} type="error" />

      {/* Primary stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12 }}>
        <MiniStat label="Total Users" value={data?.total_users} color="var(--accent-gold)" />
        <MiniStat label="Active Users" value={data?.active_users} color="#10b981" />
        <MiniStat label="Suspended" value={data?.suspended_users} color="#f97316" />
        <MiniStat label="Chat Blocked" value={data?.chat_blocked_users} color="#ef4444" />
        <MiniStat label="Total Prompts" value={data?.total_prompts} />
        <MiniStat label="Safe" value={data?.safe} color="#10b981" />
        <MiniStat label="Suspicious" value={data?.suspicious} color="#f59e0b" />
        <MiniStat label="Malicious" value={data?.malicious} color="#ef4444" />
        <MiniStat label="Critical" value={data?.critical} color="#dc2626" />
        <MiniStat label="Active Alerts" value={data?.active_alerts} color="#f97316" />
      </div>

      {/* Threat timeline */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        {[
          { label: 'Threats · Last 24h', value: data?.threats_24h, icon: Clock, color: '#ef4444' },
          { label: 'Threats · Last 7d', value: data?.threats_7d, icon: TrendingUp, color: '#f97316' },
          { label: 'Threats · Last 30d', value: data?.threats_30d, icon: Activity, color: '#f59e0b' },
        ].map(({ label, value, icon: Icon, color }) => (
          <SocCard key={label} style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '16px 20px' }}>
            <div style={{ width: 42, height: 42, display: 'grid', placeItems: 'center', borderRadius: 10, background: `${color}15`, color, flexShrink: 0 }}>
              <Icon size={20} />
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 4 }}>{label}</div>
              <div style={{ fontSize: '1.8rem', fontWeight: 800, color, lineHeight: 1 }}>{value ?? 0}</div>
            </div>
          </SocCard>
        ))}
      </div>

      {/* Recent critical alerts */}
      <SocCard>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <div>
            <div className="eyebrow" style={{ marginBottom: 3 }}>LIVE FEED</div>
            <strong style={{ fontSize: '0.95rem' }}>Recent Security Alerts</strong>
          </div>
          <span style={{ color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontSize: '0.62rem' }}>
            <i style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', marginRight: 6, boxShadow: '0 0 6px currentColor' }} />
            LIVE
          </span>
        </div>
        {recentAlerts.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: 0 }}>No recent alerts. System is clean.</p>
        ) : recentAlerts.map(a => (
          <div key={a.alert_id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderTop: '1px solid var(--border-color)' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_COLOR[a.severity] || '#64748b', flexShrink: 0, boxShadow: `0 0 6px ${SEV_COLOR[a.severity] || '#64748b'}` }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {a.threat_type} · <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>{a.user}</span>
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                {a.severity} · {Math.round((a.confidence || 0) * 100)}% confidence · {fmtTime(a.timestamp)}
              </div>
            </div>
            <span style={{ padding: '3px 7px', borderRadius: 4, fontSize: '0.62rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: a.status === 'NEW' ? '#ef4444' : '#64748b', border: `1px solid ${a.status === 'NEW' ? '#ef444444' : '#64748b44'}` }}>
              {a.status}
            </span>
          </div>
        ))}
      </SocCard>
    </div>
  );
}
