import { useState, useEffect } from 'react';
import axios from 'axios';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SocNotice } from './socUtils';

const POLICY_FIELDS = [
  { key: 'warning_threshold', label: 'Warning Threshold', desc: 'Consecutive malicious prompts before warning', type: 'number', min: 1, max: 20 },
  { key: 'block_threshold', label: 'Block Threshold', desc: 'Consecutive malicious prompts before chat block', type: 'number', min: 2, max: 50 },
  { key: 'block_cooldown_minutes', label: 'Block Duration (minutes)', desc: 'How long a chat block lasts', type: 'number', min: 1, max: 1440 },
  { key: 'repeated_attack_window_minutes', label: 'Attack Pattern Window (minutes)', desc: 'Time window for repeated attack detection', type: 'number', min: 5, max: 1440 },
  { key: 'repeated_attack_count', label: 'Repeated Attack Count', desc: 'Attacks in window to trigger pattern alert', type: 'number', min: 2, max: 20 },
  { key: 'rate_limit_chat_per_minute', label: 'Chat Rate Limit (req/min)', desc: 'Max chat requests per user per minute', type: 'number', min: 1, max: 200 },
  { key: 'rate_limit_auth_per_minute', label: 'Auth Rate Limit (req/min)', desc: 'Max auth requests per IP per minute', type: 'number', min: 1, max: 100 },
  { key: 'session_timeout_minutes', label: 'Session Timeout (minutes)', desc: 'Idle session expiry time', type: 'number', min: 5, max: 1440 },
  { key: 'suspicious_ml_threshold', label: 'Suspicious ML Threshold', desc: 'ML probability floor for SUSPICIOUS classification', type: 'float', min: 0.1, max: 0.95 },
  { key: 'malicious_ml_threshold', label: 'Malicious ML Threshold', desc: 'ML probability floor for MALICIOUS classification', type: 'float', min: 0.5, max: 0.99 },
  { key: 'alert_severity_threshold', label: 'Alert Severity Threshold', desc: 'Minimum severity to create a SOC alert', type: 'select', options: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
  { key: 'auto_block_on_critical', label: 'Auto-Block on Critical', desc: 'Automatically block users on CRITICAL threats', type: 'bool' },
  { key: 'auto_alert_on_repeated', label: 'Auto-Alert on Repeated Attacks', desc: 'Create alert when repeated attack pattern detected', type: 'bool' },
];

export default function SOCPolicies() {
  const [policies, setPolicies] = useState({});
  const [draft, setDraft] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });
  const [dirty, setDirty] = useState(false);

  const load = async () => {
    try {
      const res = await axios.get(`${API}/api/soc/policies`);
      setPolicies(res.data);
      setDraft(res.data);
      setDirty(false);
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to load policies', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const set = (key, value) => {
    setDraft(d => ({ ...d, [key]: value }));
    setDirty(true);
  };

  const save = async () => {
    if (draft.block_threshold <= draft.warning_threshold) {
      setNotice({ msg: 'Block threshold must be greater than warning threshold', type: 'error' });
      return;
    }
    setSaving(true);
    try {
      const res = await axios.patch(`${API}/api/soc/policies`, draft);
      setPolicies(res.data);
      setDraft(res.data);
      setDirty(false);
      setNotice({ msg: 'Security policies saved and audit-logged', type: 'success' });
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Save failed', type: 'error' });
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <LoadingState label="Loading security policies..." fullScreen={false} />;

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="⚙️" title="Security Policy Center" subtitle="Configure detection thresholds, rate limits and automated responses">
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn-secondary" onClick={load} disabled={saving}>Reset</button>
          <button className="btn-primary" onClick={save} disabled={saving || !dirty} style={{ width: 'auto', padding: '9px 20px' }}>
            {saving ? 'Saving...' : 'Save Policies'}
          </button>
        </div>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {dirty && (
        <div style={{ padding: '10px 16px', background: 'rgba(245,197,24,0.06)', border: '1px solid rgba(245,197,24,0.2)', borderRadius: 8, fontSize: '0.78rem', color: 'var(--accent-gold)' }}>
          ⚠ You have unsaved changes. Click "Save Policies" to apply and audit-log them.
        </div>
      )}

      <SocCard>
        {POLICY_FIELDS.map(f => (
          <div key={f.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, padding: '14px 0', borderBottom: '1px solid var(--border-color)' }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 3 }}>{f.label}</div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>{f.desc}</div>
            </div>
            <div style={{ flexShrink: 0 }}>
              {f.type === 'bool' ? (
                <button
                  onClick={() => set(f.key, !draft[f.key])}
                  className={`toggle-switch${draft[f.key] ? ' on' : ''}`}
                  aria-label={f.label}
                />
              ) : f.type === 'select' ? (
                <select className="search-input" value={draft[f.key] || ''} onChange={e => set(f.key, e.target.value)} style={{ minWidth: 120 }}>
                  {f.options.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input
                  type="number"
                  className="search-input"
                  value={draft[f.key] ?? ''}
                  min={f.min} max={f.max}
                  step={f.type === 'float' ? 0.01 : 1}
                  onChange={e => set(f.key, f.type === 'float' ? parseFloat(e.target.value) : parseInt(e.target.value, 10))}
                  style={{ width: 100, textAlign: 'right' }}
                />
              )}
            </div>
          </div>
        ))}
      </SocCard>

      <SocCard>
        <div className="eyebrow" style={{ marginBottom: 10 }}>CURRENT SAVED VALUES</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
          {Object.entries(policies).map(([k, v]) => (
            <div key={k} style={{ padding: '8px 12px', background: 'var(--bg-dark)', borderRadius: 6, border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 3 }}>{k.replace(/_/g, ' ')}</div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)' }}>{String(v)}</div>
            </div>
          ))}
        </div>
      </SocCard>
    </div>
  );
}
