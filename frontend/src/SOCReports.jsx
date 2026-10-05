import { useState } from 'react';
import axios from 'axios';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtTime, fmtPct } from './socUtils';

const RANGES = [{ label: 'Daily (24H)', hours: 24 }, { label: 'Weekly (7D)', hours: 168 }, { label: 'Monthly (30D)', hours: 720 }];

export default function SOCReports() {
  const [hours, setHours] = useState(24);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });

  const generate = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API}/api/soc/reports/summary?hours=${hours}`);
      setReport(res.data);
      setNotice({ msg: '', type: 'info' });
    } catch (e) {
      setNotice({ msg: e.response?.data?.detail || 'Failed to generate report', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = async () => {
    try {
      const res = await axios.get(`${API}/api/soc/reports/csv?hours=${hours}`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `honeyprompt_report_${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setNotice({ msg: 'CSV export failed', type: 'error' });
    }
  };

  const ts = report?.threat_summary;

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="📊" title="Security Reports" subtitle="Generate and export security reports" />
      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      <SocCard style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 6 }}>
            {RANGES.map(r => (
              <button key={r.label} className={`filter-pill${hours === r.hours ? ' active' : ''}`}
                onClick={() => setHours(r.hours)}>{r.label}</button>
            ))}
          </div>
          <button className="btn-primary" onClick={generate} disabled={loading} style={{ width: 'auto', padding: '9px 20px' }}>
            {loading ? 'Generating...' : 'Generate Report'}
          </button>
          <button className="btn-secondary" onClick={exportCSV} style={{ padding: '9px 16px' }}>
            Export CSV
          </button>
        </div>
      </SocCard>

      {report && (
        <>
          <div style={{ padding: '10px 16px', background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 8, fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
            Report generated: <strong style={{ color: 'var(--text-primary)' }}>{fmtTime(report.generated_at)}</strong> · Window: <strong style={{ color: 'var(--accent-gold)' }}>{report.window_hours}h</strong>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12 }}>
            <MiniStat label="Total Users" value={report.total_users} />
            <MiniStat label="High Risk Users" value={report.high_risk_users} color="#f97316" />
            <MiniStat label="Open Alerts" value={report.open_alerts} color="#ef4444" />
            <MiniStat label="Open Incidents" value={report.open_incidents} color="#f59e0b" />
            <MiniStat label="Total Events" value={ts?.total} />
            <MiniStat label="Malicious" value={ts?.malicious} color="#ef4444" />
            <MiniStat label="Block Rate" value={fmtPct(ts?.block_rate)} color="#f97316" />
            <MiniStat label="FP Rate" value={fmtPct(ts?.false_positive_rate)} color="#64748b" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <SocCard>
              <div className="eyebrow" style={{ marginBottom: 12 }}>TOP ATTACK TYPES</div>
              {Object.entries(ts?.top_attack_types || {}).length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No attacks in this window.</p>
                : Object.entries(ts?.top_attack_types || {}).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                  <div key={type} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.76rem' }}>
                    <span style={{ color: 'var(--text-primary)' }}>{type}</span>
                    <strong style={{ color: '#ef4444', fontFamily: 'var(--font-mono)' }}>{count}</strong>
                  </div>
                ))}
            </SocCard>

            <SocCard>
              <div className="eyebrow" style={{ marginBottom: 12 }}>HIGH RISK USERS</div>
              {(report.top_risk_users || []).length === 0
                ? <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>No high-risk users.</p>
                : (report.top_risk_users || []).map(u => (
                  <div key={u.username} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--border-color)' }}>
                    <div>
                      <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)' }}>{u.username}</div>
                      <div style={{ fontSize: '0.62rem', color: 'var(--text-secondary)' }}>{u.malicious_count} malicious · {u.suspicious_count} suspicious</div>
                    </div>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, color: u.risk_score >= 75 ? '#dc2626' : u.risk_score >= 50 ? '#f97316' : '#f59e0b', fontFamily: 'var(--font-mono)' }}>
                      {u.risk_score}/100
                    </span>
                  </div>
                ))}
            </SocCard>
          </div>

          {report.model_info && !report.model_info.error && (
            <SocCard>
              <div className="eyebrow" style={{ marginBottom: 12 }}>MODEL PERFORMANCE SNAPSHOT</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
                {[
                  ['Accuracy', fmtPct(report.model_info.accuracy)],
                  ['Precision', fmtPct(report.model_info.precision)],
                  ['Recall', fmtPct(report.model_info.recall)],
                  ['F1 Score', fmtPct(report.model_info.f1)],
                  ['ROC-AUC', report.model_info.roc_auc?.toFixed(4)],
                  ['FP Rate', fmtPct(report.model_info.false_positive_rate)],
                ].map(([k, v]) => (
                  <div key={k} style={{ padding: '8px 12px', background: 'var(--bg-dark)', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 3 }}>{k}</div>
                    <div style={{ fontSize: '0.9rem', fontWeight: 700, color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)' }}>{v ?? '—'}</div>
                  </div>
                ))}
              </div>
            </SocCard>
          )}
        </>
      )}
    </div>
  );
}
