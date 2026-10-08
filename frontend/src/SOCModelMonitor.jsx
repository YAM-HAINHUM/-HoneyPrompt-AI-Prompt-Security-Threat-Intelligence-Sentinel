import { useEffect, useState } from 'react';
import axios from 'axios';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtPct } from './socUtils';

export default function SOCModelMonitor() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState('');

  useEffect(() => {
    axios.get(`${API}/api/soc/model`)
      .then(r => setData(r.data))
      .catch(e => setNotice(e.response?.data?.detail || 'Failed to load model info'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <LoadingState label="Loading AI model telemetry..." fullScreen={false} />;

  const warn = data?.recall != null && data.recall < 0.85;
  const matrix = data?.confusion_matrix;
  const labels = data?.confusion_matrix_labels || ['SAFE', 'MALICIOUS'];

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 16, paddingBottom: 30 }}>
      <SocPageHeader icon="🤖" title="AI Model Monitoring" subtitle="NLP threat classifier performance and health" />
      <SocNotice msg={notice} onDismiss={() => setNotice('')} type="error" />

      {warn && (
        <div style={{ padding: '12px 16px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, color: '#ef4444', fontSize: '0.82rem' }}>
          ⚠ Model recall is below 85% — consider retraining on updated data.
        </div>
      )}

      {data?.error ? (
        <SocCard><p style={{ color: 'var(--text-secondary)' }}>{data.error}</p></SocCard>
      ) : <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12 }}>
          <MiniStat label="Accuracy" value={fmtPct(data?.accuracy)} color="#10b981" />
          <MiniStat label="Precision" value={fmtPct(data?.precision)} color="#10b981" />
          <MiniStat label="Recall" value={fmtPct(data?.recall)} color={warn ? '#ef4444' : '#10b981'} />
          <MiniStat label="F1 Score" value={fmtPct(data?.f1)} color="#10b981" />
          <MiniStat label="ROC-AUC" value={data?.roc_auc != null ? data.roc_auc.toFixed(4) : '—'} color="#10b981" />
          <MiniStat label="FP Rate" value={fmtPct(data?.false_positive_rate)} color="#f59e0b" />
          <MiniStat label="FN Rate" value={fmtPct(data?.false_negative_rate)} color={data?.false_negative_rate > 0.1 ? '#ef4444' : '#f59e0b'} />
          <MiniStat label="Version" value={`v${data?.model_version || 2}`} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>MODEL DETAILS</div>
            {[
              ['Architecture', data?.model],
              ['Dataset Files', (data?.dataset_files || []).join(', ')],
              ['Clean Rows', data?.clean_rows],
              ['Train Size', data?.split_sizes?.train],
              ['Val Size', data?.split_sizes?.validation],
              ['Test Size', data?.split_sizes?.test],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.76rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{k}</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 500, maxWidth: '60%', textAlign: 'right', overflowWrap: 'anywhere' }}>{String(v ?? '—')}</span>
              </div>
            ))}
          </SocCard>

          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>CLASS DISTRIBUTION</div>
            {Object.entries(data?.class_distribution || {}).map(([cls, count]) => (
              <div key={cls} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: '0.76rem' }}>
                  <span style={{ color: cls === 'MALICIOUS' ? '#ef4444' : '#10b981', fontWeight: 600 }}>{cls}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{count}</span>
                </div>
                <div style={{ height: 5, background: 'var(--bg-dark)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${(count / (data?.clean_rows || 1)) * 100}%`, background: cls === 'MALICIOUS' ? '#ef4444' : '#10b981', borderRadius: 3 }} />
                </div>
              </div>
            ))}

            <div className="eyebrow" style={{ margin: '16px 0 10px' }}>OPERATING THRESHOLDS</div>
            {Object.entries(data?.operating_thresholds || {}).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--border-color)', fontSize: '0.72rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>{k.replace(/_/g, ' ')}</span>
                <span style={{ color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)' }}>{typeof v === 'number' ? v.toFixed(4) : String(v)}</span>
              </div>
            ))}
          </SocCard>
        </div>

        {matrix && (
          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>CONFUSION MATRIX</div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ borderCollapse: 'collapse', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                <thead>
                  <tr>
                    <th style={{ padding: '8px 16px', color: 'var(--text-secondary)', textAlign: 'left' }}>Actual \ Predicted</th>
                    {labels.map(l => <th key={l} style={{ padding: '8px 16px', color: 'var(--text-secondary)' }}>{l}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {matrix.map((row, i) => (
                    <tr key={i}>
                      <td style={{ padding: '8px 16px', color: 'var(--text-secondary)', fontWeight: 600 }}>{labels[i]}</td>
                      {row.map((cell, j) => (
                        <td key={j} style={{ padding: '8px 24px', textAlign: 'center', fontWeight: 700, color: i === j ? '#10b981' : '#ef4444', background: i === j ? 'rgba(16,185,129,0.06)' : 'rgba(239,68,68,0.06)', border: '1px solid var(--border-color)' }}>
                          {cell}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SocCard>
        )}

        {data?.per_class && (
          <SocCard>
            <div className="eyebrow" style={{ marginBottom: 12 }}>PER-CLASS METRICS</div>
            <div style={{ overflowX: 'auto' }}>
              <table className="hp-table">
                <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Support</th></tr></thead>
                <tbody>
                  {Object.entries(data.per_class).map(([cls, m]) => (
                    <tr key={cls}>
                      <td style={{ fontWeight: 700, color: cls === 'MALICIOUS' ? '#ef4444' : '#10b981' }}>{cls}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{fmtPct(m.precision)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{fmtPct(m.recall)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{fmtPct(m.f1)}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{m.support}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SocCard>
        )}
      </>}
    </div>
  );
}
