import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  FileText,
  Download,
  Eye,
  ShieldCheck,
  RefreshCw,
  Clock,
  Lock,
  MessageSquare,
  Bell,
} from 'lucide-react';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtTime, fmtPct, SEV_COLOR } from './socUtils';

const USER_REPORT_TYPES = [
  {
    id: 'personal_security',
    name: 'Personal Security Report',
    desc: 'Comprehensive summary of your prompt safety, risk score, threat breakdown & permissions',
    icon: ShieldCheck,
    badge: 'SECURITY SUMMARY',
  },
  {
    id: 'security_history',
    name: 'My Security History Report',
    desc: 'Chronological timeline of all your prompts, threat scans, classifications & SENTINEL actions',
    icon: FileText,
    badge: 'PROMPT AUDIT',
  },
  {
    id: 'my_chat_activity',
    name: 'My Chat Activity Report',
    desc: 'Audit of your private chat conversations, message counts & security evaluations',
    icon: MessageSquare,
    badge: 'CHAT SESSIONS',
  },
  {
    id: 'security_alerts',
    name: 'My Security Alerts Report',
    desc: 'Security notices, policy warnings & automated protective restrictions for your account',
    icon: Bell,
    badge: 'ALERTS & NOTICES',
  },
];

const DATE_RANGES = [
  { id: 'today', label: 'Today' },
  { id: '7d', label: 'Last 7 Days' },
  { id: '30d', label: 'Last 30 Days' },
  { id: '90d', label: 'Last 90 Days' },
  { id: 'custom', label: 'Custom Range' },
];

const CLASSIFICATIONS = ['ALL', 'SAFE', 'SUSPICIOUS', 'MALICIOUS'];
const SEVERITIES = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export default function UserReportsPage() {
  const [reportType, setReportType] = useState('personal_security');
  const [dateRange, setDateRange] = useState('30d');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [classification, setClassification] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');

  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingExcel, setExportingExcel] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });

  const [historyItems, setHistoryItems] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('generator'); // 'generator' | 'history'

  const buildPayload = () => {
    const p = { report_type: reportType, date_range: dateRange };
    if (dateRange === 'custom' && dateFrom) p.date_from = dateFrom;
    if (dateRange === 'custom' && dateTo) p.date_to = dateTo;
    if (classification !== 'ALL') p.classification = classification;
    if (severity !== 'ALL') p.severity = severity;
    return p;
  };

  const fetchPreview = async (type = reportType) => {
    setLoading(true);
    setNotice({ msg: '', type: 'info' });

    const endpointMap = {
      personal_security: '/api/user/reports/security',
      security_history: '/api/user/reports/history',
      my_chat_activity: '/api/user/reports/activity',
      security_alerts: '/api/user/reports/alerts',
    };

    const url = `${API}${endpointMap[type] || endpointMap.personal_security}`;
    // Build clean params (no undefined values)
    const payload = buildPayload();
    const params = {};
    Object.entries(payload).forEach(([k, v]) => { if (v !== undefined && v !== null) params[k] = v; });

    try {
      const token = localStorage.getItem('hp_token');
      const res = await axios.get(url, {
        params,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      setReportData(res.data);
      setNotice({
        msg: `Preview loaded: ${res.data.record_count ?? 0} account events analyzed.`,
        type: 'success',
      });
      loadUserHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'Failed to generate report preview.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const authHeaders = () => {
    const token = localStorage.getItem('hp_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const exportPDF = async () => {
    setExportingPdf(true);
    setNotice({ msg: 'Generating your confidential PDF security report...', type: 'info' });
    try {
      const payload = buildPayload();
      const res = await axios.post(`${API}/api/user/reports/pdf`, payload, {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_My_${reportType.toUpperCase()}_${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'PDF report downloaded successfully.', type: 'success' });
      loadUserHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'PDF download failed.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setExportingPdf(false);
    }
  };

  const exportExcel = async () => {
    setExportingExcel(true);
    setNotice({ msg: 'Compiling your personal Excel workbook...', type: 'info' });
    try {
      const payload = buildPayload();
      const res = await axios.post(`${API}/api/user/reports/excel`, payload, {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_My_${reportType.toUpperCase()}_${new Date().toISOString().slice(0, 10)}.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'Excel report downloaded successfully.', type: 'success' });
      loadUserHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'Excel export failed.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setExportingExcel(false);
    }
  };

  const loadUserHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await axios.get(`${API}/api/user/reports/generation-history?page=1&page_size=20`, {
        headers: authHeaders(),
      });
      setHistoryItems(res.data?.items || []);
    } catch {
      setHistoryItems([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    fetchPreview(reportType);
    loadUserHistory();
  }, [reportType, dateRange]);

  const activeTypeConfig = USER_REPORT_TYPES.find(t => t.id === reportType) || USER_REPORT_TYPES[0];

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18, paddingBottom: 40 }}>
      {/* Header */}
      <SocPageHeader
        icon="📈"
        title="My Security Reports & Exports"
        subtitle="Export your personal security telemetry, chat safety audit logs, and alert history"
      >
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={`btn-secondary${activeTab === 'generator' ? ' active' : ''}`}
            onClick={() => setActiveTab('generator')}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <FileText size={14} style={{ marginRight: 6 }} /> My Report Center
          </button>
          <button
            className={`btn-secondary${activeTab === 'history' ? ' active' : ''}`}
            onClick={() => {
              setActiveTab('history');
              loadUserHistory();
            }}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <Clock size={14} style={{ marginRight: 6 }} /> Generation History ({historyItems.length})
          </button>
        </div>
      </SocPageHeader>

      {/* Scope Notice */}
      <div style={{ padding: '10px 16px', background: 'rgba(245,197,24,0.06)', border: '1px solid var(--border-gold)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <Lock size={15} color="var(--accent-gold)" />
        <span><strong>Data Privacy Guarantee:</strong> Reports generated here contain ONLY your authorized account data. System security rules, API secrets, and other users' records are strictly protected.</span>
      </div>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {activeTab === 'generator' && (
        <>
          {/* User Report Types Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            {USER_REPORT_TYPES.map(rt => {
              const Icon = rt.icon;
              const isActive = reportType === rt.id;
              return (
                <button
                  key={rt.id}
                  onClick={() => setReportType(rt.id)}
                  style={{
                    background: isActive ? 'color-mix(in srgb, var(--accent-gold) 10%, var(--bg-card))' : 'var(--bg-card)',
                    border: `1px solid ${isActive ? 'var(--accent-gold)' : 'var(--border-color)'}`,
                    borderRadius: 8,
                    padding: '14px 16px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 6,
                    transition: 'all 0.16s ease',
                    boxShadow: isActive ? 'var(--shadow-gold)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: isActive ? 'var(--accent-gold)' : 'var(--text-primary)', fontWeight: 600, fontSize: '0.84rem' }}>
                      <Icon size={16} /> {rt.name}
                    </div>
                    <span style={{ fontSize: '0.58rem', fontFamily: 'var(--font-mono)', padding: '2px 5px', borderRadius: 3, background: isActive ? 'var(--accent-gold)' : 'rgba(255,255,255,0.06)', color: isActive ? '#000' : 'var(--text-secondary)', fontWeight: 700 }}>
                      {rt.badge}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.7rem', color: 'var(--text-secondary)', lineHeight: 1.35 }}>
                    {rt.desc}
                  </p>
                </button>
              );
            })}
          </div>

          {/* Filter & Actions Bar */}
          <SocCard style={{ padding: '16px 20px', borderTop: '3px solid var(--accent-gold)' }}>
            <div className="eyebrow" style={{ marginBottom: 10 }}>
              FILTERS & EXPORT — {activeTypeConfig.name.toUpperCase()}
            </div>

            {/* Date Filters */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginRight: 4, fontWeight: 600 }}>Period:</span>
              {DATE_RANGES.map(r => (
                <button
                  key={r.id}
                  className={`filter-pill${dateRange === r.id ? ' active' : ''}`}
                  onClick={() => setDateRange(r.id)}
                  style={{ fontSize: '0.72rem', padding: '5px 12px' }}
                >
                  {r.label}
                </button>
              ))}

              {dateRange === 'custom' && (
                <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center', marginLeft: 8 }}>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={e => setDateFrom(e.target.value)}
                    className="search-input"
                    style={{ padding: '4px 8px', fontSize: '0.72rem', height: 30 }}
                  />
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>to</span>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={e => setDateTo(e.target.value)}
                    className="search-input"
                    style={{ padding: '4px 8px', fontSize: '0.72rem', height: 30 }}
                  />
                </div>
              )}
            </div>

            {/* Classification & Severity filters for history */}
            {reportType === 'security_history' && (
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 14 }}>
                <div style={{ minWidth: 160 }}>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Classification</label>
                  <select
                    value={classification}
                    onChange={e => setClassification(e.target.value)}
                    className="search-input"
                    style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                  >
                    {CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                <div style={{ minWidth: 160 }}>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Severity</label>
                  <select
                    value={severity}
                    onChange={e => setSeverity(e.target.value)}
                    className="search-input"
                    style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                  >
                    {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', paddingTop: 10, borderTop: '1px solid var(--border-color)' }}>
              <button
                className="btn-primary"
                onClick={() => fetchPreview(reportType)}
                disabled={loading || exportingPdf || exportingExcel}
                style={{ width: 'auto', padding: '9px 20px', display: 'inline-flex', alignItems: 'center', gap: 7 }}
              >
                <Eye size={15} /> Preview Report
              </button>

              <button
                className="btn-secondary"
                onClick={exportPDF}
                disabled={loading || exportingPdf || exportingExcel}
                style={{ padding: '9px 18px', display: 'inline-flex', alignItems: 'center', gap: 7, borderColor: 'var(--border-gold)' }}
              >
                <Download size={15} /> {exportingPdf ? 'Generating PDF...' : 'Download PDF'}
              </button>

              <button
                className="btn-secondary"
                onClick={exportExcel}
                disabled={loading || exportingPdf || exportingExcel}
                style={{ padding: '9px 18px', display: 'inline-flex', alignItems: 'center', gap: 7 }}
              >
                <Download size={15} /> {exportingExcel ? 'Compiling Excel...' : 'Export Excel (.xlsx)'}
              </button>
            </div>

            {/* HoneyBee Loading State */}
            {(loading || exportingPdf || exportingExcel) && (
              <div style={{ marginTop: 16 }}>
                <LoadingState
                  label={exportingPdf ? 'HoneyPrompt is rendering your PDF report...' : exportingExcel ? 'HoneyPrompt is assembling your Excel report...' : 'HoneyPrompt is compiling your security history...'}
                  compact
                />
              </div>
            )}
          </SocCard>

          {/* Interactive User Report Preview */}
          {reportData && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Summary Metrics */}
              {reportData.summary && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12 }}>
                  {reportData.summary.total_prompts !== undefined && <MiniStat label="Total Prompts" value={reportData.summary.total_prompts} />}
                  {reportData.summary.security_score !== undefined && <MiniStat label="Security Score" value={`${reportData.summary.security_score}/100`} color="var(--accent-gold)" />}
                  {reportData.summary.safe !== undefined && <MiniStat label="SAFE Prompts" value={reportData.summary.safe} color="#10b981" />}
                  {reportData.summary.suspicious !== undefined && <MiniStat label="SUSPICIOUS" value={reportData.summary.suspicious} color="#f59e0b" />}
                  {reportData.summary.malicious !== undefined && <MiniStat label="MALICIOUS" value={reportData.summary.malicious} color="#ef4444" />}
                  {reportData.summary.blocked !== undefined && <MiniStat label="Blocked" value={reportData.summary.blocked} color="#f97316" />}
                  {reportData.summary.total_conversations !== undefined && <MiniStat label="Conversations" value={reportData.summary.total_conversations} />}
                  {reportData.summary.total_messages !== undefined && <MiniStat label="Total Messages" value={reportData.summary.total_messages} />}
                </div>
              )}

              {/* Data Table */}
              <SocCard style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="eyebrow">PREVIEW: {activeTypeConfig.name.toUpperCase()}</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {reportData.record_count} total events found
                  </span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  {/* Personal Security Events Table */}
                  {reportType === 'personal_security' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Classification</th>
                          <th>Threat Type</th>
                          <th>Severity</th>
                          <th>Action Taken</th>
                          <th>Prompt Preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.recent_events || []).length === 0 ? (
                          <tr><td colSpan={6} className="empty-table-cell">No security events found for your account in this window.</td></tr>
                        ) : (
                          reportData.recent_events.map((e, idx) => (
                            <tr key={idx}>
                              <td>{fmtTime(e.timestamp)}</td>
                              <td><span className={`soc-badge ${e.classification === 'SAFE' ? 'soc-badge-safe' : 'soc-badge-malicious'}`}>{e.classification}</span></td>
                              <td><strong>{e.threat_type}</strong></td>
                              <td><span style={{ color: SEV_COLOR[e.severity] || '#64748b', fontWeight: 700 }}>{e.severity}</span></td>
                              <td><span style={{ color: e.action === 'BLOCKED' ? '#ef4444' : '#10b981', fontWeight: 600 }}>{e.action}</span></td>
                              <td style={{ fontSize: '0.72rem' }}>{e.prompt_preview || '—'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Security History Table */}
                  {reportType === 'security_history' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Classification</th>
                          <th>Threat Type</th>
                          <th>Severity</th>
                          <th>Confidence</th>
                          <th>Action</th>
                          <th>Reason / Details</th>
                          <th>Prompt Preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.history || []).length === 0 ? (
                          <tr><td colSpan={8} className="empty-table-cell">No history logs match your filter criteria.</td></tr>
                        ) : (
                          reportData.history.slice(0, 40).map((h, idx) => (
                            <tr key={idx}>
                              <td>{fmtTime(h.timestamp)}</td>
                              <td><span className={`soc-badge ${h.classification === 'SAFE' ? 'soc-badge-safe' : 'soc-badge-malicious'}`}>{h.classification}</span></td>
                              <td><strong>{h.threat_type}</strong></td>
                              <td><span style={{ color: SEV_COLOR[h.severity] || '#64748b', fontWeight: 700 }}>{h.severity}</span></td>
                              <td>{fmtPct(h.confidence)}</td>
                              <td><span style={{ color: h.action === 'BLOCKED' ? '#ef4444' : '#10b981', fontWeight: 600 }}>{h.action}</span></td>
                              <td style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{h.reason || 'Normal request processing'}</td>
                              <td style={{ fontSize: '0.72rem' }}>{h.prompt_preview || '—'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* My Chat Activity Table */}
                  {reportType === 'my_chat_activity' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Session Title</th>
                          <th>Conversation ID</th>
                          <th>Created Timestamp</th>
                          <th>Last Updated</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.conversations || []).length === 0 ? (
                          <tr><td colSpan={4} className="empty-table-cell">No saved chat sessions found.</td></tr>
                        ) : (
                          reportData.conversations.map(c => (
                            <tr key={c.conversation_id}>
                              <td><strong>{c.title || 'Untitled Chat'}</strong></td>
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>{c.conversation_id}</td>
                              <td>{fmtTime(c.created_at)}</td>
                              <td>{fmtTime(c.updated_at)}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* My Security Alerts Table */}
                  {reportType === 'security_alerts' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Alert Timestamp</th>
                          <th>Threat Type</th>
                          <th>Severity</th>
                          <th>Classification</th>
                          <th>Action Taken</th>
                          <th>Status</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.alerts || []).length === 0 ? (
                          <tr><td colSpan={7} className="empty-table-cell">No security alerts logged for your account.</td></tr>
                        ) : (
                          reportData.alerts.map(a => (
                            <tr key={a.alert_id || a.timestamp}>
                              <td>{fmtTime(a.timestamp)}</td>
                              <td><strong>{a.threat_type}</strong></td>
                              <td><span style={{ color: SEV_COLOR[a.severity] || '#64748b', fontWeight: 700 }}>{a.severity}</span></td>
                              <td>{a.classification}</td>
                              <td>{a.action}</td>
                              <td><span className="soc-badge">{a.status}</span></td>
                              <td style={{ fontSize: '0.72rem' }}>{a.description}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}
                </div>
              </SocCard>
            </div>
          )}
        </>
      )}

      {/* User Generation History Tab */}
      {activeTab === 'history' && (
        <SocCard style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="eyebrow" style={{ marginBottom: 3 }}>YOUR REPORT ARCHIVE</div>
              <strong style={{ fontSize: '0.95rem' }}>Personal Report Generation History</strong>
            </div>
            <button className="btn-secondary" onClick={loadUserHistory} disabled={historyLoading} style={{ padding: '7px 12px', fontSize: '0.72rem' }}>
              <RefreshCw size={13} style={{ marginRight: 5 }} /> Refresh
            </button>
          </div>

          {historyLoading ? (
            <div style={{ padding: 30 }}>
              <LoadingState label="Loading report history..." compact />
            </div>
          ) : historyItems.length === 0 ? (
            <p style={{ padding: 30, color: 'var(--text-secondary)', margin: 0, textAlign: 'center' }}>
              You haven't generated any export reports yet.
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="hp-table">
                <thead>
                  <tr>
                    <th>Report ID</th>
                    <th>Report Type</th>
                    <th>Format</th>
                    <th>Window</th>
                    <th>Records</th>
                    <th>Status</th>
                    <th>Generated Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {historyItems.map(h => (
                    <tr key={h.report_id}>
                      <td><strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-gold)' }}>{h.report_id}</strong></td>
                      <td>{h.report_type?.replace(/_/g, ' ').toUpperCase()}</td>
                      <td><span className="soc-badge" style={{ background: h.format === 'PDF' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)', color: h.format === 'PDF' ? '#ef4444' : '#10b981' }}>{h.format}</span></td>
                      <td>{h.date_from ? `${h.date_from} → ${h.date_to}` : 'All-time'}</td>
                      <td>{h.record_count}</td>
                      <td><span style={{ color: h.status === 'SUCCESS' ? '#10b981' : '#ef4444', fontWeight: 600 }}>{h.status}</span></td>
                      <td>{fmtTime(h.generated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SocCard>
      )}
    </div>
  );
}
