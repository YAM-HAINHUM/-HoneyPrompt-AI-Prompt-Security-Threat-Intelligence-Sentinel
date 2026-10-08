import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  Calendar,
  Filter,
  Shield,
  AlertTriangle,
  Users,
  Database,
  Activity,
  CheckCircle2,
  Lock,
  Clock,
  ExternalLink,
  Mail,
  X,
  MessageSquare,
  Send,
} from 'lucide-react';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtTime, fmtPct, SEV_COLOR } from './socUtils';

const REPORT_TYPES = [
  {
    id: 'security_overview',
    name: 'Security Overview',
    desc: 'Total users, prompts, threat classification, block rate & system security scores',
    icon: Shield,
    badge: 'EXECUTIVE',
  },
  {
    id: 'threat_intelligence',
    name: 'Threat Intelligence',
    desc: 'Injection, jailbreaks, exfiltration, frequency, severity & targeted users',
    icon: AlertTriangle,
    badge: 'ATTACK INTEL',
  },
  {
    id: 'user_security',
    name: 'User Security & Risk',
    desc: 'Account status, risk scores, consecutive threats, restriction history & activity',
    icon: Users,
    badge: 'USER RISK',
  },
  {
    id: 'audit_log',
    name: 'Audit & Compliance Log',
    desc: 'Administrative actions, policy changes, user restrictions & security overrides',
    icon: Database,
    badge: 'COMPLIANCE',
  },
  {
    id: 'incidents',
    name: 'Security Incidents',
    desc: 'Incident IDs, severities, assigned SOC handlers, containment & resolution time',
    icon: Activity,
    badge: 'SOC INCIDENTS',
  },
  {
    id: 'chat_activity',
    name: 'Chat & Security Activity',
    desc: 'Conversation volume, message traffic, threat detections & blocked communications',
    icon: FileText,
    badge: 'TELEMETRY',
  },
  {
    id: 'user_chats',
    name: 'User-Wise Chat & Telemetry',
    desc: 'User prompt history, conversation transcripts, risk scores & security events',
    icon: MessageSquare,
    badge: 'USER CHATS',
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
const ACTIONS = ['ALL', 'ALLOWED', 'MONITORED', 'BLOCKED'];
const INCIDENT_STATUSES = ['ALL', 'OPEN', 'INVESTIGATING', 'CONTAINMENT', 'RESOLVED'];

const THREAT_TYPES = [
  'ALL',
  'Prompt Injection',
  'Jailbreak Attempts',
  'System Prompt Extraction',
  'Credential Extraction',
  'Data Exfiltration',
  'Role Manipulation',
  'Privilege Escalation',
  'Security Policy Bypass',
  'Harmful Requests',
  'Probing & Reconnaissance',
];

export default function SOCReports() {
  const [reportType, setReportType] = useState('security_overview');
  const [dateRange, setDateRange] = useState('30d');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [classification, setClassification] = useState('ALL');
  const [severity, setSeverity] = useState('ALL');
  const [threatType, setThreatType] = useState('ALL');
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState('Generating security report...');
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingExcel, setExportingExcel] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });

  const [historyItems, setHistoryItems] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('generator'); // 'generator' | 'history'

  // Modal States
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [emailRecipient, setEmailRecipient] = useState('');
  const [emailCc, setEmailCc] = useState('');
  const [emailSubject, setEmailSubject] = useState('');
  const [emailMessage, setEmailMessage] = useState('');
  const [emailFormat, setEmailFormat] = useState('PDF');
  const [sendingEmail, setSendingEmail] = useState(false);

  const authHeaders = () => {
    const token = localStorage.getItem('hp_token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const buildFilterPayload = () => {
    const p = { report_type: reportType, date_range: dateRange };
    if (dateRange === 'custom' && dateFrom) p.date_from = dateFrom;
    if (dateRange === 'custom' && dateTo) p.date_to = dateTo;
    if (classification !== 'ALL') p.classification = classification;
    if (severity !== 'ALL') p.severity = severity;
    if (threatType !== 'ALL') p.threat_type = threatType;
    if (userFilter.trim()) p.user = userFilter.trim();
    if (actionFilter !== 'ALL') p.action = actionFilter;
    if (statusFilter !== 'ALL') p.status = statusFilter;
    return p;
  };

  const parseErrorMessage = async (e, fallback) => {
    if (e.response?.data instanceof Blob) {
      try {
        const text = await e.response.data.text();
        const json = JSON.parse(text);
        return json.detail || fallback;
      } catch {
        return fallback;
      }
    }
    return e.response?.data?.detail || fallback;
  };

  const fetchPreview = async (type = reportType, openModal = false) => {
    setLoading(true);
    setLoadingMsg('HoneyPrompt is compiling security telemetry...');
    setNotice({ msg: '', type: 'info' });

    const endpointMap = {
      security_overview: '/api/admin/reports/security',
      threat_intelligence: '/api/admin/reports/threats',
      user_security: '/api/admin/reports/users',
      audit_log: '/api/admin/reports/audit',
      incidents: '/api/admin/reports/incidents',
      chat_activity: '/api/admin/reports/activity',
      user_chats: '/api/admin/reports/user-chats',
    };

    const url = `${API}${endpointMap[type] || endpointMap.security_overview}`;
    // Build clean params — no undefined values
    const payload = buildFilterPayload();
    const params = {};
    Object.entries(payload).forEach(([k, v]) => { if (v !== undefined && v !== null) params[k] = v; });

    try {
      const res = await axios.get(url, { params, headers: authHeaders() });
      setReportData(res.data);
      setNotice({
        msg: `Report compiled successfully: ${res.data.record_count ?? 0} records analyzed (${res.data.date_from || 'start'} to ${res.data.date_to || 'now'}).`,
        type: 'success',
      });
      if (openModal) setShowPreviewModal(true);
      loadHistory();
    } catch (e) {
      const msg = await parseErrorMessage(e, 'Unable to generate report preview.');
      setNotice({ msg, type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const exportPDF = async (customFilters = null) => {
    setExportingPdf(true);
    setNotice({ msg: 'Generating PDF security report...', type: 'info' });
    try {
      const payload = customFilters || buildFilterPayload();
      const res = await axios.post(`${API}/api/admin/reports/pdf`, payload, {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_${(payload.report_type || reportType).toUpperCase()}_Report_${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'Report generated successfully.', type: 'success' });
      loadHistory();
    } catch (e) {
      const msg = await parseErrorMessage(e, 'Unable to generate report.');
      setNotice({ msg, type: 'error' });
    } finally {
      setExportingPdf(false);
    }
  };

  const exportExcel = async (customFilters = null) => {
    setExportingExcel(true);
    setNotice({ msg: 'Compiling multi-sheet Excel workbook...', type: 'info' });
    try {
      const payload = customFilters || buildFilterPayload();
      const res = await axios.post(`${API}/api/admin/reports/excel`, payload, {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_${(payload.report_type || reportType).toUpperCase()}_Report_${new Date().toISOString().slice(0, 10)}.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'Report generated successfully.', type: 'success' });
      loadHistory();
    } catch (e) {
      const msg = await parseErrorMessage(e, 'Unable to generate report.');
      setNotice({ msg, type: 'error' });
    } finally {
      setExportingExcel(false);
    }
  };

  const openEmailModal = () => {
    const currentName = REPORT_TYPES.find(t => t.id === reportType)?.name || 'Security Report';
    setEmailSubject(`HoneyPrompt Sentinel Security Report — ${currentName}`);
    setEmailMessage(`Please find attached the ${currentName} generated from HoneyPrompt Sentinel.`);
    setShowEmailModal(true);
  };

  const sendEmailReport = async () => {
    if (!emailRecipient || !emailRecipient.includes('@')) {
      setNotice({ msg: 'Please provide a valid recipient email address.', type: 'error' });
      return;
    }
    setSendingEmail(true);
    setNotice({ msg: 'Generating report and dispatching email...', type: 'info' });

    try {
      const base = buildFilterPayload();
      const payload = { ...base, recipient_email: emailRecipient, format: emailFormat };
      if (emailCc.trim()) payload.cc_email = emailCc.trim();
      if (emailSubject.trim()) payload.subject = emailSubject.trim();
      if (emailMessage.trim()) payload.message = emailMessage.trim();

      const res = await axios.post(`${API}/api/admin/reports/email`, payload, {
        headers: authHeaders(),
      });
      setNotice({ msg: res.data?.message || 'Report emailed successfully.', type: 'success' });
      setShowEmailModal(false);
      loadHistory();
    } catch (e) {
      const msg = await parseErrorMessage(e, 'Unable to send email.');
      setNotice({ msg, type: 'error' });
    } finally {
      setSendingEmail(false);
    }
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await axios.get(`${API}/api/admin/reports/history?page=1&page_size=30`, {
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
    loadHistory();
  }, [reportType, dateRange]);

  const currentTypeConfig = REPORT_TYPES.find(t => t.id === reportType) || REPORT_TYPES[0];

  return (
    <div style={{ maxWidth: 1320, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18, paddingBottom: 40 }}>
      {/* Page Header */}
      <SocPageHeader
        icon="📊"
        title="Security Reports & Export Center"
        subtitle="Generate, preview, email and download compliance-ready security intelligence reports"
      >
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={`btn-secondary${activeTab === 'generator' ? ' active' : ''}`}
            onClick={() => setActiveTab('generator')}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <FileText size={14} style={{ marginRight: 6 }} /> Report Center
          </button>
          <button
            className={`btn-secondary${activeTab === 'history' ? ' active' : ''}`}
            onClick={() => {
              setActiveTab('history');
              loadHistory();
            }}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <Clock size={14} style={{ marginRight: 6 }} /> Report History ({historyItems.length})
          </button>
        </div>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {activeTab === 'generator' && (
        <>
          {/* Report Type Selector Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10 }}>
            {REPORT_TYPES.map(rt => {
              const Icon = rt.icon;
              const isActive = reportType === rt.id;
              return (
                <button
                  key={rt.id}
                  onClick={() => {
                    setReportType(rt.id);
                  }}
                  style={{
                    background: isActive ? 'color-mix(in srgb, var(--accent-gold) 12%, var(--bg-card))' : 'var(--bg-card)',
                    border: `1px solid ${isActive ? 'var(--accent-gold)' : 'var(--border-color)'}`,
                    borderRadius: 8,
                    padding: '12px 14px',
                    textAlign: 'left',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 6,
                    position: 'relative',
                    transition: 'all 0.16s ease',
                    boxShadow: isActive ? 'var(--shadow-gold)' : 'none',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: isActive ? 'var(--accent-gold)' : 'var(--text-primary)', fontWeight: 600, fontSize: '0.84rem' }}>
                      <Icon size={16} /> {rt.name}
                    </div>
                    <span style={{ fontSize: '0.56rem', fontFamily: 'var(--font-mono)', padding: '2px 5px', borderRadius: 3, background: isActive ? 'var(--accent-gold)' : 'rgba(255,255,255,0.06)', color: isActive ? '#000' : 'var(--text-secondary)', fontWeight: 700 }}>
                      {rt.badge}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.68rem', color: 'var(--text-secondary)', lineHeight: 1.35 }}>
                    {rt.desc}
                  </p>
                </button>
              );
            })}
          </div>

          {/* Filter & Export Control Console */}
          <SocCard style={{ padding: '18px 20px', borderTop: '3px solid var(--accent-gold)' }}>
            <div className="eyebrow" style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Filter size={13} /> REPORT CONFIGURATION & FILTERS — {currentTypeConfig.name.toUpperCase()}
            </div>

            {/* Date Range Pills */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 14 }}>
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

            {/* Granular Filters Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))', gap: 10, marginBottom: 16 }}>
              <div>
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

              <div>
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

              <div>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Threat Category</label>
                <select
                  value={threatType}
                  onChange={e => setThreatType(e.target.value)}
                  className="search-input"
                  style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                >
                  {THREAT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Action</label>
                <select
                  value={actionFilter}
                  onChange={e => setActionFilter(e.target.value)}
                  className="search-input"
                  style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                >
                  {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>

              {reportType === 'incidents' && (
                <div>
                  <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Incident Status</label>
                  <select
                    value={statusFilter}
                    onChange={e => setStatusFilter(e.target.value)}
                    className="search-input"
                    style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                  >
                    {INCIDENT_STATUSES.map(st => <option key={st} value={st}>{st}</option>)}
                  </select>
                </div>
              )}

              <div>
                <label style={{ display: 'block', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                  User Account {reportType === 'user_chats' && <span style={{ color: 'var(--accent-gold)' }}>*</span>}
                </label>
                <input
                  type="text"
                  placeholder="Filter by username..."
                  value={userFilter}
                  onChange={e => setUserFilter(e.target.value)}
                  className="search-input"
                  style={{ width: '100%', fontSize: '0.72rem', height: 32, padding: '4px 8px' }}
                />
              </div>
            </div>

            {/* Action Control Buttons */}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', paddingTop: 12, borderTop: '1px solid var(--border-color)' }}>
              <button
                className="btn-primary"
                onClick={() => fetchPreview(reportType, true)}
                disabled={loading || exportingPdf || exportingExcel || sendingEmail}
                style={{ width: 'auto', padding: '9px 18px', display: 'inline-flex', alignItems: 'center', gap: 7 }}
              >
                <Eye size={15} /> Preview Report
              </button>

              <button
                className="btn-secondary"
                onClick={() => exportPDF()}
                disabled={loading || exportingPdf || exportingExcel || sendingEmail}
                style={{ padding: '9px 16px', display: 'inline-flex', alignItems: 'center', gap: 7, borderColor: 'var(--border-gold)' }}
              >
                <Download size={15} /> {exportingPdf ? 'Generating PDF...' : 'Generate PDF'}
              </button>

              <button
                className="btn-secondary"
                onClick={() => exportExcel()}
                disabled={loading || exportingPdf || exportingExcel || sendingEmail}
                style={{ padding: '9px 16px', display: 'inline-flex', alignItems: 'center', gap: 7 }}
              >
                <Download size={15} /> {exportingExcel ? 'Compiling Excel...' : 'Export Excel (.xlsx)'}
              </button>

              <button
                className="btn-secondary"
                onClick={openEmailModal}
                disabled={loading || exportingPdf || exportingExcel || sendingEmail}
                style={{ padding: '9px 16px', display: 'inline-flex', alignItems: 'center', gap: 7, color: 'var(--accent-gold)' }}
              >
                <Mail size={15} /> Email Report
              </button>

              <button
                className="btn-secondary"
                onClick={() => {
                  setClassification('ALL');
                  setSeverity('ALL');
                  setThreatType('ALL');
                  setUserFilter('');
                  setActionFilter('ALL');
                  setStatusFilter('ALL');
                  setDateRange('30d');
                }}
                style={{ marginLeft: 'auto', padding: '9px 14px', fontSize: '0.74rem' }}
              >
                <RefreshCw size={13} style={{ marginRight: 5 }} /> Reset Filters
              </button>
            </div>

            {/* Loading Feedback Loader */}
            {(loading || exportingPdf || exportingExcel || sendingEmail) && (
              <div style={{ marginTop: 16 }}>
                <LoadingState
                  label={
                    sendingEmail
                      ? 'HoneyPrompt is dispatching secure email report...'
                      : exportingPdf
                      ? 'Compiling and styling PDF security report...'
                      : exportingExcel
                      ? 'Assembling multi-sheet Excel workbook...'
                      : loadingMsg
                  }
                  compact
                />
              </div>
            )}
          </SocCard>

          {/* Interactive Inline Report Preview Area */}
          {reportData && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Meta Banner */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, padding: '10px 18px', background: 'rgba(245,197,24,0.06)', border: '1px solid var(--border-gold)', borderRadius: 8, fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
                <div>
                  <strong style={{ color: 'var(--text-primary)' }}>{currentTypeConfig.name}</strong> · Period: <strong style={{ color: 'var(--accent-gold)' }}>{reportData.date_from}</strong> to <strong style={{ color: 'var(--accent-gold)' }}>{reportData.date_to}</strong> · Analyzed Records: <strong style={{ color: 'var(--text-primary)' }}>{reportData.record_count}</strong>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>
                  <CheckCircle2 size={13} color="var(--accent-green)" /> Generated: {fmtTime(reportData.generated_at)}
                </div>
              </div>

              {/* Summary KPIs */}
              {reportData.summary && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12 }}>
                  {reportData.summary.total_prompts !== undefined && <MiniStat label="Prompts Analyzed" value={reportData.summary.total_prompts} />}
                  {reportData.summary.security_score !== undefined && <MiniStat label="Security Score" value={`${reportData.summary.security_score}/100`} color="var(--accent-gold)" />}
                  {reportData.summary.safe !== undefined && <MiniStat label="SAFE Prompts" value={reportData.summary.safe} color="#10b981" />}
                  {reportData.summary.suspicious !== undefined && <MiniStat label="SUSPICIOUS" value={reportData.summary.suspicious} color="#f59e0b" />}
                  {reportData.summary.malicious !== undefined && <MiniStat label="MALICIOUS" value={reportData.summary.malicious} color="#ef4444" />}
                  {reportData.summary.block_rate !== undefined && <MiniStat label="Block Rate" value={fmtPct(reportData.summary.block_rate / 100)} color="#f97316" />}
                  {reportData.summary.total_users !== undefined && <MiniStat label="Total Users" value={reportData.summary.total_users} />}
                  {reportData.summary.blocked_users !== undefined && <MiniStat label="Blocked Users" value={reportData.summary.blocked_users} color="#dc2626" />}
                  {reportData.summary.total_conversations !== undefined && <MiniStat label="Total Chats" value={reportData.summary.total_conversations} />}
                  {reportData.summary.total_messages !== undefined && <MiniStat label="Total Messages" value={reportData.summary.total_messages} />}
                  {reportData.summary.target_user !== undefined && <MiniStat label="Filtered Account" value={reportData.summary.target_user} color="var(--accent-gold)" />}
                </div>
              )}

              {/* Data Table by Report Type */}
              <SocCard style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="eyebrow">DATABASE TELEMETRY: {currentTypeConfig.name.toUpperCase()} RECORDS</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    Showing top {Math.min(50, reportData.record_count || 0)} records
                  </span>
                </div>

                <div style={{ overflowX: 'auto' }}>
                  {/* Security Overview Table */}
                  {reportType === 'security_overview' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Email</th>
                          <th>Status</th>
                          <th>Prompts</th>
                          <th>Safe</th>
                          <th>Suspicious</th>
                          <th>Malicious</th>
                          <th>Blocked</th>
                          <th>Risk Score</th>
                          <th>Last Activity</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.users || []).length === 0 ? (
                          <tr><td colSpan={10} className="empty-table-cell">No user records found for selected filters.</td></tr>
                        ) : (
                          reportData.users.slice(0, 30).map(u => (
                            <tr key={u.username}>
                              <td><strong>{u.username}</strong></td>
                              <td>{u.email || '—'}</td>
                              <td><span className={`soc-badge ${u.status === 'ACTIVE' ? 'soc-badge-active' : 'soc-badge-blocked'}`}>{u.status}</span></td>
                              <td>{u.total_prompts}</td>
                              <td style={{ color: '#10b981' }}>{u.safe}</td>
                              <td style={{ color: '#f59e0b' }}>{u.suspicious}</td>
                              <td style={{ color: '#ef4444' }}>{u.malicious}</td>
                              <td style={{ color: '#f97316' }}>{u.blocked}</td>
                              <td><strong>{u.risk_score}</strong></td>
                              <td>{fmtTime(u.last_activity)}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Threat Intelligence Table */}
                  {reportType === 'threat_intelligence' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Threat Category</th>
                          <th>Detection Count</th>
                          <th>Severity</th>
                          <th>Avg Confidence</th>
                          <th>Targeted Accounts</th>
                          <th>Blocked Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.threats || []).length === 0 ? (
                          <tr><td colSpan={6} className="empty-table-cell">No threats detected in this window.</td></tr>
                        ) : (
                          reportData.threats.map(t => (
                            <tr key={t.threat_type}>
                              <td><strong style={{ color: 'var(--accent-gold)' }}>{t.threat_type}</strong></td>
                              <td><strong>{t.count}</strong></td>
                              <td><span style={{ color: SEV_COLOR[t.severity] || '#64748b', fontWeight: 700 }}>{t.severity}</span></td>
                              <td>{fmtPct(t.avg_confidence)}</td>
                              <td>{t.target_users_count}</td>
                              <td style={{ color: '#ef4444' }}>{t.blocked_count}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* User Security Table */}
                  {reportType === 'user_security' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Email</th>
                          <th>Role</th>
                          <th>Status</th>
                          <th>Prompts</th>
                          <th>Malicious</th>
                          <th>Consecutive Attacks</th>
                          <th>Risk Score</th>
                          <th>Restrictions</th>
                          <th>Last Threat</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.users || []).length === 0 ? (
                          <tr><td colSpan={10} className="empty-table-cell">No user security profiles found.</td></tr>
                        ) : (
                          reportData.users.slice(0, 40).map(u => (
                            <tr key={u.username}>
                              <td><strong>{u.username}</strong></td>
                              <td>{u.email || '—'}</td>
                              <td>{u.role}</td>
                              <td><span className={`soc-badge ${u.status === 'ACTIVE' ? 'soc-badge-active' : 'soc-badge-blocked'}`}>{u.status}</span></td>
                              <td>{u.total_prompts}</td>
                              <td style={{ color: '#ef4444' }}>{u.malicious}</td>
                              <td>{u.consecutive_malicious}</td>
                              <td><strong style={{ color: u.risk_score >= 50 ? '#ef4444' : 'var(--text-primary)' }}>{u.risk_score}</strong></td>
                              <td>{u.current_restrictions}</td>
                              <td>{u.last_threat_type !== 'None' ? `${u.last_threat_type} (${fmtTime(u.last_threat)})` : 'None'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Audit Log Table */}
                  {reportType === 'audit_log' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Admin / Actor</th>
                          <th>Action Executed</th>
                          <th>Target</th>
                          <th>Result</th>
                          <th>Reason / Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.logs || []).length === 0 ? (
                          <tr><td colSpan={6} className="empty-table-cell">No audit log records found for selected filters.</td></tr>
                        ) : (
                          reportData.logs.slice(0, 40).map(l => (
                            <tr key={l.audit_id}>
                              <td>{fmtTime(l.timestamp)}</td>
                              <td><strong>{l.admin}</strong></td>
                              <td><span style={{ color: 'var(--accent-gold)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{l.action}</span></td>
                              <td>{l.target || '—'}</td>
                              <td><span style={{ color: l.result === 'SUCCESS' ? '#10b981' : '#ef4444', fontWeight: 600 }}>{l.result}</span></td>
                              <td style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{l.reason || '—'}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Incidents Table */}
                  {reportType === 'incidents' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Incident ID</th>
                          <th>Created</th>
                          <th>Title / Threat</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Handler</th>
                          <th>Resolution</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.incidents || []).length === 0 ? (
                          <tr><td colSpan={7} className="empty-table-cell">No security incident records found.</td></tr>
                        ) : (
                          reportData.incidents.slice(0, 30).map(inc => (
                            <tr key={inc.incident_id}>
                              <td><strong style={{ fontFamily: 'var(--font-mono)' }}>{inc.incident_id}</strong></td>
                              <td>{fmtTime(inc.created_at)}</td>
                              <td>{inc.title}</td>
                              <td><span style={{ color: SEV_COLOR[inc.severity] || '#64748b', fontWeight: 700 }}>{inc.severity}</span></td>
                              <td><span className="soc-badge">{inc.status}</span></td>
                              <td>{inc.assigned_admin}</td>
                              <td>{inc.resolution}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* Chat Activity Table */}
                  {reportType === 'chat_activity' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Conversation ID</th>
                          <th>User</th>
                          <th>Session Title</th>
                          <th>Created At</th>
                          <th>Last Updated</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.conversations || []).length === 0 ? (
                          <tr><td colSpan={5} className="empty-table-cell">No chat activity records found.</td></tr>
                        ) : (
                          reportData.conversations.slice(0, 35).map(c => (
                            <tr key={c.conversation_id}>
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>{c.conversation_id.slice(0, 12)}...</td>
                              <td><strong>{c.user}</strong></td>
                              <td>{c.title || 'Untitled Chat'}</td>
                              <td>{fmtTime(c.created_at)}</td>
                              <td>{fmtTime(c.updated_at)}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  )}

                  {/* User-Wise Chats Table */}
                  {reportType === 'user_chats' && (
                    <table className="hp-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>User</th>
                          <th>Classification</th>
                          <th>Threat Category</th>
                          <th>Action</th>
                          <th>Prompt & Telemetry</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(reportData.messages || []).length === 0 ? (
                          <tr><td colSpan={6} className="empty-table-cell">No user chat messages found matching filters.</td></tr>
                        ) : (
                          reportData.messages.slice(0, 35).map(m => (
                            <tr key={m.request_id || Math.random()}>
                              <td style={{ fontSize: '0.72rem' }}>{fmtTime(m.timestamp)}</td>
                              <td><strong>{m.user}</strong></td>
                              <td>
                                <span style={{ color: m.classification === 'MALICIOUS' ? '#ef4444' : m.classification === 'SUSPICIOUS' ? '#f59e0b' : '#10b981', fontWeight: 700, fontSize: '0.7rem' }}>
                                  {m.classification}
                                </span>
                              </td>
                              <td><span style={{ color: 'var(--accent-gold)', fontSize: '0.74rem' }}>{m.threat_type}</span></td>
                              <td><span className="soc-badge">{m.action}</span></td>
                              <td style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {m.prompt}
                              </td>
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

      {/* Report Generation History Tab */}
      {activeTab === 'history' && (
        <SocCard style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="eyebrow" style={{ marginBottom: 3 }}>AUDITABLE REPORT GENERATION ARCHIVE</div>
              <strong style={{ fontSize: '0.95rem' }}>Report Generation History</strong>
            </div>
            <button className="btn-secondary" onClick={loadHistory} disabled={historyLoading} style={{ padding: '7px 12px', fontSize: '0.72rem' }}>
              <RefreshCw size={13} style={{ marginRight: 5 }} /> Refresh History
            </button>
          </div>

          {historyLoading ? (
            <div style={{ padding: 30 }}>
              <LoadingState label="Loading report generation records..." compact />
            </div>
          ) : historyItems.length === 0 ? (
            <p style={{ padding: 30, color: 'var(--text-secondary)', margin: 0, textAlign: 'center' }}>
              No reports have been generated yet. Use the Report Center above to generate PDF and Excel reports.
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="hp-table">
                <thead>
                  <tr>
                    <th>Report ID</th>
                    <th>Report Type</th>
                    <th>Format</th>
                    <th>Generated By</th>
                    <th>Reporting Window</th>
                    <th>Records</th>
                    <th>Status</th>
                    <th>Timestamp</th>
                    <th style={{ textAlign: 'right' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {historyItems.map(h => (
                    <tr key={h.report_id}>
                      <td><strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-gold)' }}>{h.report_id}</strong></td>
                      <td>{h.report_type?.replace(/_/g, ' ').toUpperCase()}</td>
                      <td><span className="soc-badge" style={{ background: h.format?.includes('PDF') ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)', color: h.format?.includes('PDF') ? '#ef4444' : '#10b981' }}>{h.format}</span></td>
                      <td><strong>{h.generated_by}</strong> ({h.role})</td>
                      <td>{h.date_from ? `${h.date_from} → ${h.date_to}` : 'All-time'}</td>
                      <td>{h.record_count}</td>
                      <td><span style={{ color: h.status === 'SUCCESS' ? '#10b981' : '#ef4444', fontWeight: 600 }}>{h.status}</span></td>
                      <td>{fmtTime(h.generated_at)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="btn-secondary"
                          onClick={() => {
                            const reqFilters = { ...h.filters, report_type: h.report_type };
                            if (h.format?.includes('EXCEL')) exportExcel(reqFilters);
                            else exportPDF(reqFilters);
                          }}
                          style={{ fontSize: '0.68rem', padding: '4px 8px' }}
                          title="Re-download report document"
                        >
                          <Download size={12} /> Download
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SocCard>
      )}

      {/* ========================================================================= */}
      {/* EMAIL REPORT MODAL */}
      {/* ========================================================================= */}
      {showEmailModal && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)', display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 520,
              background: 'var(--bg-panel)',
              border: '1px solid var(--border-gold)',
              boxShadow: 'var(--shadow)',
              borderRadius: 12,
              padding: 24,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(245,197,24,0.15)', border: '1px solid rgba(245,197,24,0.3)', display: 'grid', placeItems: 'center', color: 'var(--accent-gold)' }}>
                  <Mail size={18} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '1.05rem', color: 'var(--text-primary)' }}>Email Security Report</h3>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Send encrypted report attachment via SMTP</div>
                </div>
              </div>
              <button onClick={() => setShowEmailModal(false)} style={{ background: 'none', border: 0, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={18} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  Recipient Email <span style={{ color: '#ef4444' }}>*</span>
                </label>
                <input
                  type="email"
                  placeholder="sec-ops@company.com"
                  value={emailRecipient}
                  onChange={e => setEmailRecipient(e.target.value)}
                  className="search-input"
                  style={{ width: '100%', fontSize: '0.85rem' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                  CC Recipient (Optional)
                </label>
                <input
                  type="email"
                  placeholder="audit@company.com"
                  value={emailCc}
                  onChange={e => setEmailCc(e.target.value)}
                  className="search-input"
                  style={{ width: '100%', fontSize: '0.85rem' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Email Subject
                  </label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={e => setEmailSubject(e.target.value)}
                    className="search-input"
                    style={{ width: '100%', fontSize: '0.82rem' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Format
                  </label>
                  <select
                    value={emailFormat}
                    onChange={e => setEmailFormat(e.target.value)}
                    className="search-input"
                    style={{ width: '100%', fontSize: '0.82rem', height: 36 }}
                  >
                    <option value="PDF">PDF (.pdf)</option>
                    <option value="EXCEL">Excel (.xlsx)</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                  Short Message / Note
                </label>
                <textarea
                  rows={3}
                  value={emailMessage}
                  onChange={e => setEmailMessage(e.target.value)}
                  placeholder="Add custom notes for recipient..."
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

              <div style={{ background: 'var(--bg-dark)', padding: '10px 12px', borderRadius: 6, border: '1px solid var(--border-color)', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                Report: <strong style={{ color: 'var(--text-primary)' }}>{currentTypeConfig.name}</strong> · Format: <strong style={{ color: 'var(--accent-gold)' }}>{emailFormat}</strong>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 4 }}>
              <button className="btn-secondary" onClick={() => setShowEmailModal(false)}>
                Cancel
              </button>
              <button
                className="btn-primary"
                onClick={sendEmailReport}
                disabled={sendingEmail || !emailRecipient}
                style={{ width: 'auto' }}
              >
                <Send size={14} /> {sendingEmail ? 'Sending...' : 'Send Report Email'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* FULL PREVIEW MODAL */}
      {/* ========================================================================= */}
      {showPreviewModal && reportData && (
        <div className="modal-overlay" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(5px)', display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: 900,
              maxHeight: '90vh',
              overflowY: 'auto',
              background: 'var(--bg-panel)',
              border: '1px solid var(--border-gold)',
              boxShadow: 'var(--shadow)',
              borderRadius: 12,
              padding: 24,
              display: 'flex',
              flexDirection: 'column',
              gap: 16,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
              <div>
                <span className="eyebrow">SECURITY REPORT PREVIEW</span>
                <h3 style={{ margin: 0, fontSize: '1.2rem', color: 'var(--accent-gold)' }}>{currentTypeConfig.name}</h3>
              </div>
              <button className="btn-secondary" onClick={() => setShowPreviewModal(false)}>
                <X size={16} /> Close Preview
              </button>
            </div>

            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Period: <strong>{reportData.date_from}</strong> to <strong>{reportData.date_to}</strong> · Analyzed Records: <strong>{reportData.record_count}</strong>
            </div>

            {reportData.summary && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10 }}>
                {Object.entries(reportData.summary).map(([k, v]) => (
                  <div key={k} style={{ padding: '8px 12px', background: 'var(--bg-dark)', borderRadius: 6, border: '1px solid var(--border-color)' }}>
                    <div style={{ fontSize: '0.62rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 2 }}>{k.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)' }}>{String(v)}</div>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 12 }}>
              <button className="btn-secondary" onClick={() => exportPDF()}>
                <Download size={14} /> Download PDF
              </button>
              <button className="btn-secondary" onClick={() => exportExcel()}>
                <Download size={14} /> Export Excel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
