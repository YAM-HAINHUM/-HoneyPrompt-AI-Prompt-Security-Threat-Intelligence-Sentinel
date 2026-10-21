import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { MessageSquare, Download, Eye, RefreshCw, Clock, FileText } from 'lucide-react';
import LoadingState from './LoadingState';
import { API, SocPageHeader, SocCard, SocNotice, MiniStat, fmtTime } from './socUtils';

const DATE_RANGES = [
  { id: 'today', label: 'Today' },
  { id: '7d', label: 'Last 7 Days' },
  { id: '30d', label: 'Last 30 Days' },
  { id: '90d', label: 'Last 90 Days' },
  { id: 'custom', label: 'Custom Range' },
];

const authHeaders = () => {
  const token = localStorage.getItem('hp_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

function fmtDuration(createdAt, updatedAt) {
  if (!createdAt || !updatedAt) return '—';
  try {
    const diff = Math.max(0, new Date(updatedAt) - new Date(createdAt));
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return '< 1 min';
    if (mins < 60) return `${mins} min`;
    const hrs = Math.floor(mins / 60);
    const rem = mins % 60;
    return rem > 0 ? `${hrs}h ${rem}m` : `${hrs}h`;
  } catch {
    return '—';
  }
}

export default function UserReportsPage() {
  const [dateRange, setDateRange] = useState('30d');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingExcel, setExportingExcel] = useState(false);
  const [notice, setNotice] = useState({ msg: '', type: 'info' });

  const [historyItems, setHistoryItems] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('generator');

  const buildParams = () => {
    const p = { date_range: dateRange };
    if (dateRange === 'custom' && dateFrom) p.date_from = dateFrom;
    if (dateRange === 'custom' && dateTo) p.date_to = dateTo;
    return p;
  };

  const buildPayload = () => ({ report_type: 'my_chat_activity', ...buildParams() });

  const fetchPreview = async () => {
    setLoading(true);
    setNotice({ msg: '', type: 'info' });
    try {
      const res = await axios.get(`${API}/api/user/reports/activity`, {
        params: buildParams(),
        headers: authHeaders(),
      });
      setReportData(res.data);
      setNotice({ msg: `Preview loaded: ${res.data.summary?.total_conversations ?? 0} conversations found.`, type: 'success' });
      loadHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'Failed to load report.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const exportPDF = async () => {
    setExportingPdf(true);
    setNotice({ msg: 'Generating PDF...', type: 'info' });
    try {
      const res = await axios.post(`${API}/api/user/reports/pdf`, buildPayload(), {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_ChatActivity_${new Date().toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'PDF downloaded.', type: 'success' });
      loadHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'PDF download failed.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setExportingPdf(false);
    }
  };

  const exportExcel = async () => {
    setExportingExcel(true);
    setNotice({ msg: 'Generating Excel...', type: 'info' });
    try {
      const res = await axios.post(`${API}/api/user/reports/excel`, buildPayload(), {
        responseType: 'blob',
        headers: authHeaders(),
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = `HoneyPrompt_ChatActivity_${new Date().toISOString().slice(0, 10)}.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice({ msg: 'Excel downloaded.', type: 'success' });
      loadHistory();
    } catch (e) {
      const msg = e.response?.data?.detail || 'Excel export failed.';
      setNotice({ msg: typeof msg === 'string' ? msg : JSON.stringify(msg), type: 'error' });
    } finally {
      setExportingExcel(false);
    }
  };

  const loadHistory = async () => {
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
    fetchPreview();
    loadHistory();
  }, [dateRange]);

  const s = reportData?.summary || {};
  const conversations = reportData?.conversations || [];

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18, paddingBottom: 40 }}>
      <SocPageHeader
        icon="💬"
        title="My Chat Reports"
        subtitle="Export your conversation history and time spent in chat sessions"
      >
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={`btn-secondary${activeTab === 'generator' ? ' active' : ''}`}
            onClick={() => setActiveTab('generator')}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <MessageSquare size={14} style={{ marginRight: 6 }} /> Chat Report
          </button>
          <button
            className={`btn-secondary${activeTab === 'history' ? ' active' : ''}`}
            onClick={() => { setActiveTab('history'); loadHistory(); }}
            style={{ padding: '8px 14px', fontSize: '0.78rem' }}
          >
            <Clock size={14} style={{ marginRight: 6 }} /> Export History ({historyItems.length})
          </button>
        </div>
      </SocPageHeader>

      <SocNotice msg={notice.msg} type={notice.type} onDismiss={() => setNotice({ msg: '' })} />

      {activeTab === 'generator' && (
        <>
          {/* Filter & Actions */}
          <SocCard style={{ padding: '16px 20px', borderTop: '3px solid var(--accent-gold)' }}>
            <div className="eyebrow" style={{ marginBottom: 10 }}>PERIOD & EXPORT</div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 14 }}>
              <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontWeight: 600 }}>Period:</span>
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
                  <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
                    className="search-input" style={{ padding: '4px 8px', fontSize: '0.72rem', height: 30 }} />
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem' }}>to</span>
                  <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
                    className="search-input" style={{ padding: '4px 8px', fontSize: '0.72rem', height: 30 }} />
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center', paddingTop: 10, borderTop: '1px solid var(--border-color)' }}>
              <button className="btn-primary" onClick={fetchPreview} disabled={loading || exportingPdf || exportingExcel}
                style={{ width: 'auto', padding: '9px 20px', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                <Eye size={15} /> Preview
              </button>
              <button className="btn-secondary" onClick={exportPDF} disabled={loading || exportingPdf || exportingExcel}
                style={{ padding: '9px 18px', display: 'inline-flex', alignItems: 'center', gap: 7, borderColor: 'var(--border-gold)' }}>
                <Download size={15} /> {exportingPdf ? 'Generating...' : 'Download PDF'}
              </button>
              <button className="btn-secondary" onClick={exportExcel} disabled={loading || exportingPdf || exportingExcel}
                style={{ padding: '9px 18px', display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                <Download size={15} /> {exportingExcel ? 'Generating...' : 'Export Excel'}
              </button>
            </div>

            {(loading || exportingPdf || exportingExcel) && (
              <div style={{ marginTop: 16 }}>
                <LoadingState label="Compiling your chat report..." compact />
              </div>
            )}
          </SocCard>

          {/* Summary Stats */}
          {reportData && !loading && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
                <MiniStat label="Conversations" value={s.total_conversations ?? 0} />
                <MiniStat label="Total Messages" value={s.total_messages ?? 0} />
              </div>

              {/* Conversations Table */}
              <SocCard style={{ padding: 0, overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="eyebrow">YOUR CONVERSATIONS</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    {conversations.length} sessions
                  </span>
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="hp-table">
                    <thead>
                      <tr>
                        <th>Conversation</th>
                        <th>Started</th>
                        <th>Last Active</th>
                        <th>Time Spent</th>
                      </tr>
                    </thead>
                    <tbody>
                      {conversations.length === 0 ? (
                        <tr><td colSpan={4} className="empty-table-cell">No conversations found for this period.</td></tr>
                      ) : (
                        conversations.map(c => (
                          <tr key={c.conversation_id}>
                            <td><strong>{c.title || 'Untitled Chat'}</strong></td>
                            <td>{fmtTime(c.created_at)}</td>
                            <td>{fmtTime(c.updated_at)}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-gold)' }}>
                              {fmtDuration(c.created_at, c.updated_at)}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </SocCard>
            </>
          )}
        </>
      )}

      {/* Export History Tab */}
      {activeTab === 'history' && (
        <SocCard style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div className="eyebrow" style={{ marginBottom: 3 }}>EXPORT ARCHIVE</div>
              <strong style={{ fontSize: '0.95rem' }}>Report Generation History</strong>
            </div>
            <button className="btn-secondary" onClick={loadHistory} disabled={historyLoading}
              style={{ padding: '7px 12px', fontSize: '0.72rem' }}>
              <RefreshCw size={13} style={{ marginRight: 5 }} /> Refresh
            </button>
          </div>

          {historyLoading ? (
            <div style={{ padding: 30 }}><LoadingState label="Loading history..." compact /></div>
          ) : historyItems.length === 0 ? (
            <p style={{ padding: 30, color: 'var(--text-secondary)', margin: 0, textAlign: 'center' }}>
              No exports generated yet.
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="hp-table">
                <thead>
                  <tr>
                    <th>Report ID</th>
                    <th>Format</th>
                    <th>Period</th>
                    <th>Records</th>
                    <th>Status</th>
                    <th>Generated</th>
                  </tr>
                </thead>
                <tbody>
                  {historyItems.map(h => (
                    <tr key={h.report_id}>
                      <td><strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-gold)' }}>{h.report_id}</strong></td>
                      <td>
                        <span className="soc-badge" style={{
                          background: h.format === 'PDF' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
                          color: h.format === 'PDF' ? '#ef4444' : '#10b981',
                        }}>{h.format}</span>
                      </td>
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
