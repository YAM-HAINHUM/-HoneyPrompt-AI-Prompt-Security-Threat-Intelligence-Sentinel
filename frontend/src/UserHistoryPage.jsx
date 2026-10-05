import { Fragment, useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { AlertCircle, Check, ChevronDown, Search } from 'lucide-react';
import LoadingState from './LoadingState';

const CLASSIFICATIONS = ['All', 'SAFE', 'SUSPICIOUS', 'MALICIOUS'];

export default function UserHistoryPage() {
  const [pageData, setPageData] = useState({ items: [], total: 0, page: 1, page_size: 10 });
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [classification, setClassification] = useState('All');
  const [threatType, setThreatType] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/user/history', {
        params: {
          page,
          page_size: 10,
          search: search || undefined,
          classification: classification === 'All' ? undefined : classification,
          threat_type: threatType || undefined,
          date_from: dateFrom || undefined,
          date_to: dateTo || undefined,
        },
      });
      setPageData(response.data);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Your security history could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [page, search, classification, threatType, dateFrom, dateTo]);

  useEffect(() => {
    const timer = window.setTimeout(fetchHistory, 0);
    return () => window.clearTimeout(timer);
  }, [fetchHistory]);

  const updateFilter = (setter, value) => {
    setter(value);
    setPage(1);
  };

  const reportFalsePositive = async (entry) => {
    try {
      await axios.post(`http://127.0.0.1:8000/api/user/logs/${encodeURIComponent(entry.request_id)}/false-positive`, { reason: 'Reported incorrect detection from security history' });
      setPageData(current => ({ ...current, items: current.items.map(item => item.request_id === entry.request_id ? { ...item, false_positive_report: { reported_at: new Date().toISOString() } } : item) }));
      setNotice('Report sent to the security team for review.');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Your report could not be submitted.');
    }
  };

  const totalPages = Math.max(1, Math.ceil(pageData.total / pageData.page_size));

  return (
    <div className="role-dashboard user-history-page">
      <header className="role-page-heading">
        <div><span className="eyebrow">PRIVATE ACTIVITY</span><h1>Security History</h1><p>Your prompt classifications and Sentinel analysis, visible only to your account.</p></div>
        <span className="role-label role-label-user"><AlertCircle size={14} /> PERSONAL RECORDS</span>
      </header>

      <section className="history-filters card" aria-label="Filter your security history">
        <label className="history-search"><span>Search</span><span className="history-input-wrap"><Search size={15} /><input value={search} onChange={event => updateFilter(setSearch, event.target.value)} placeholder="Search prompt or threat" /></span></label>
        <label><span>Classification</span><select value={classification} onChange={event => updateFilter(setClassification, event.target.value)}>{CLASSIFICATIONS.map(value => <option key={value}>{value}</option>)}</select></label>
        <label><span>Threat type</span><input value={threatType} onChange={event => updateFilter(setThreatType, event.target.value)} placeholder="Any threat" /></label>
        <label><span>From</span><input type="date" value={dateFrom} onChange={event => updateFilter(setDateFrom, event.target.value)} /></label>
        <label><span>To</span><input type="date" value={dateTo} onChange={event => updateFilter(setDateTo, event.target.value)} /></label>
      </section>

      {error && <div className="auth-error" role="alert">{error}</div>}
      {notice && <div className="dashboard-notice" role="status"><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notice">×</button></div>}

      <section className="card history-table-card" aria-label="Your prompt security history">
        <div className="history-table-meta"><span>{pageData.total} events</span><span>Page {page} of {totalPages}</span></div>
        {loading ? <LoadingState label="Loading your security history..." compact /> : pageData.items.length === 0 ? <p className="empty-state">No security events match your filters.</p> : <div className="table-scroll">
          <table className="role-table history-table">
            <thead><tr><th>Timestamp</th><th>Prompt preview</th><th>Classification</th><th>Threat</th><th>Severity</th><th>Action</th><th>Analysis</th></tr></thead>
            <tbody>{pageData.items.map(entry => <Fragment key={entry.request_id}>
              <tr key={entry.request_id}>
                <td><time dateTime={entry.timestamp}>{new Date(entry.timestamp).toLocaleString()}</time></td>
                <td className="history-preview">{entry.prompt_preview}</td>
                <td><span className={`classification-chip classification-${entry.classification?.toLowerCase()}`}>{entry.classification}</span></td>
                <td>{entry.threat_type}</td>
                <td>{entry.severity}</td>
                <td>{entry.action}</td>
                <td><button className="history-details-toggle" aria-expanded={expandedId === entry.request_id} onClick={() => setExpandedId(current => current === entry.request_id ? null : entry.request_id)}>{expandedId === entry.request_id ? 'Hide' : 'View'} <ChevronDown size={13} /></button></td>
              </tr>
              {expandedId === entry.request_id && <tr className="history-expanded-row"><td colSpan={7}>
                <div className="history-expanded-content">
                  <div><span>Confidence</span><strong>{typeof entry.confidence === 'number' ? `${(entry.confidence * 100).toFixed(1)}%` : 'Unavailable'}</strong></div>
                  <div><span>Risk score</span><strong>{entry.risk_score ?? 'Unavailable'}</strong></div>
                  <div><span>Reason</span><strong>{entry.reason || 'No additional explanation recorded.'}</strong></div>
                  <div><span>Request ID</span><strong>{entry.request_id}</strong></div>
                  {entry.classification !== 'SAFE' && <button className="report-button" disabled={Boolean(entry.false_positive_report)} onClick={() => reportFalsePositive(entry)}>{entry.false_positive_report ? <><Check size={13} /> Reported</> : 'Report incorrect detection'}</button>}
                </div>
              </td></tr>}
            </Fragment>)}</tbody>
          </table>
        </div>}
        <footer className="history-pagination">
          <button className="btn-secondary" disabled={page <= 1 || loading} onClick={() => setPage(current => current - 1)}>Previous</button>
          <span>{pageData.total ? `${(page - 1) * pageData.page_size + 1}–${Math.min(page * pageData.page_size, pageData.total)} of ${pageData.total}` : '0 results'}</span>
          <button className="btn-secondary" disabled={page >= totalPages || loading} onClick={() => setPage(current => current + 1)}>Next</button>
        </footer>
      </section>
    </div>
  );
}