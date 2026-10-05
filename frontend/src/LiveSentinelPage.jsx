import { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, AlertTriangle, Database, Radio, RefreshCw, Server, Shield, ShieldCheck, ShieldX } from 'lucide-react';

const EVENT_STYLE = {
  SAFE: { icon: ShieldCheck, className: 'event-icon-safe' },
  SUSPICIOUS: { icon: AlertTriangle, className: 'event-icon-suspicious' },
  MALICIOUS: { icon: ShieldX, className: 'event-icon-malicious' },
};

export default function LiveSentinelPage() {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [updatedAt, setUpdatedAt] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const [statusResponse, logsResponse] = await Promise.all([
        axios.get('http://127.0.0.1:8000/status'),
        axios.get('http://127.0.0.1:8000/api/logs'),
      ]);
      setStatus(statusResponse.data);
      setEvents(logsResponse.data.slice().reverse().slice(0, 25));
      setConnected(true);
      setUpdatedAt(new Date());
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    const initialRefresh = window.setTimeout(refresh, 0);
    const intervalId = window.setInterval(refresh, 5000);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(intervalId);
    };
  }, [refresh]);

  const services = [
    { label: 'SYSTEM STATUS', value: connected ? 'NOMINAL' : 'UNAVAILABLE', icon: Shield, state: connected ? 'online' : 'offline' },
    { label: 'LLM ENDPOINT', value: status?.llm_key_configured ? 'ONLINE' : 'NOT CONFIGURED', icon: Radio, state: status?.llm_key_configured ? 'online' : 'warning' },
    { label: 'HONEYPROMPT DETECTOR', value: 'ACTIVE', icon: Activity, state: 'online' },
    { label: 'AUDIT STORE', value: connected ? 'CONNECTED' : 'UNAVAILABLE', icon: Database, state: connected ? 'online' : 'offline' },
  ];

  return (
    <div className="role-dashboard sentinel-page">
      <header className="role-page-heading">
        <div><span className="eyebrow">REAL-TIME MONITORING</span><h1>Live Sentinel</h1><p>System health and classified prompt activity across the protected environment.</p></div>
        <button type="button" className="sentinel-refresh" onClick={refresh} aria-label="Refresh Sentinel status"><RefreshCw size={15} /> Refresh</button>
      </header>

      <section className="sentinel-service-grid" aria-label="System service status">
        {services.map(service => {
          const Icon = service.icon;
          return <article className={`card sentinel-service sentinel-${service.state}`} key={service.label}>
            <div className="sentinel-service-icon"><Icon size={17} /></div>
            <span className="eyebrow">{service.label}</span>
            <strong><i /> {service.value}</strong>
          </article>;
        })}
      </section>

      <section className="card sentinel-events">
        <div className="panel-heading"><div><span className="eyebrow">EVENT STREAM</span><h2>Recent threat events</h2></div><span className="monitor-live"><i /> REFRESHES EVERY 5 SEC</span></div>
        {events.length === 0 ? <p className="empty-state">{connected ? 'No prompt events recorded yet.' : 'Waiting for backend telemetry.'}</p> : <div className="sentinel-event-list">
          {events.map(event => {
            const visual = EVENT_STYLE[event.classification] || EVENT_STYLE.SAFE;
            const Icon = visual.icon;
            return <article className="sentinel-event" key={event.request_id}>
              <span className={`event-icon ${visual.className}`}><Icon size={16} /></span>
              <div className="event-details"><strong>{event.classification} <span>· {event.threat_type}</span></strong><span>{new Date(event.timestamp).toLocaleString()} · {event.request_id || 'ID unavailable'}</span></div>
              <div className="sentinel-event-meta"><span className={`severity-${event.severity?.toLowerCase()}`}>{event.severity}</span><span>{event.confidence ? `${Math.round(event.confidence * 100)}% confidence` : 'Confidence unavailable'}</span><b>{event.action}</b></div>
            </article>;
          })}
        </div>}
        <footer className="sentinel-footer"><span><Server size={13} /> {status?.system || 'HoneyPrompt security gateway'}</span><span>{updatedAt ? `LAST SYNC ${updatedAt.toLocaleTimeString()}` : 'AWAITING TELEMETRY'}</span></footer>
      </section>
    </div>
  );
}