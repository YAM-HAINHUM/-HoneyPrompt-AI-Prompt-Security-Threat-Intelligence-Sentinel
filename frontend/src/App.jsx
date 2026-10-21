import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, FileText, Hexagon, BarChart2, Settings, LogOut, Moon, Sun, User, ChevronDown, Activity, MessageSquare, Menu, X, Bell, SlidersHorizontal, AlertTriangle, Pin } from 'lucide-react';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';
import { useTheme } from './ThemeContext';
import ChatPage from './ChatPage';
import DashboardPage from './DashboardPage';
import LiveSentinelPage from './LiveSentinelPage';
import ThreatMatrixPage from './ThreatMatrixPage';
import AuditLogsPage from './AuditLogsPage';
import AnalyticsPage from './AnalyticsPage';
import SettingsPage from './SettingsPage';
import UserHistoryPage from './UserHistoryPage';
import ChatHistoryPage from './ChatHistoryPage';
import UserAlertsPage from './UserAlertsPage';
import UserProfilePage from './UserProfilePage';
import UserReportsPage from './UserReportsPage';
import LoadingState from './LoadingState';
import LoginPage from './LoginPage';
import SignupPage from './SignupPage';
import AdminPatternsPage from './AdminPatternsPage';
import SOCCommandCenter from './SOCCommandCenter';
import SOCAlerts from './SOCAlerts';
import SOCThreatIntelligence from './SOCThreatIntelligence';
import SOCUserRisk from './SOCUserRisk';
import SOCThreatInvestigation from './SOCThreatInvestigation';
import SOCAuditLogs from './SOCAuditLogs';
import SOCRestrictions from './SOCRestrictions';
import SOCModelMonitor from './SOCModelMonitor';
import SOCSecurityTesting from './SOCSecurityTesting';
import SOCIncidents from './SOCIncidents';
import SOCReports from './SOCReports';
import SOCPolicies from './SOCPolicies';
import HoneyBeeBackground from './HoneyBeeBackground';
import HoneyPromptLogo from './assets/honeyprompt-logo.png';
import './App.css';

const DEFAULT_USER_PREFERENCES = { inAppAlerts: true, compactChat: false, sendOnEnter: true };

function storedUserPreferences() {
  try {
    const user = JSON.parse(localStorage.getItem('hp_user') || 'null');
    return { ...DEFAULT_USER_PREFERENCES, ...JSON.parse(localStorage.getItem(`hp_user_preferences_${user?.username || 'guest'}`) || '{}') };
  } catch {
    return DEFAULT_USER_PREFERENCES;
  }
}

function ProtectedLayout() {
  const { user, loading: authLoading, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarPinned, setSidebarPinned] = useState(() => localStorage.getItem('hp_sidebar_pinned') === 'true');
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [alertFeedError, setAlertFeedError] = useState('');
  const [userPreferences, setUserPreferences] = useState(storedUserPreferences);
  const [seenAt, setSeenAt] = useState(0);

  // Initialise seenAt once user is known (key depends on username)
  useEffect(() => {
    if (!user) return;
    const key = `hp_alerts_seen_${user.username}`;
    const stored = Number(localStorage.getItem(key) || 0);
    if (!stored) {
      // First login — mark everything already in the feed as seen
      const now = Date.now();
      localStorage.setItem(key, String(now));
      setSeenAt(now);
    } else {
      setSeenAt(stored);
    }
  }, [user?.username]);
  const [adminNotifs, setAdminNotifs] = useState([]);
  const [adminNotifError, setAdminNotifError] = useState('');

  const isAdmin = user?.role?.toLowerCase() === 'admin';
  const [toolsOpen, setToolsOpen] = useState(false);
  const [legacyOpen, setLegacyOpen] = useState(false);

  useEffect(() => {
    const onPreferencesChanged = event => setUserPreferences(current => ({ ...current, ...event.detail }));
    window.addEventListener('hp-user-preferences', onPreferencesChanged);
    return () => window.removeEventListener('hp-user-preferences', onPreferencesChanged);
  }, []);

  useEffect(() => {
    if (!user || isAdmin) return undefined;
    const fetchNotifs = async () => {
      try {
        const token = localStorage.getItem('hp_token');
        const res = await axios.get('http://127.0.0.1:8000/api/user/notifications', {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        setAdminNotifs(res.data || []);
        setAdminNotifError('');
      } catch (error) {
        setAdminNotifError(error.response?.data?.detail || 'Admin notifications could not be refreshed.');
      }
    };
    fetchNotifs();
    const id = window.setInterval(fetchNotifs, 15000);
    return () => window.clearInterval(id);
  }, [user, isAdmin]);

  const [realtimeToast, setRealtimeToast] = useState(null);

  useEffect(() => {
    if (!user) return undefined;
    const fetchAlerts = async () => {
      // Admin uses /api/admin/alerts, users use /api/user/alerts (only when inAppAlerts enabled)
      if (!isAdmin && !userPreferences.inAppAlerts) return;
      try {
        const token = localStorage.getItem('hp_token');
        const endpoint = isAdmin ? '/api/admin/alerts' : '/api/user/alerts';
        const response = await axios.get(`http://127.0.0.1:8000${endpoint}`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        setAlerts(response.data || []);
        setAlertFeedError('');
      } catch (error) {
        // Silently ignore 401s here — AuthContext interceptor handles session expiry
        if (error.response?.status !== 401) {
          setAlertFeedError(error.response?.data?.detail || 'Security alerts could not be refreshed.');
        }
      }
    };
    fetchAlerts();
    const intervalId = window.setInterval(fetchAlerts, 8000);
    return () => window.clearInterval(intervalId);
  }, [isAdmin, user, userPreferences.inAppAlerts]);

  // Real-time SSE alert push transport for Admin
  useEffect(() => {
    if (!isAdmin || !user) return undefined;
    const token = localStorage.getItem('hp_token');
    const es = new EventSource(`http://127.0.0.1:8000/api/soc/alerts/stream?token=${encodeURIComponent(token || '')}`);

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type !== 'SECURITY_ALERT' && payload.type !== 'CHAT_ACTIVITY') return;
        if (payload.type === 'SECURITY_ALERT' && payload.alert) {
          const newAlert = payload.alert;
          // Immediately prepend to alerts list (dedup by alert_id)
          setAlerts(prev => {
            const exists = prev.some(a =>
              (a.alert_id && a.alert_id === newAlert.alert_id) ||
              (a.request_id && a.request_id === newAlert.request_id)
            );
            if (exists) return prev;
            return [newAlert, ...prev];
          });
          // Show toast
          setRealtimeToast(newAlert);
          // Auto-dismiss toast after 8s
          setTimeout(() => setRealtimeToast(t => t?.alert_id === newAlert.alert_id ? null : t), 8000);
          // Broadcast to all admin pages
          window.dispatchEvent(new CustomEvent('hp-admin-alert', { detail: newAlert }));
        }
        window.dispatchEvent(new CustomEvent('hp-data-refresh', { detail: payload.activity }));
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    };

    es.onerror = () => {
      // SSE will auto-reconnect; no action needed
    };

    return () => {
      es.close();
    };
  }, [isAdmin, user]);

  useEffect(() => {
    const toolsPaths = ['/soc/model', '/soc/testing', '/soc/incidents', '/soc/policies', '/admin/patterns'];
    const legacyPaths = ['/sentinel', '/threats', '/logs', '/analytics'];
    if (toolsPaths.some(p => location.pathname.startsWith(p))) setToolsOpen(true);
    if (legacyPaths.some(p => location.pathname.startsWith(p))) setLegacyOpen(true);
  }, [location.pathname]);

  if (authLoading) return <LoadingState label="Verifying your secure session..." fullScreen />;
  if (!user) return <Navigate to="/login" replace />;

  const adminOnlyPaths = ['/dashboard', '/sentinel', '/threats', '/logs', '/analytics', '/admin/patterns',
    '/soc', '/soc/alerts', '/soc/threat-intel', '/soc/user-risk', '/soc/investigation',
    '/soc/audit', '/soc/restrictions', '/soc/model', '/soc/testing', '/soc/incidents',
    '/soc/reports', '/soc/policies'];
  if (!isAdmin && adminOnlyPaths.some(p => location.pathname.startsWith(p))) return <Navigate to="/" replace />;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const closeMobileNav = () => setMobileNavOpen(false);
  const toggleSidebarPinned = () => {
    setSidebarPinned(current => {
      const next = !current;
      localStorage.setItem('hp_sidebar_pinned', String(next));
      return next;
    });
  };
  const routeTitle = {
    '/': 'Secure Chat', '/dashboard': 'Dashboard', '/sentinel': 'Live Sentinel',
    '/threats': 'Threat Matrix', '/logs': 'Audit Logs', '/analytics': 'Analytics',
    '/settings': 'Settings', '/history': 'Security History', '/chat-history': 'Chat History',
    '/alerts': 'Security Alerts', '/profile': 'Your Profile', '/reports': 'My Reports', '/admin/patterns': 'Security Rules',
    '/soc': 'Command Center', '/soc/alerts': 'Security Alerts', '/soc/threat-intel': 'Threat Intelligence',
    '/soc/user-risk': 'User Risk', '/soc/investigation': 'Threat Investigation',
    '/soc/audit': 'Audit Log', '/soc/restrictions': 'Active Restrictions',
    '/soc/model': 'Model Monitor', '/soc/testing': 'Security Testing',
    '/soc/incidents': 'Incidents', '/soc/reports': 'Reports & Exports', '/soc/policies': 'Security Policies',
  }[location.pathname] || 'Security Console';
  const unreadNotifCount = isAdmin ? 0 : adminNotifs.filter(n => !n.is_read).length;
  const visibleAlerts = isAdmin || userPreferences.inAppAlerts ? alerts : [];
  const unreadCount = (isAdmin
    ? visibleAlerts.filter(alert => new Date(alert.timestamp).getTime() > seenAt).length
    : visibleAlerts.filter(alert => !alert.is_read).length) + unreadNotifCount;

  const toggleNotifications = () => {
    const nextOpen = !notificationsOpen;
    setNotificationsOpen(nextOpen);
    if (nextOpen) {
      const timestamp = Date.now();
      localStorage.setItem(`hp_alerts_seen_${user.username}`, String(timestamp));
      setSeenAt(timestamp);
    }
  };

  const markNotificationRead = async alert => {
    if (isAdmin || alert.is_read) return;
    try {
      await axios.post(`http://127.0.0.1:8000/api/user/alerts/${encodeURIComponent(alert.request_id)}/read`);
      setAlerts(current => current.map(item => item.request_id === alert.request_id ? { ...item, is_read: true } : item));
    } catch {
      setAlerts(current => current);
    }
  };

  return (
    <div className="app-container">
      {mobileNavOpen && <button className="nav-scrim" onClick={closeMobileNav} aria-label="Close navigation" />}
      <aside className={`sidebar${mobileNavOpen ? ' sidebar-open' : ''}${sidebarPinned ? ' sidebar-pinned' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><img src={HoneyPromptLogo} alt="" /></div>
          <div>
            <div className="brand-name">HoneyPrompt</div>
            <div className="brand-badge">SENTINEL V2.4</div>
          </div>
          <button className="icon-button sidebar-close" onClick={closeMobileNav} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <button
          type="button"
          className="sidebar-pin"
          onClick={toggleSidebarPinned}
          aria-label={sidebarPinned ? 'Unpin sidebar; expand on hover' : 'Pin sidebar open'}
          aria-pressed={sidebarPinned}
          title={sidebarPinned ? 'Unpin sidebar' : 'Pin sidebar open'}
        >
          <Pin size={15} />
        </button>

        <div className="nav-section-label">{isAdmin ? 'System operations' : 'My workspace'}</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {isAdmin && (
            <NavLink to="/dashboard" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <LayoutDashboard size={17} /> Dashboard
            </NavLink>
          )}

          {isAdmin && <>
            <NavLink to="/soc" end onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Shield size={17} /> Command Center</NavLink>
            <NavLink to="/soc/alerts" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Bell size={17} /> Security Alerts</NavLink>
            <NavLink to="/soc/user-risk" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><User size={17} /> User Risk</NavLink>
            <NavLink to="/soc/threat-intel" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><BarChart2 size={17} /> Threat Intelligence</NavLink>
            <NavLink to="/soc/investigation" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Hexagon size={17} /> Investigation</NavLink>
            <NavLink to="/soc/audit" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> Audit Logs</NavLink>
            <NavLink to="/soc/restrictions" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Activity size={17} /> Restrictions</NavLink>
            <NavLink to="/soc/reports" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> Reports</NavLink>

            {/* Secondary / Admin Tools Submenu */}
            <div className="nav-submenu">
              <button
                type="button"
                className={`nav-submenu-toggle ${['/soc/model', '/soc/testing', '/soc/incidents', '/soc/policies', '/admin/patterns'].some(p => location.pathname.startsWith(p)) ? 'active-within' : ''}`}
                onClick={() => setToolsOpen(!toolsOpen)}
              >
                <SlidersHorizontal size={17} />
                <span>More / Security Tools</span>
                <ChevronDown size={14} className={`submenu-arrow ${toolsOpen ? 'rotated' : ''}`} />
              </button>
              {toolsOpen && (
                <div className="nav-submenu-items">
                  <NavLink to="/soc/model" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Model Monitor</NavLink>
                  <NavLink to="/soc/testing" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Security Testing</NavLink>
                  <NavLink to="/soc/incidents" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Incidents</NavLink>
                  <NavLink to="/soc/policies" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Policies</NavLink>
                  <NavLink to="/admin/patterns" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Security Rules</NavLink>
                </div>
              )}
            </div>

            {/* Legacy Submenu */}
            <div className="nav-submenu">
              <button
                type="button"
                className={`nav-submenu-toggle ${['/sentinel', '/threats', '/logs', '/analytics'].some(p => location.pathname.startsWith(p)) ? 'active-within' : ''}`}
                onClick={() => setLegacyOpen(!legacyOpen)}
              >
                <Activity size={17} />
                <span>Legacy Tools</span>
                <ChevronDown size={14} className={`submenu-arrow ${legacyOpen ? 'rotated' : ''}`} />
              </button>
              {legacyOpen && (
                <div className="nav-submenu-items">
                  <NavLink to="/sentinel" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Live Sentinel</NavLink>
                  <NavLink to="/threats" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Threat Matrix</NavLink>
                  <NavLink to="/logs" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Audit Logs (Legacy)</NavLink>
                  <NavLink to="/analytics" onClick={closeMobileNav} className={({ isActive }) => `nav-item nav-subitem ${isActive ? 'active' : ''}`}>Analytics</NavLink>
                </div>
              )}
            </div>
          </>}

          <NavLink to="/" end onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <MessageSquare size={17} /> Secure Chat
          </NavLink>
          {!isAdmin && <>
            <NavLink to="/chat-history" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><MessageSquare size={17} /> Chat History</NavLink>
            <NavLink to="/alerts" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Bell size={17} /> Alerts{unreadCount > 0 && <span className="nav-count">{unreadCount > 9 ? '9+' : unreadCount}</span>}</NavLink>
            <NavLink to="/reports" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> My Reports</NavLink>
            <NavLink to="/profile" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><User size={17} /> Profile</NavLink>
          </>}
          {isAdmin && <NavLink to="/chat-history" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><MessageSquare size={17} /> Chat History</NavLink>}
          <NavLink to="/settings" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Settings size={17} /> Settings
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <button className="theme-toggle" onClick={toggle}>
            {theme === 'dark' ? <><Moon size={15} /> Dark Mode</> : <><Sun size={15} /> Light Mode</>}
          </button>

          <div className="profile-wrap">
            <button className="profile-trigger" onClick={() => setProfileOpen(o => !o)} aria-expanded={profileOpen}>
              <span className="profile-avatar"><User size={16} /></span>
              <span className="profile-summary">
                <span className="profile-name">{user.username}</span>
                <span className="profile-status"><i /> Active session</span>
              </span>
              <ChevronDown size={15} className={profileOpen ? 'chevron-open' : ''} />
            </button>

            {profileOpen && (
              <div className="profile-menu">
                <div className="profile-detail">
                  <strong>{user.full_name}</strong>
                  <span>{user.email}</span>
                  <span>Role: <b>{user.role}</b></span>
                </div>
                <button className="profile-menu-link" onClick={() => { setProfileOpen(false); navigate(isAdmin ? '/settings' : '/profile'); }}>Profile</button>
                <button className="profile-menu-link" onClick={() => { setProfileOpen(false); navigate('/settings'); }}>Settings</button>
                {isAdmin && <button className="profile-menu-link" onClick={() => { setProfileOpen(false); navigate('/admin/patterns'); }}>Security rules</button>}
                <button onClick={handleLogout} className="profile-logout">
                  <LogOut size={14} /> Sign Out
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      <div className="main-content">
        <div className="top-bar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={20} /></button>
          <div className="topbar-page"><span className="topbar-eyebrow">SECURITY OPERATIONS</span><strong>{routeTitle}</strong></div>
          <span className="system-pill"><i /> SYSTEM NOMINAL</span>
          <div className="notification-wrap">
            <button className="icon-button notification-button" onClick={toggleNotifications} aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ''}`} aria-expanded={notificationsOpen}>
              <Bell size={18} />{unreadCount > 0 && <span className="notification-count">{unreadCount > 9 ? '9+' : unreadCount}</span>}
            </button>
            {notificationsOpen && <section className="notification-center" aria-label="Security notifications">
              <div className="notification-heading"><div><span className="topbar-eyebrow">SECURITY FEED</span><strong>{isAdmin ? 'System alerts' : 'My alerts'}</strong></div><span className="monitor-live"><i /> LIVE</span></div>
              {/* Admin notifications for users */}
              {!isAdmin && adminNotifs.filter(n => !n.is_read).slice(0, 3).map(n => (
                <article className="notification-item" key={n.notification_id} style={{ borderLeft: `3px solid ${n.priority === 'danger' ? '#ef4444' : n.priority === 'warning' ? '#f59e0b' : n.priority === 'success' ? '#10b981' : '#3b82f6'}` }}>
                  <span className="notification-severity" style={{ color: n.priority === 'danger' ? '#ef4444' : n.priority === 'warning' ? '#f59e0b' : '#3b82f6' }}>ADMIN</span>
                  <div><strong>{n.title}</strong><span>{n.message.slice(0, 80)}{n.message.length > 80 ? '…' : ''}</span><span>{new Date(n.created_at).toLocaleString()}</span></div>
                </article>
              ))}
              {visibleAlerts.length ? visibleAlerts.slice(0, 6).map(alert => <article className={`notification-item${alert.is_read ? ' notification-read' : ''}${alert.repeated_malicious_activity ? ' multiple-attempts-alert' : ''}`} key={alert.alert_id || alert.request_id}>
                <span className="notification-severity">{alert.repeated_malicious_activity ? 'REPEATED' : (alert.severity || alert.classification)}</span>
                <div>
                  <strong>{alert.repeated_malicious_activity ? `Repeated Malicious Activity · ${alert.consecutive_count} consecutive` : alert.threat_type}</strong>
                  <span>{isAdmin ? `${alert.user} · ` : ''}{alert.severity} · {Math.round((alert.confidence || 0) * 100)}% · {alert.current_action || alert.action}</span>
                  {alert.prompt_preview && <span style={{ fontStyle: 'italic', opacity: 0.85 }}>"{alert.prompt_preview.slice(0, 75)}"</span>}
                  <span>{new Date(alert.timestamp).toLocaleString()}</span>
                  {isAdmin && (
                    <button
                      className="notification-mark-read"
                      style={{ marginTop: 5, alignSelf: 'flex-start' }}
                      onClick={() => {
                        setNotificationsOpen(false);
                        navigate('/soc/alerts');
                      }}
                    >
                      View Investigation
                    </button>
                  )}
                </div>
                {!isAdmin && !alert.is_read && <button className="notification-mark-read" onClick={() => markNotificationRead(alert)}>Mark read</button>}
              </article>) : (!isAdmin && adminNotifs.length === 0 ? <p className="notification-empty">No security alerts in this feed.</p> : null)}
              {alertFeedError && <p className="notification-error" role="status">{alertFeedError}</p>}
              {adminNotifError && <p className="notification-error" role="status">{adminNotifError}</p>}
              {!isAdmin && adminNotifs.length === 0 && visibleAlerts.length === 0 && <p className="notification-empty">No alerts.</p>}
            </section>}
          </div>
          <span className="topbar-version">SENTINEL <b>V2.4</b></span>
        </div>

        <div className="page-container">
          <Routes>
            <Route path="/" element={<ChatPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/sentinel" element={<LiveSentinelPage />} />
            <Route path="/threats" element={<ThreatMatrixPage />} />
            <Route path="/logs" element={<AuditLogsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/history" element={<UserHistoryPage />} />
            <Route path="/chat-history" element={<ChatHistoryPage />} />
            <Route path="/alerts" element={<UserAlertsPage />} />
            <Route path="/reports" element={<UserReportsPage />} />
            <Route path="/profile" element={<UserProfilePage />} />
            <Route path="/admin/patterns" element={<AdminPatternsPage />} />
            <Route path="/soc" element={<SOCCommandCenter />} />
            <Route path="/soc/alerts" element={<SOCAlerts />} />
            <Route path="/soc/threat-intel" element={<SOCThreatIntelligence />} />
            <Route path="/soc/user-risk" element={<SOCUserRisk />} />
            <Route path="/soc/investigation" element={<SOCThreatInvestigation />} />
            <Route path="/soc/audit" element={<SOCAuditLogs />} />
            <Route path="/soc/restrictions" element={<SOCRestrictions />} />
            <Route path="/soc/model" element={<SOCModelMonitor />} />
            <Route path="/soc/testing" element={<SOCSecurityTesting />} />
            <Route path="/soc/incidents" element={<SOCIncidents />} />
            <Route path="/soc/reports" element={<SOCReports />} />
            <Route path="/soc/policies" element={<SOCPolicies />} />
          </Routes>
        </div>
      </div>

      {/* Real-time Admin Alert Toast Notification (Requirements 7 & 8) */}
      {isAdmin && realtimeToast && (
        <aside className="soc-realtime-toast" role="alert" aria-live="assertive">
          <div className="soc-toast-header">
            <div className="soc-toast-title">
              <AlertTriangle size={18} className="soc-toast-icon" />
              <strong>
                {realtimeToast.severity === 'CRITICAL' ? '⚠️ CRITICAL THREAT DETECTED' : '⚠️ HIGH-RISK ACTIVITY DETECTED'}
              </strong>
            </div>
            <button
              className="soc-toast-close"
              onClick={() => setRealtimeToast(null)}
              aria-label="Dismiss notification"
            >
              <X size={15} />
            </button>
          </div>

          <div className="soc-toast-body">
            <div className="soc-toast-row">
              <span className="soc-toast-label">Severity:</span>
              <span className="soc-toast-badge" style={{ color: realtimeToast.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b', fontWeight: 700 }}>
                {realtimeToast.severity_icon || '🔴'} {realtimeToast.severity}
              </span>
            </div>
            <div className="soc-toast-row">
              <span className="soc-toast-label">User:</span>
              <strong className="soc-toast-val">{realtimeToast.user}</strong>
            </div>
            <div className="soc-toast-row">
              <span className="soc-toast-label">Threat:</span>
              <span className="soc-toast-val">{realtimeToast.threat_type}</span>
            </div>
            <div className="soc-toast-row">
              <span className="soc-toast-label">Risk Score:</span>
              <span className="soc-toast-val" style={{ color: '#ef4444', fontWeight: 700 }}>{realtimeToast.risk_score} / 100</span>
            </div>
            <div className="soc-toast-row">
              <span className="soc-toast-label">Confidence:</span>
              <span className="soc-toast-val">{Math.round((realtimeToast.confidence || 0) * 100)}%</span>
            </div>
            {realtimeToast.prompt_preview && (
              <div className="soc-toast-preview">
                "{realtimeToast.prompt_preview}"
              </div>
            )}
            <div className="soc-toast-row">
              <span className="soc-toast-label">Action:</span>
              <strong className="soc-toast-action" style={{ color: '#f59e0b' }}>{realtimeToast.action || 'Review Required'}</strong>
            </div>
          </div>

          <div className="soc-toast-footer">
            <button
              className="soc-toast-btn-action"
              onClick={() => {
                setRealtimeToast(null);
                const timestamp = Date.now();
                localStorage.setItem(`hp_alerts_seen_${user.username}`, String(timestamp));
                setSeenAt(timestamp);
                navigate('/soc/alerts');
              }}
            >
              View Investigation
            </button>
            <button
              className="soc-toast-btn-dismiss"
              onClick={() => setRealtimeToast(null)}
            >
              Dismiss
            </button>
          </div>
        </aside>
      )}
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <HoneyBeeBackground />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route path="/*" element={<ProtectedLayout />} />
      </Routes>
    </Router>
  );
}
