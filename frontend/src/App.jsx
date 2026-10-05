import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, FileText, Hexagon, BarChart2, Settings, LogOut, Moon, Sun, User, ChevronDown, Activity, MessageSquare, Menu, X, Bell, SlidersHorizontal, AlertTriangle } from 'lucide-react';
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
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [userPreferences, setUserPreferences] = useState(storedUserPreferences);
  const [seenAt, setSeenAt] = useState(() => Number(localStorage.getItem(`hp_alerts_seen_${user?.username || 'guest'}`) || 0));

  const isAdmin = user?.role?.toLowerCase() === 'admin';

  useEffect(() => {
    const onPreferencesChanged = event => setUserPreferences(current => ({ ...current, ...event.detail }));
    window.addEventListener('hp-user-preferences', onPreferencesChanged);
    return () => window.removeEventListener('hp-user-preferences', onPreferencesChanged);
  }, []);

  useEffect(() => {
    if (!user) return undefined;
    const endpoint = isAdmin ? '/api/admin/alerts' : '/api/user/alerts';
    const fetchAlerts = async () => {
      if (!isAdmin && !userPreferences.inAppAlerts) return;
      try {
        const response = await axios.get(`http://127.0.0.1:8000${endpoint}`);
        setAlerts(response.data);
      } catch {
        setAlerts([]);
      }
    };
    fetchAlerts();
    const intervalId = window.setInterval(fetchAlerts, 5000);
    return () => window.clearInterval(intervalId);
  }, [isAdmin, user, userPreferences.inAppAlerts]);

  if (authLoading) return <LoadingState label="Verifying your secure session..." fullScreen />;
  if (!user) return <Navigate to="/login" replace />;

  const adminOnlyPaths = ['/sentinel', '/threats', '/logs', '/analytics', '/admin/patterns',
    '/soc', '/soc/alerts', '/soc/threat-intel', '/soc/user-risk', '/soc/investigation',
    '/soc/audit', '/soc/restrictions', '/soc/model', '/soc/testing', '/soc/incidents',
    '/soc/reports', '/soc/policies'];
  if (!isAdmin && adminOnlyPaths.some(p => location.pathname.startsWith(p))) return <Navigate to="/dashboard" replace />;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const closeMobileNav = () => setMobileNavOpen(false);
  const routeTitle = {
    '/': 'Secure Chat', '/dashboard': 'Dashboard', '/sentinel': 'Live Sentinel',
    '/threats': 'Threat Matrix', '/logs': 'Audit Logs', '/analytics': 'Analytics',
    '/settings': 'Settings', '/history': 'Security History', '/chat-history': 'Chat History',
    '/alerts': 'Security Alerts', '/profile': 'Your Profile', '/admin/patterns': 'Security Rules',
    '/soc': 'Command Center', '/soc/alerts': 'Security Alerts', '/soc/threat-intel': 'Threat Intelligence',
    '/soc/user-risk': 'User Risk', '/soc/investigation': 'Threat Investigation',
    '/soc/audit': 'Audit Log', '/soc/restrictions': 'Active Restrictions',
    '/soc/model': 'Model Monitor', '/soc/testing': 'Security Testing',
    '/soc/incidents': 'Incidents', '/soc/reports': 'Reports', '/soc/policies': 'Security Policies',
  }[location.pathname] || 'Security Console';
  const visibleAlerts = isAdmin || userPreferences.inAppAlerts ? alerts : [];
  const unreadCount = isAdmin
    ? visibleAlerts.filter(alert => new Date(alert.timestamp).getTime() > seenAt).length
    : visibleAlerts.filter(alert => !alert.is_read).length;

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
      <aside className={`sidebar${mobileNavOpen ? ' sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><img src={HoneyPromptLogo} alt="" /></div>
          <div>
            <div className="brand-name">HoneyPrompt</div>
            <div className="brand-badge">SENTINEL V2.4</div>
          </div>
          <button className="icon-button sidebar-close" onClick={closeMobileNav} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <div className="nav-section-label">{isAdmin ? 'System operations' : 'My workspace'}</div>
        <nav className="primary-nav" aria-label="Main navigation">
          <NavLink to="/dashboard" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <LayoutDashboard size={17} /> Dashboard
          </NavLink>
          {isAdmin && <>
            <div className="nav-section-label" style={{marginTop:8}}>SOC</div>
            <NavLink to="/soc" end onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Shield size={17} /> Command Center</NavLink>
            <NavLink to="/soc/alerts" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Bell size={17} /> Security Alerts</NavLink>
            <NavLink to="/soc/user-risk" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><User size={17} /> User Risk</NavLink>
            <NavLink to="/soc/threat-intel" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><BarChart2 size={17} /> Threat Intel</NavLink>
            <NavLink to="/soc/investigation" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Hexagon size={17} /> Investigation</NavLink>
            <NavLink to="/soc/audit" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> Audit Log</NavLink>
            <NavLink to="/soc/restrictions" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Activity size={17} /> Restrictions</NavLink>
            <NavLink to="/soc/model" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><SlidersHorizontal size={17} /> Model Monitor</NavLink>
            <NavLink to="/soc/testing" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Shield size={17} /> Security Testing</NavLink>
            <NavLink to="/soc/incidents" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><AlertTriangle size={17} /> Incidents</NavLink>
            <NavLink to="/soc/reports" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><BarChart2 size={17} /> Reports</NavLink>
            <NavLink to="/soc/policies" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Settings size={17} /> Policies</NavLink>
            <div className="nav-section-label" style={{marginTop:8}}>LEGACY</div>
            <NavLink to="/sentinel" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Activity size={17} /> Live Sentinel</NavLink>
            <NavLink to="/threats" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Hexagon size={17} /> Threat Matrix</NavLink>
            <NavLink to="/logs" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> Audit Logs</NavLink>
            <NavLink to="/analytics" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><BarChart2 size={17} /> Analytics</NavLink>
            <NavLink to="/admin/patterns" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><SlidersHorizontal size={17} /> Security Rules</NavLink>
          </>}
          <NavLink to="/" end onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <MessageSquare size={17} /> Secure Chat
          </NavLink>
          {!isAdmin && <>
            <NavLink to="/chat-history" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><MessageSquare size={17} /> Chat History</NavLink>
            <NavLink to="/history" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><FileText size={17} /> Security History</NavLink>
            <NavLink to="/alerts" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><Bell size={17} /> Alerts{unreadCount > 0 && <span className="nav-count">{unreadCount > 9 ? '9+' : unreadCount}</span>}</NavLink>
            <NavLink to="/profile" onClick={closeMobileNav} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}><User size={17} /> Profile</NavLink>
          </>}
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
              {visibleAlerts.length ? visibleAlerts.slice(0, 6).map(alert => <article className={`notification-item${alert.is_read ? ' notification-read' : ''}${alert.repeated_malicious_activity ? ' multiple-attempts-alert' : ''}`} key={alert.request_id}>
                <span className="notification-severity">{alert.repeated_malicious_activity ? 'REPEATED' : alert.classification}</span>
                <div><strong>{alert.repeated_malicious_activity ? `Repeated Malicious Activity · ${alert.consecutive_count} consecutive` : alert.threat_type}</strong><span>{isAdmin ? `${alert.user} · ` : ''}{alert.severity} · {Math.round((alert.confidence || 0) * 100)}% · {alert.current_action || alert.action}</span><span>{new Date(alert.timestamp).toLocaleString()}</span></div>
                {!isAdmin && !alert.is_read && <button className="notification-mark-read" onClick={() => markNotificationRead(alert)}>Mark read</button>}
              </article>) : <p className="notification-empty">No security alerts in this feed.</p>}
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
