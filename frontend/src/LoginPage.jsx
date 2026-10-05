import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, AlertCircle, Activity, LockKeyhole, Radio, UserRound, ShieldCheck } from 'lucide-react';
import { useAuth } from './AuthContext';
import HoneyPromptLogo from './assets/honeyprompt-logo.png';
import LoadingState from './LoadingState';

const TEST_ACCOUNTS = {
  user: { username: 'yammahajan0312@gmail.com', password: 'Admin@1234' },
  admin: { username: 'admin_01', password: 'Admin@1234' },
};

export default function LoginPage() {
  const { login, logout } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', password: '', remember: false, accountType: 'user' });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handle = (e) => setForm(f => ({ ...f, [e.target.name]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }));

  const fillTestCredentials = (accountType) => setForm(f => ({ ...f, ...TEST_ACCOUNTS[accountType], accountType }));

  const submit = async (e) => {
    e.preventDefault();
    if (!form.username.trim() || !form.password) { setError('Please enter username and password.'); return; }
    setError(''); setLoading(true);
    try {
      const authenticatedUser = await login(form.username.trim(), form.password);
      if (authenticatedUser.role?.toLowerCase() !== form.accountType) {
        await logout();
        setError(`This account is not assigned the ${form.accountType === 'admin' ? 'Administrator' : 'User'} role. Select the role assigned to your account.`);
        return;
      }
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please try again.');
    } finally { setLoading(false); }
  };

  return (
    <div className="auth-page">
      <section className="auth-story">
        <div className="auth-story-top">
          <div className="auth-logo-area">
            <div className="auth-logo-icon"><img src={HoneyPromptLogo} alt="" /></div>
            <div><div className="auth-logo-name">HoneyPrompt</div><div className="auth-logo-sub">AI PROMPT SECURITY</div></div>
          </div>
        </div>
        <div className="auth-story-copy">
          <span className="eyebrow"><i /> SENTINEL V2.4 / SECURITY CONSOLE</span>
          <h1 className="auth-tagline">Secure every<br /><span>AI conversation.</span></h1>
          <p className="auth-desc-text">Detect prompt injection, jailbreaks, system-prompt extraction, and adversarial attacks before they reach your AI systems.</p>
          <div className="auth-monitor">
            <div className="monitor-heading"><span>THREAT TELEMETRY</span><span className="monitor-live"><i /> LIVE</span></div>
            <div className="monitor-chart" aria-label="Decorative threat telemetry visualization">
              {[22, 34, 28, 47, 38, 62, 43, 56, 32, 72, 48, 66, 42, 58, 36, 76, 51, 64, 44, 82, 54, 68, 49, 74, 57, 88, 62, 78, 52, 69, 46, 84].map((height, index) => <i key={index} style={{ '--bar-height': `${height}%` }} />)}
            </div>
            <div className="monitor-statuses">
              <div><Activity size={15} /><span>SYSTEM STATUS</span><b>PROTECTED</b></div>
              <div><Radio size={15} /><span>THREAT DETECTION</span><b>ACTIVE</b></div>
              <div><LockKeyhole size={15} /><span>LLM SECURITY</span><b>ONLINE</b></div>
            </div>
          </div>
        </div>
        <div className="auth-story-foot"><span>AI PROMPT SECURITY &amp; THREAT INTELLIGENCE</span><span>01 / ACCESS CONTROL</span></div>
      </section>

      <section className="auth-right">
        <div className="auth-card">
          <div className="auth-brand">
            <span className="auth-brand-image-frame"><img className="brand-icon auth-brand-image" src={HoneyPromptLogo} alt="" /></span>
            <div><div className="auth-title">HoneyPrompt</div><div className="auth-subtitle">SENTINEL V2.4</div></div>
          </div>

          <span className="eyebrow auth-form-eyebrow">SECURE ACCESS / 01</span>
          <h2 className="auth-heading">Welcome back</h2>
          <p className="auth-desc">Sign in to access your HoneyPrompt security console.</p>

          {error && <div className="auth-error" role="alert"><AlertCircle size={15} /> {error}</div>}
          {loading && <LoadingState label="Verifying your secure account..." compact />}

          <form onSubmit={submit} className="auth-form">
            <fieldset className="account-mode-fieldset">
              <legend>Sign in as</legend>
              <div className="account-mode" role="group" aria-label="Choose assigned account type">
                <button type="button" className={form.accountType === 'user' ? 'selected' : ''} aria-pressed={form.accountType === 'user'} onClick={() => setForm(f => ({ ...f, accountType: 'user' }))}><UserRound size={15} /> User</button>
                <button type="button" className={form.accountType === 'admin' ? 'selected' : ''} aria-pressed={form.accountType === 'admin'} onClick={() => setForm(f => ({ ...f, accountType: 'admin' }))}><ShieldCheck size={15} /> Administrator</button>
              </div>
              <span className="account-mode-note">Access is verified against the role assigned to your account.</span>
            </fieldset>
            <div className="form-group">
              <label htmlFor="login-username">Username or email</label>
              <input id="login-username" name="username" value={form.username} onChange={handle} placeholder="name@company.com" autoComplete="username" />
            </div>
            <div className="form-group">
              <label htmlFor="login-password">Password</label>
              <div className="pw-wrap">
                <input id="login-password" name="password" type={showPw ? 'text' : 'password'} value={form.password} onChange={handle} placeholder="Enter your password" autoComplete="current-password" />
                <button type="button" className="pw-toggle" onClick={() => setShowPw(s => !s)} aria-label={showPw ? 'Hide password' : 'Show password'}>
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
            <div className="form-row">
              <label className="checkbox-label"><input type="checkbox" name="remember" checked={form.remember} onChange={handle} /> Remember me</label>
              <span className="form-note">Protected session</span>
            </div>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Verifying access...' : <>Sign in <span aria-hidden="true">→</span></>}
            </button>
          </form>

          <p className="auth-switch">New to HoneyPrompt? <Link to="/signup">Create your account <span aria-hidden="true">→</span></Link></p>
          <p className="auth-hint"><LockKeyhole size={13} /> Credentials are transmitted over your protected session.</p>
          <div className="test-credential-actions" aria-label="Fill test account credentials">
            <button type="button" onClick={() => fillTestCredentials('user')} className="test-credentials"><UserRound size={14} /> User test account</button>
            <button type="button" onClick={() => fillTestCredentials('admin')} className="test-credentials"><ShieldCheck size={14} /> Admin test account</button>
          </div>
        </div>
      </section>
    </div>
  );
}
