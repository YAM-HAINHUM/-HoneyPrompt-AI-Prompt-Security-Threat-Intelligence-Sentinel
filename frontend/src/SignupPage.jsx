import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Eye, EyeOff, AlertCircle, Activity, LockKeyhole, Radio, Check } from 'lucide-react';
import { useAuth } from './AuthContext';
import HoneyPromptLogo from './assets/honeyprompt-logo.png';
import LoadingState from './LoadingState';

export default function SignupPage() {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ full_name: '', username: '', email: '', password: '', confirm: '' });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handle = (e) => setForm(f => ({ ...f, [e.target.name]: e.target.value }));
  const passwordChecks = [
    ['8+ characters', form.password.length >= 8],
    ['Uppercase', /[A-Z]/.test(form.password)],
    ['Lowercase', /[a-z]/.test(form.password)],
    ['Number', /\d/.test(form.password)],
    ['Special character', /[^A-Za-z0-9]/.test(form.password)],
  ];
  const passwordScore = passwordChecks.filter(([, passed]) => passed).length;
  const passwordStrength = passwordScore < 3 ? 'Weak' : passwordScore < 5 ? 'Medium' : 'Strong';

  const submit = async (e) => {
    e.preventDefault();
    const { full_name, username, email, password, confirm } = form;
    if (!full_name.trim() || !username.trim() || !email.trim() || !password) { setError('All fields are required.'); return; }
    if (password.length < 8) { setError('Password must be at least 8 characters.'); return; }
    if (password !== confirm) { setError('Passwords do not match.'); return; }
    if (!/\S+@\S+\.\S+/.test(email)) { setError('Please enter a valid email address.'); return; }
    setError(''); setLoading(true);
    try {
      await signup(full_name.trim(), username.trim(), email.trim(), password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.detail || 'Signup failed. Please try again.');
    } finally { setLoading(false); }
  };

  return (
    <div className="auth-page signup-page">
      <section className="auth-story">
        <div className="auth-story-top">
          <div className="auth-logo-area">
            <div className="auth-logo-icon"><img src={HoneyPromptLogo} alt="" /></div>
            <div><div className="auth-logo-name">HoneyPrompt</div><div className="auth-logo-sub">AI PROMPT SECURITY</div></div>
          </div>
        </div>
        <div className="auth-story-copy">
          <span className="eyebrow"><i /> SENTINEL V2.4 / SECURITY CONSOLE</span>
          <h1 className="auth-tagline">Make your AI<br /><span>safer by design.</span></h1>
          <p className="auth-desc-text">Bring prompt defense, threat visibility, and secure AI conversations into one operational console.</p>
          <div className="auth-monitor">
            <div className="monitor-heading"><span>PROTECTION LAYERS</span><span className="monitor-live"><i /> READY</span></div>
            <div className="monitor-statuses">
              <div><Activity size={15} /><span>PROMPT INSPECTION</span><b>ENABLED</b></div>
              <div><Radio size={15} /><span>THREAT INTELLIGENCE</span><b>ACTIVE</b></div>
              <div><LockKeyhole size={15} /><span>SECURE AI GATEWAY</span><b>ONLINE</b></div>
            </div>
          </div>
        </div>
        <div className="auth-story-foot"><span>AI PROMPT SECURITY &amp; THREAT INTELLIGENCE</span><span>02 / ACCOUNT ENROLLMENT</span></div>
      </section>

      <section className="auth-right signup-right">
        <div className="auth-card">
          <div className="auth-brand">
            <span className="auth-brand-image-frame"><img className="brand-icon auth-brand-image" src={HoneyPromptLogo} alt="" /></span>
            <div><div className="auth-title">HoneyPrompt</div><div className="auth-subtitle">SENTINEL V2.4</div></div>
          </div>

        <span className="eyebrow auth-form-eyebrow">SECURE ACCESS / 02</span>
        <h2 className="auth-heading">Create your account</h2>
        <p className="auth-desc">Start monitoring and protecting your AI systems.</p>

        {error && <div className="auth-error" role="alert"><AlertCircle size={15} /> {error}</div>}
        {loading && <LoadingState label="Securing your new account..." compact />}

        <form onSubmit={submit} className="auth-form">
          <div className="form-group">
            <label htmlFor="signup-fullname">Full name</label>
            <input id="signup-fullname" name="full_name" value={form.full_name} onChange={handle} placeholder="Your name" autoComplete="name" />
          </div>
          <div className="form-group">
            <label htmlFor="signup-username">Username</label>
            <input id="signup-username" name="username" value={form.username} onChange={handle} placeholder="Choose a username" autoComplete="username" />
          </div>
          <div className="form-group">
            <label htmlFor="signup-email">Email address</label>
            <input id="signup-email" name="email" type="email" value={form.email} onChange={handle} placeholder="you@company.com" autoComplete="email" />
          </div>
          <div className="form-group">
            <label htmlFor="signup-password">Password</label>
            <div className="pw-wrap">
              <input id="signup-password" name="password" type={showPw ? 'text' : 'password'} value={form.password} onChange={handle} placeholder="Create a strong password" autoComplete="new-password" />
              <button type="button" className="pw-toggle" onClick={() => setShowPw(s => !s)} aria-label={showPw ? 'Hide password' : 'Show password'}>
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <div className="password-meter" aria-label={`Password strength: ${passwordStrength.toLowerCase()}`}>
              <div className="pw-strength-bar">{[1, 2, 3].map(level => <i key={level} className={passwordScore >= (level === 1 ? 1 : level === 2 ? 3 : 5) ? `strength-${level}` : ''} />)}</div>
              <span>{passwordStrength}</span>
            </div>
            <div className="pw-reqs">{passwordChecks.map(([label, passed]) => <span key={label} className={`pw-req${passed ? ' met' : ''}`}><Check size={12} /> {label}</span>)}</div>
          </div>
          <div className="form-group">
            <label htmlFor="signup-confirm">Confirm password</label>
            <input id="signup-confirm" name="confirm" type={showPw ? 'text' : 'password'} value={form.confirm} onChange={handle} placeholder="Re-enter your password" autoComplete="new-password" />
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Creating account...' : <>Create account <span aria-hidden="true">→</span></>}
          </button>
        </form>

        <p className="auth-switch">Already have an account? <Link to="/login">Sign in <span aria-hidden="true">→</span></Link></p>
        <p className="auth-hint"><LockKeyhole size={13} /> Account details stay within your protected session.</p>
        </div>
      </section>
    </div>
  );
}
