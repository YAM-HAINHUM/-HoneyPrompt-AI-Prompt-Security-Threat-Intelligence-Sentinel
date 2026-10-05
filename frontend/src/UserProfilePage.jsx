import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { CalendarDays, Clock3, KeyRound, LogOut, ShieldCheck, UserRound } from 'lucide-react';
import { useAuth } from './AuthContext';
import LoadingState from './LoadingState';

export default function UserProfilePage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [passwordForm, setPasswordForm] = useState({ current_password: '', new_password: '', confirm_password: '' });
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const initials = (user?.full_name || user?.username || 'HP')
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(part => part[0].toUpperCase())
    .join('');

  const handlePasswordChange = event => setPasswordForm(current => ({ ...current, [event.target.name]: event.target.value }));

  const submitPassword = async event => {
    event.preventDefault();
    setMessage('');
    setError('');
    if (passwordForm.new_password.length < 8) {
      setError('Your new password must contain at least 8 characters.');
      return;
    }
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setError('The new passwords do not match.');
      return;
    }
    setSaving(true);
    try {
      await axios.post('http://127.0.0.1:8000/api/user/password', {
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      });
      setMessage('Password updated. Sign in again with your new password.');
      await logout();
      navigate('/login', { replace: true });
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Your password could not be updated.');
    } finally {
      setSaving(false);
    }
  };

  const signOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="role-dashboard profile-page">
      <header className="role-page-heading"><div><span className="eyebrow">PERSONAL ACCOUNT</span><h1>Your profile</h1><p>Account identity and session security.</p></div><span className="role-label role-label-user"><ShieldCheck size={14} /> ACCOUNT ACTIVE</span></header>

      <section className="profile-hero card">
        <div className="profile-large-avatar" aria-label={`Avatar for ${user?.full_name || user?.username}`}>{initials}</div>
        <div className="profile-hero-copy"><span className="eyebrow">HONEYPROMPT USER</span><h2>{user?.full_name || user?.username}</h2><p>{user?.email}</p></div>
        <div className="profile-role-mark"><UserRound size={15} /> {user?.role || 'User'}</div>
      </section>

      <section className="profile-details-grid" aria-label="Account details">
        <article className="card profile-detail-card"><span className="profile-detail-icon"><UserRound size={16} /></span><span className="eyebrow">USERNAME</span><strong>{user?.username || '—'}</strong></article>
        <article className="card profile-detail-card"><span className="profile-detail-icon"><CalendarDays size={16} /></span><span className="eyebrow">ACCOUNT CREATED</span><strong>{user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Not available'}</strong></article>
        <article className="card profile-detail-card"><span className="profile-detail-icon"><Clock3 size={16} /></span><span className="eyebrow">LAST LOGIN</span><strong>{user?.last_login ? new Date(user.last_login).toLocaleString() : 'Not available'}</strong></article>
        <article className="card profile-detail-card"><span className="profile-detail-icon"><ShieldCheck size={16} /></span><span className="eyebrow">ACCOUNT STATUS</span><strong>{user?.is_blocked ? 'Blocked' : user?.is_active === false ? 'Inactive' : 'Active'}</strong></article>
      </section>

      <section className="card profile-security-card">
        <div className="panel-heading"><div><span className="eyebrow">CREDENTIALS</span><h2>Change password</h2></div><KeyRound size={17} className="text-gold" /></div>
        <form className="profile-password-form" onSubmit={submitPassword}>
          <label>Current password<input name="current_password" type="password" autoComplete="current-password" required value={passwordForm.current_password} onChange={handlePasswordChange} /></label>
          <label>New password<input name="new_password" type="password" autoComplete="new-password" minLength={8} required value={passwordForm.new_password} onChange={handlePasswordChange} /></label>
          <label>Confirm new password<input name="confirm_password" type="password" autoComplete="new-password" minLength={8} required value={passwordForm.confirm_password} onChange={handlePasswordChange} /></label>
          {saving && <LoadingState label="Updating your secure credentials..." compact />}
          {error && <p className="auth-error" role="alert">{error}</p>}
          {message && <p className="dashboard-notice" role="status">{message}</p>}
          <button className="btn-primary" type="submit" disabled={saving}>{saving ? 'Updating password...' : 'Update password'}</button>
        </form>
      </section>

      <section className="card profile-session-card">
        <div><span className="eyebrow">SESSION</span><strong>Sign out of this device</strong><span>Your current HoneyPrompt session will be ended.</span></div>
        <button type="button" className="btn-secondary" onClick={signOut}><LogOut size={15} /> Sign out</button>
      </section>
    </div>
  );
}