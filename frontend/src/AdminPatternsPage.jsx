import { useEffect, useState } from 'react';
import axios from 'axios';
import { Plus, ShieldAlert, ToggleLeft, ToggleRight } from 'lucide-react';
import LoadingState from './LoadingState';

export default function AdminPatternsPage() {
  const [patterns, setPatterns] = useState([]);
  const [phrase, setPhrase] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/admin/patterns');
      setPatterns(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to load security rules.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);

  const addPattern = async (event) => {
    event.preventDefault();
    if (!phrase.trim()) return;
    setError('');
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/admin/patterns', { phrase: phrase.trim() });
      setPatterns(current => [...current, response.data]);
      setPhrase('');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to add this rule.');
    }
  };

  const togglePattern = async (pattern) => {
    try {
      const response = await axios.patch(`http://127.0.0.1:8000/api/admin/patterns/${pattern.id}`, { is_active: !pattern.is_active });
      setPatterns(current => current.map(item => item.id === response.data.id ? response.data : item));
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to update this rule.');
    }
  };

  return (
    <div className="role-dashboard admin-rule-page">
      <header className="role-page-heading">
        <div><span className="eyebrow">ADMINISTRATOR CONTROL</span><h1>Security rules</h1><p>Manage exact phrases that the detector blocks before a prompt reaches the model.</p></div>
        <span className="role-label role-label-admin"><ShieldAlert size={14} /> ADMIN ONLY</span>
      </header>

      <form className="card rule-create-form" onSubmit={addPattern}>
        <label htmlFor="blocked-phrase">Add a blocked phrase</label>
        <div className="rule-input-row"><input id="blocked-phrase" value={phrase} onChange={event => setPhrase(event.target.value)} placeholder="Enter a phrase to block" maxLength={250} /><button className="btn-primary" type="submit"><Plus size={16} /> Add rule</button></div>
        <p>Matching is case-insensitive phrase containment. Use narrow phrases to avoid blocking unrelated prompts.</p>
      </form>

      {error && <div className="auth-error" role="alert">{error}</div>}

      <section className="card rule-list" aria-label="Managed prompt rules">
        <div className="rule-list-heading"><h2>Managed phrases</h2><span>{patterns.filter(pattern => pattern.is_active).length} active</span></div>
        {loading ? <LoadingState label="Loading security rules..." compact /> : patterns.length === 0 ? <p className="empty-state">No administrator-managed phrases yet.</p> : patterns.map(pattern => (
          <div className="rule-row" key={pattern.id}>
            <div><strong>{pattern.phrase}</strong><span>Added by {pattern.created_by} · {new Date(pattern.created_at).toLocaleString()}</span></div>
            <button type="button" className={`rule-toggle${pattern.is_active ? ' enabled' : ''}`} onClick={() => togglePattern(pattern)} aria-label={`${pattern.is_active ? 'Disable' : 'Enable'} ${pattern.phrase}`}>
              {pattern.is_active ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}{pattern.is_active ? 'Blocking' : 'Disabled'}
            </button>
          </div>
        ))}
      </section>
    </div>
  );
}