import { createContext, useContext, useState, useEffect, useRef } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

// Set auth header immediately from localStorage before any component mounts
const _storedToken = localStorage.getItem('hp_token');
if (_storedToken) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${_storedToken}`;
}

// Global axios interceptor: on 401, clear stale token so ProtectedLayout redirects to login
axios.interceptors.response.use(
  res => res,
  err => {
    if (err.response?.status === 401) {
      const url = err.config?.url || '';
      // Only clear session for auth/me — not for every 401 (e.g. wrong endpoint)
      if (url.includes('/api/auth/me')) {
        localStorage.removeItem('hp_token');
        localStorage.removeItem('hp_user');
        delete axios.defaults.headers.common['Authorization'];
      } else {
        // For non-auth/me 401s, re-apply the token from localStorage in case the
        // default header was accidentally cleared (e.g. by a concurrent auth/me failure)
        const token = localStorage.getItem('hp_token');
        if (token) {
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        }
      }
    }
    return Promise.reject(err);
  }
);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(() => Boolean(localStorage.getItem('hp_token')));
  const refreshRef = useRef(null);

  const _scheduleRefresh = (token) => {
    if (refreshRef.current) clearInterval(refreshRef.current);
    // Re-validate session every 4 minutes to keep it alive
    refreshRef.current = setInterval(() => {
      axios.get('http://127.0.0.1:8000/api/auth/me')
        .then(({ data }) => {
          localStorage.setItem('hp_user', JSON.stringify(data));
          setUser(data);
        })
        .catch(() => {
          clearInterval(refreshRef.current);
          localStorage.removeItem('hp_token');
          localStorage.removeItem('hp_user');
          delete axios.defaults.headers.common['Authorization'];
          setUser(null);
        });
    }, 4 * 60 * 1000);
  };

  useEffect(() => {
    const token = localStorage.getItem('hp_token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      axios.get('http://127.0.0.1:8000/api/auth/me')
        .then(({ data }) => {
          localStorage.setItem('hp_user', JSON.stringify(data));
          setUser(data);
          _scheduleRefresh(token);
        })
        .catch(() => {
          localStorage.removeItem('hp_token');
          localStorage.removeItem('hp_user');
          delete axios.defaults.headers.common['Authorization'];
          setUser(null);
        })
        .finally(() => setLoading(false));
      return;
    }
    localStorage.removeItem('hp_user');
    setLoading(false);
  }, []);

  useEffect(() => () => { if (refreshRef.current) clearInterval(refreshRef.current); }, []);

  const login = async (username, password) => {
    const res = await axios.post('http://127.0.0.1:8000/api/auth/login', { username, password });
    const { token, user: u } = res.data;
    localStorage.setItem('hp_token', token);
    localStorage.setItem('hp_user', JSON.stringify(u));
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setUser(u);
    _scheduleRefresh(token);
    return u;
  };

  const signup = async (full_name, username, email, password) => {
    const res = await axios.post('http://127.0.0.1:8000/api/auth/signup', { full_name, username, email, password });
    const { token, user: u } = res.data;
    localStorage.setItem('hp_token', token);
    localStorage.setItem('hp_user', JSON.stringify(u));
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setUser(u);
    return u;
  };

  const logout = async () => {
    await axios.post('http://127.0.0.1:8000/api/auth/logout').catch(() => null);
    localStorage.removeItem('hp_token');
    localStorage.removeItem('hp_user');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
