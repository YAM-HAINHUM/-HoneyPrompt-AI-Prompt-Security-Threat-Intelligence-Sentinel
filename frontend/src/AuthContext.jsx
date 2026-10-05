import { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(() => Boolean(localStorage.getItem('hp_token')));

  useEffect(() => {
    const token = localStorage.getItem('hp_token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      axios.get('http://127.0.0.1:8000/api/auth/me')
        .then(({ data }) => {
          localStorage.setItem('hp_user', JSON.stringify(data));
          setUser(data);
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
  }, []);

  const login = async (username, password) => {
    const res = await axios.post('http://127.0.0.1:8000/api/auth/login', { username, password });
    const { token, user: u } = res.data;
    localStorage.setItem('hp_token', token);
    localStorage.setItem('hp_user', JSON.stringify(u));
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setUser(u);
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
