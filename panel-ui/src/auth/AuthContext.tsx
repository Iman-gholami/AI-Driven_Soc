import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { setUnauthorizedHandler } from '../api/client';

const TOKEN_KEY = 'access_token';
const USER_KEY = 'soc_auth_user';
const EXPIRES_KEY = 'soc_auth_expires_at';

export interface AuthUser {
  username: string;
  displayName: string;
  role: string;
}

interface LoginInput {
  username: string;
  password: string;
  otp?: string;
  remember?: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (input: LoginInput) => Promise<AuthUser>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readStoredUser(): AuthUser | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function readStoredToken() {
  const token = localStorage.getItem(TOKEN_KEY);
  const expiresAt = localStorage.getItem(EXPIRES_KEY);
  if (!token) return null;
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    clearStoredSession();
    return null;
  }
  return token;
}

function clearStoredSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(EXPIRES_KEY);
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => readStoredToken());
  const [user, setUser] = useState<AuthUser | null>(() => (readStoredToken() ? readStoredUser() : null));

  const login = useCallback(async (input: LoginInput) => {
    const response = await axios.post(
      `${import.meta.env.VITE_API_URL || ''}/auth/login`,
      input,
      { timeout: 15000 },
    );
    const payload = response.data?.data || response.data;
    const nextToken = String(payload?.token || '');
    const nextUser = payload?.user as AuthUser;
    if (!nextToken || !nextUser?.username) throw new Error('Invalid authentication response');

    localStorage.setItem(TOKEN_KEY, nextToken);
    localStorage.setItem(USER_KEY, JSON.stringify(nextUser));
    if (payload.expiresAt) localStorage.setItem(EXPIRES_KEY, payload.expiresAt);
    setToken(nextToken);
    setUser(nextUser);
    return nextUser;
  }, []);

  const logout = useCallback(async () => {
    const currentToken = token;
    clearStoredSession();
    setToken(null);
    setUser(null);

    if (currentToken) {
      await axios.post(
        `${import.meta.env.VITE_API_URL || ''}/auth/logout`,
        {},
        { headers: { Authorization: `Bearer ${currentToken}` }, timeout: 5000 },
      ).catch(() => undefined);
    }
  }, [token]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearStoredSession();
      setToken(null);
      setUser(null);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    token,
    isAuthenticated: Boolean(token && user),
    login,
    logout,
  }), [token, user, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}

export const RequireAuth: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <Outlet />;
};
