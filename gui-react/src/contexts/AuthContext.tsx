import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { User, Session } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  requirePasswordChange: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [requirePasswordChange, setRequirePasswordChange] = useState(false);

  const refreshUser = async () => {
    try {
      if (api.isAuthenticated()) {
        const userData = await api.getCurrentUser();
        setUser(userData);
      }
    } catch (err) {
      setUser(null);
    }
  };

  useEffect(() => {
    const checkAuth = async () => {
      console.log('AuthContext: Checking authentication on startup');
      try {
        console.log('AuthContext: isAuthenticated =', api.isAuthenticated());
        if (api.isAuthenticated()) {
          await refreshUser();
        }
      } catch (err) {
        console.error('AuthContext: Error during auth check:', err);
      } finally {
        console.log('AuthContext: Auth check complete, setting loading to false');
        setLoading(false);
      }
    };
    checkAuth();
  }, []);

  const login = async (username: string, password: string) => {
    try {
      setError(null);
      const session: Session = await api.login(username, password);
      setUser(session.user);
      setRequirePasswordChange(session.require_password_change);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Login failed');
      throw err;
    }
  };

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setUser(null);
      setRequirePasswordChange(false);
    }
  };

  const changePassword = async (currentPassword: string, newPassword: string) => {
    await api.changePassword(currentPassword, newPassword);
    setRequirePasswordChange(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        requirePasswordChange,
        login,
        logout,
        changePassword,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}