import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { CustomThemeProvider } from './contexts/ThemeContext';
import { LoginForm } from './components/auth/LoginForm';
import { AppLayout } from './components/layout/AppLayout';
import { Dashboard } from './components/dashboard/Dashboard';
import { TokenList } from './components/tokens/TokenList';
import { ActivityList } from './components/activity/ActivityList';
import { UserList } from './components/users/UserList';
import { ApiKeyList } from './components/apikeys/ApiKeyList';
import { Settings } from './components/settings/Settings';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { PasswordChangeDialog } from './components/auth/PasswordChangeDialog';

function App() {
  console.log('App component is rendering');
  return (
    <CustomThemeProvider>
      <AuthProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<LoginForm />} />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Dashboard />} />
              <Route path="tokens" element={<TokenList />} />
              <Route path="activity" element={<ActivityList />} />
              <Route path="users" element={<UserList />} />
              <Route path="api-keys" element={<ApiKeyList />} />
              <Route path="settings" element={<Settings />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <PasswordChangeDialog />
        </Router>
      </AuthProvider>
    </CustomThemeProvider>
  );
}

export default App;
