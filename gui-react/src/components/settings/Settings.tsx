import { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  Divider,
  FormGroup,
  FormControlLabel,
  Switch,
  Card,
  CardContent,
  Chip,
  RadioGroup,
  Radio,
  FormControl,
  FormLabel,
} from '@mui/material';
import {
  Save as SaveIcon,
  Security as SecurityIcon,
  Person as PersonIcon,
  VpnKey as VpnKeyIcon,
  Palette as PaletteIcon,
  DarkMode,
  LightMode,
  SettingsBrightness,
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';
import { useTheme } from '../../contexts/ThemeContext';
import { api } from '../../services/api';
import { ApiConfiguration } from './ApiConfiguration';

export function Settings() {
  const { user } = useAuth();
  const { mode, setTheme } = useTheme();
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Password change form
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  
  // Profile form
  const [profileForm, setProfileForm] = useState({
    email: user?.email || '',
    full_name: user?.full_name || '',
  });
  
  // Security settings
  const [securitySettings, setSecuritySettings] = useState({
    twoFactorEnabled: false, // Not implemented yet
    sessionTimeout: 24, // hours
  });

  const handlePasswordChange = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setError('New passwords do not match');
      return;
    }
    
    if (passwordForm.newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }
    
    try {
      await api.changePassword(passwordForm.currentPassword, passwordForm.newPassword);
      setSuccess('Password changed successfully');
      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      });
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to change password');
      setSuccess(null);
    }
  };

  const handleProfileUpdate = async () => {
    // Note: API doesn't support profile updates yet
    setError('Profile updates are not implemented yet');
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Theme Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <PaletteIcon sx={{ mr: 1 }} />
            <Typography variant="h6">Appearance</Typography>
          </Box>
          <FormControl component="fieldset">
            <FormLabel component="legend" sx={{ mb: 2 }}>Theme Mode</FormLabel>
            <RadioGroup
              value={mode}
              onChange={(e) => setTheme(e.target.value as 'light' | 'dark')}
              sx={{
                '& .MuiFormControlLabel-root': {
                  mb: 1,
                  mr: 3,
                },
              }}
            >
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <FormControlLabel
                  value="light"
                  control={<Radio />}
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <LightMode sx={{ mr: 1, fontSize: '1.2rem' }} />
                      <Box>
                        <Typography variant="body1">Light Mode</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Clean and bright interface for better readability in well-lit environments
                        </Typography>
                      </Box>
                    </Box>
                  }
                />
                <FormControlLabel
                  value="dark"
                  control={<Radio />}
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <DarkMode sx={{ mr: 1, fontSize: '1.2rem' }} />
                      <Box>
                        <Typography variant="body1">Dark Mode</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Reduced eye strain with a dark theme, perfect for low-light conditions
                        </Typography>
                      </Box>
                    </Box>
                  }
                />
              </Box>
            </RadioGroup>
          </FormControl>
          <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
              <SettingsBrightness sx={{ mr: 1, fontSize: '1rem', color: 'text.secondary' }} />
              <Typography variant="body2" color="text.secondary" fontWeight={500}>
                Smart Theme Detection
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary">
              Your theme preference is automatically saved and will persist across sessions. 
              The system will also respect your operating system's theme preference when you first visit.
            </Typography>
          </Box>
        </CardContent>
      </Card>

      {/* User Profile */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <PersonIcon sx={{ mr: 1 }} />
            <Typography variant="h6">User Profile</Typography>
          </Box>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mb: 2 }}>
            <Box>
              <Typography variant="body2" color="text.secondary">Username</Typography>
              <Typography variant="body1">{user?.username}</Typography>
            </Box>
            <Box>
              <Typography variant="body2" color="text.secondary">Role</Typography>
              <Chip label={user?.role} size="small" color={user?.role === 'admin' ? 'error' : 'primary'} />
            </Box>
            <Box>
              <Typography variant="body2" color="text.secondary">Created</Typography>
              <Typography variant="body1">
                {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
              </Typography>
            </Box>
            <Box>
              <Typography variant="body2" color="text.secondary">Last Login</Typography>
              <Typography variant="body1">
                {user?.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'N/A'}
              </Typography>
            </Box>
          </Box>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <TextField
              label="Email"
              value={profileForm.email}
              onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })}
              fullWidth
              disabled
            />
            <TextField
              label="Full Name"
              value={profileForm.full_name}
              onChange={(e) => setProfileForm({ ...profileForm, full_name: e.target.value })}
              fullWidth
              disabled
            />
          </Box>
          <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleProfileUpdate}
              disabled
            >
              Update Profile
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Change Password */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <VpnKeyIcon sx={{ mr: 1 }} />
            <Typography variant="h6">Change Password</Typography>
          </Box>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Current Password"
              type="password"
              value={passwordForm.currentPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
              fullWidth
            />
            <TextField
              label="New Password"
              type="password"
              value={passwordForm.newPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
              fullWidth
              helperText="Minimum 8 characters"
            />
            <TextField
              label="Confirm New Password"
              type="password"
              value={passwordForm.confirmPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
              fullWidth
            />
          </Box>
          <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handlePasswordChange}
              disabled={!passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}
            >
              Change Password
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* Security Settings */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <SecurityIcon sx={{ mr: 1 }} />
            <Typography variant="h6">Security Settings</Typography>
          </Box>
          <FormGroup>
            <FormControlLabel
              control={
                <Switch
                  checked={securitySettings.twoFactorEnabled}
                  onChange={(e) => setSecuritySettings({
                    ...securitySettings,
                    twoFactorEnabled: e.target.checked
                  })}
                  disabled
                />
              }
              label="Two-Factor Authentication"
            />
            <Typography variant="body2" color="text.secondary" sx={{ ml: 4, mb: 2 }}>
              Two-factor authentication is not implemented yet
            </Typography>
          </FormGroup>
          <TextField
            label="Session Timeout (hours)"
            type="number"
            value={securitySettings.sessionTimeout}
            onChange={(e) => setSecuritySettings({
              ...securitySettings,
              sessionTimeout: parseInt(e.target.value) || 24
            })}
            sx={{ mt: 2 }}
            disabled
            helperText="Session timeout configuration is not implemented yet"
          />
        </CardContent>
      </Card>

      {/* API Configuration */}
      <ApiConfiguration />

      {/* System Information */}
      <Paper sx={{ p: 3, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          System Information
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
          <Box>
            <Typography variant="body2" color="text.secondary">TokenShield Version</Typography>
            <Typography variant="body1">1.0.0</Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">API Endpoint</Typography>
            <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
              {import.meta.env.VITE_API_URL || '/api/v1'}
            </Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">Environment</Typography>
            <Typography variant="body1">{import.meta.env.MODE}</Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">React GUI Version</Typography>
            <Typography variant="body1">0.0.0</Typography>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
}