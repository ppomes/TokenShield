import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Alert,
  Box,
  Typography,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Check as CheckIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { useAuth } from '../../contexts/AuthContext';

export function PasswordChangeDialog() {
  const { requirePasswordChange, changePassword } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const passwordRequirements = [
    { regex: /.{12,}/, text: 'At least 12 characters' },
    { regex: /[A-Z]/, text: 'At least one uppercase letter' },
    { regex: /[a-z]/, text: 'At least one lowercase letter' },
    { regex: /[0-9]/, text: 'At least one digit' },
    { regex: /[!@#$%^&*(),.?":{}|<>]/, text: 'At least one special character' },
  ];

  const validatePassword = (password: string) => {
    return passwordRequirements.every((req) => req.regex.test(password));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (!validatePassword(newPassword)) {
      setError('Password does not meet requirements');
      return;
    }

    setLoading(true);
    try {
      await changePassword(currentPassword, newPassword);
      // Dialog will close automatically when requirePasswordChange becomes false
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      open={requirePasswordChange}
      onClose={() => {}}
      disableEscapeKeyDown
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Change Password Required</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>
          You must change your password before continuing.
        </Alert>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={handleSubmit}>
          <TextField
            fullWidth
            margin="normal"
            label="Current Password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            required
          />
          <TextField
            fullWidth
            margin="normal"
            label="New Password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
          <TextField
            fullWidth
            margin="normal"
            label="Confirm New Password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />

          <Typography variant="body2" sx={{ mt: 2, mb: 1 }}>
            Password Requirements:
          </Typography>
          <List dense>
            {passwordRequirements.map((req, index) => {
              const isValid = req.regex.test(newPassword);
              return (
                <ListItem key={index}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    {isValid ? (
                      <CheckIcon color="success" fontSize="small" />
                    ) : (
                      <CloseIcon color="error" fontSize="small" />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={req.text}
                    primaryTypographyProps={{
                      variant: 'body2',
                      color: isValid ? 'text.primary' : 'text.secondary',
                    }}
                  />
                </ListItem>
              );
            })}
          </List>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button
          type="submit"
          variant="contained"
          onClick={handleSubmit}
          disabled={loading || !currentPassword || !newPassword || !confirmPassword}
        >
          Change Password
        </Button>
      </DialogActions>
    </Dialog>
  );
}