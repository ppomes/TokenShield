import { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';

export function ApiConfiguration() {
  const [apiUrl, setApiUrl] = useState('');
  const [defaultApiUrl, setDefaultApiUrl] = useState('');
  const [connectionStatus, setConnectionStatus] = useState<'unknown' | 'connected' | 'error'>('unknown');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
  
  useEffect(() => {
    // Get current API URL from the API service
    const currentUrl = api.getApiUrl();
    setApiUrl(currentUrl);
    
    // Determine default URL based on environment
    const defaultUrl = import.meta.env.VITE_API_URL || '/api/v1';
    setDefaultApiUrl(defaultUrl);
    
    // Test initial connection
    testConnection(currentUrl);
  }, []);

  const testConnection = async (urlToTest?: string) => {
    const testUrl = urlToTest || apiUrl;
    setConnectionStatus('unknown');
    setError(null);
    
    try {
      // Create a temporary API instance to test the connection
      const testApi = api.createTestInstance(testUrl);
      await testApi.getVersion(); // Test with a simple endpoint
      setConnectionStatus('connected');
    } catch (err: any) {
      setConnectionStatus('error');
      setError(`Connection failed: ${err.message || 'Unknown error'}`);
    }
  };

  const handleSave = () => {
    try {
      // Validate URL format
      if (apiUrl && !apiUrl.startsWith('/') && !apiUrl.startsWith('http')) {
        setError('API URL must start with http://, https://, or / for relative URLs');
        return;
      }
      
      // Update the API service configuration
      api.setApiUrl(apiUrl);
      
      // Store in localStorage like the legacy UI
      localStorage.setItem('tokenshield_api_url', apiUrl);
      
      setSuccess('API configuration saved successfully');
      setError(null);
      
      // Test the new connection
      testConnection();
      
      // Clear success message after 3 seconds
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(`Failed to save configuration: ${err.message}`);
    }
  };

  const handleReset = () => {
    setApiUrl(defaultApiUrl);
    localStorage.removeItem('tokenshield_api_url');
    setResetDialogOpen(false);
    setSuccess('Configuration reset to default');
    setTimeout(() => setSuccess(null), 3000);
  };

  const getStatusColor = () => {
    switch (connectionStatus) {
      case 'connected': return 'success';
      case 'error': return 'error';
      default: return 'warning';
    }
  };

  const getStatusText = () => {
    switch (connectionStatus) {
      case 'connected': return 'Connected';
      case 'error': return 'Connection Error';
      default: return 'Testing...';
    }
  };

  return (
    <Card sx={{ mt: 3 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <SettingsIcon sx={{ mr: 1 }} />
          <Typography variant="h6">API Configuration</Typography>
        </Box>
        
        <Typography variant="body2" color="text.secondary" paragraph>
          Configure the TokenShield API endpoint. You can use relative URLs (e.g., /api/v1) when using the built-in proxy,
          or absolute URLs (e.g., http://localhost:8090/api/v1) to connect directly to the API service.
        </Typography>

        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            {success}
          </Alert>
        )}
        
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            label="API URL"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            fullWidth
            placeholder="e.g., /api/v1 or http://localhost:8090/api/v1"
            helperText="Current API endpoint for TokenShield management API"
          />
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Alert 
              severity={getStatusColor()} 
              sx={{ flexGrow: 1 }}
              icon={connectionStatus === 'unknown' ? <RefreshIcon /> : undefined}
            >
              <strong>Connection Status:</strong> {getStatusText()}
            </Alert>
            <IconButton onClick={() => testConnection()} disabled={connectionStatus === 'unknown'}>
              <RefreshIcon />
            </IconButton>
          </Box>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              onClick={() => setResetDialogOpen(true)}
              disabled={apiUrl === defaultApiUrl}
            >
              Reset to Default
            </Button>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSave}
            >
              Save Configuration
            </Button>
          </Box>
        </Box>

        <Box sx={{ mt: 2, p: 2, bgcolor: 'background.default', borderRadius: 1 }}>
          <Typography variant="body2" color="text.secondary">
            <strong>Configuration Options:</strong>
          </Typography>
          <Typography variant="body2" color="text.secondary">
            • <strong>Relative URL</strong> (e.g., /api/v1): Uses nginx proxy built into this container
          </Typography>
          <Typography variant="body2" color="text.secondary">
            • <strong>Absolute URL</strong> (e.g., http://localhost:8090/api/v1): Direct connection to API service
          </Typography>
          <Typography variant="body2" color="text.secondary">
            • <strong>Default</strong>: {defaultApiUrl}
          </Typography>
        </Box>
      </CardContent>

      {/* Reset Confirmation Dialog */}
      <Dialog open={resetDialogOpen} onClose={() => setResetDialogOpen(false)}>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <WarningIcon sx={{ mr: 1, color: 'warning.main' }} />
            Reset API Configuration
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to reset the API configuration to the default value?
          </Typography>
          <Typography sx={{ mt: 1 }}>
            <strong>Current:</strong> {apiUrl}
          </Typography>
          <Typography>
            <strong>Default:</strong> {defaultApiUrl}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResetDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleReset} color="warning" variant="contained">
            Reset
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
}