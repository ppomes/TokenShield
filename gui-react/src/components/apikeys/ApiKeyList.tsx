import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  IconButton,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  TextField,
  Chip,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Snackbar,
} from '@mui/material';
import {
  Add as AddIcon,
  Refresh as RefreshIcon,
  Block as BlockIcon,
  ContentCopy as CopyIcon,
  Key as KeyIcon,
} from '@mui/icons-material';
import { DataGrid, type GridColDef, type GridRenderCellParams } from '@mui/x-data-grid';
import { api } from '../../services/api';
import type { ApiKey } from '../../types';

export function ApiKeyList() {
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [keyToRevoke, setKeyToRevoke] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newKeyDialog, setNewKeyDialog] = useState(false);
  const [newKey, setNewKey] = useState<ApiKey | null>(null);
  const [copySnackbar, setCopySnackbar] = useState(false);
  
  // Form state for new API key
  const [newApiKey, setNewApiKey] = useState({
    client_name: '',
    permissions: {
      read: true,
      write: false,
      admin: false,
    },
  });

  const loadApiKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getApiKeys();
      setApiKeys(result.api_keys);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApiKeys();
  }, []);

  const handleRevokeClick = (apiKey: string) => {
    setKeyToRevoke(apiKey);
    setRevokeDialogOpen(true);
  };

  const handleRevokeConfirm = async () => {
    if (!keyToRevoke) return;

    try {
      await api.revokeApiKey(keyToRevoke);
      setRevokeDialogOpen(false);
      setKeyToRevoke(null);
      loadApiKeys();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to revoke API key');
    }
  };

  const handleCreateApiKey = async () => {
    try {
      const permissions = Object.keys(newApiKey.permissions)
        .filter(key => newApiKey.permissions[key as keyof typeof newApiKey.permissions]);
      
      const result = await api.createApiKey(newApiKey.client_name, permissions);
      setNewKey(result);
      setCreateDialogOpen(false);
      setNewKeyDialog(true);
      setNewApiKey({
        client_name: '',
        permissions: {
          read: true,
          write: false,
          admin: false,
        },
      });
      loadApiKeys();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to create API key');
    }
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopySnackbar(true);
  };

  const formatPermissions = (permissions: string[]) => {
    return permissions.map(p => (
      <Chip
        key={p}
        label={p}
        size="small"
        color={p === 'admin' ? 'error' : p === 'write' ? 'primary' : 'default'}
        sx={{ mr: 0.5 }}
      />
    ));
  };

  const columns: GridColDef[] = [
    {
      field: 'api_key',
      headerName: 'API Key',
      width: 300,
      renderCell: (params: GridRenderCellParams) => (
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <code style={{ fontSize: '0.875rem' }}>
            {params.value.substring(0, 8)}...{params.value.substring(params.value.length - 4)}
          </code>
          <IconButton
            size="small"
            onClick={() => handleCopyKey(params.value)}
            sx={{ ml: 1 }}
          >
            <CopyIcon fontSize="small" />
          </IconButton>
        </Box>
      ),
    },
    {
      field: 'client_name',
      headerName: 'Client Name',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'permissions',
      headerName: 'Permissions',
      width: 250,
      renderCell: (params) => (
        <Box sx={{ display: 'flex' }}>
          {formatPermissions(params.value)}
        </Box>
      ),
    },
    {
      field: 'is_active',
      headerName: 'Status',
      width: 100,
      renderCell: (params: GridRenderCellParams) => (
        <Chip
          label={params.value ? 'Active' : 'Revoked'}
          color={params.value ? 'success' : 'default'}
          size="small"
        />
      ),
    },
    {
      field: 'created_at',
      headerName: 'Created',
      width: 180,
      valueFormatter: (value: string) => {
        return new Date(value).toLocaleString();
      },
    },
    {
      field: 'last_used_at',
      headerName: 'Last Used',
      width: 180,
      valueFormatter: (value: string | null) => {
        return value ? new Date(value).toLocaleString() : 'Never';
      },
    },
    {
      field: 'actions',
      headerName: 'Actions',
      width: 100,
      sortable: false,
      renderCell: (params: GridRenderCellParams) => (
        <Box>
          {params.row.is_active && (
            <IconButton
              size="small"
              onClick={() => handleRevokeClick(params.row.api_key)}
              color="error"
            >
              <BlockIcon />
            </IconButton>
          )}
        </Box>
      ),
    },
  ];

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          API Keys
        </Typography>
        <Box>
          <IconButton onClick={loadApiKeys} disabled={loading} sx={{ mr: 1 }}>
            <RefreshIcon />
          </IconButton>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Create API Key
          </Button>
        </Box>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ height: 600, width: '100%' }}>
        <DataGrid
          rows={apiKeys}
          columns={columns}
          loading={loading}
          pageSizeOptions={[25, 50, 100]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 25 },
            },
          }}
          getRowId={(row) => row.api_key}
          disableRowSelectionOnClick
        />
      </Paper>

      {/* Create API Key Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create API Key</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 2 }}>
            <TextField
              label="Client Name"
              value={newApiKey.client_name}
              onChange={(e) => setNewApiKey({ ...newApiKey, client_name: e.target.value })}
              fullWidth
              required
              helperText="A descriptive name for this API key"
            />
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Permissions
              </Typography>
              <FormGroup>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newApiKey.permissions.read}
                      onChange={(e) => setNewApiKey({
                        ...newApiKey,
                        permissions: { ...newApiKey.permissions, read: e.target.checked }
                      })}
                    />
                  }
                  label="Read - View tokens and statistics"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newApiKey.permissions.write}
                      onChange={(e) => setNewApiKey({
                        ...newApiKey,
                        permissions: { ...newApiKey.permissions, write: e.target.checked }
                      })}
                    />
                  }
                  label="Write - Create and revoke tokens"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newApiKey.permissions.admin}
                      onChange={(e) => setNewApiKey({
                        ...newApiKey,
                        permissions: { ...newApiKey.permissions, admin: e.target.checked }
                      })}
                    />
                  }
                  label="Admin - Manage users and API keys"
                />
              </FormGroup>
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleCreateApiKey} 
            variant="contained"
            disabled={!newApiKey.client_name || (!newApiKey.permissions.read && !newApiKey.permissions.write && !newApiKey.permissions.admin)}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* New API Key Display Dialog */}
      <Dialog
        open={newKeyDialog}
        onClose={() => setNewKeyDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <KeyIcon sx={{ mr: 1 }} />
            API Key Created
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Please copy this API key now. You won't be able to see it again!
          </Alert>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TextField
              fullWidth
              value={newKey?.api_key || ''}
              InputProps={{
                readOnly: true,
                sx: { fontFamily: 'monospace' }
              }}
            />
            <IconButton onClick={() => handleCopyKey(newKey?.api_key || '')}>
              <CopyIcon />
            </IconButton>
          </Box>
          <Box sx={{ mt: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Client Name: <strong>{newKey?.client_name}</strong>
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Permissions: {newKey?.permissions.join(', ')}
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewKeyDialog(false)} variant="contained">
            Done
          </Button>
        </DialogActions>
      </Dialog>

      {/* Revoke API Key Dialog */}
      <Dialog
        open={revokeDialogOpen}
        onClose={() => setRevokeDialogOpen(false)}
      >
        <DialogTitle>Revoke API Key</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to revoke this API key? This action cannot be undone.
            <br /><br />
            API Key: <strong>{keyToRevoke?.substring(0, 8)}...{keyToRevoke?.substring(keyToRevoke.length - 4)}</strong>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevokeDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleRevokeConfirm} color="error" variant="contained">
            Revoke
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={copySnackbar}
        autoHideDuration={2000}
        onClose={() => setCopySnackbar(false)}
        message="API key copied to clipboard"
      />
    </Box>
  );
}