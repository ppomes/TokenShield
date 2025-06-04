import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  IconButton,
  InputAdornment,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Chip,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  Block as BlockIcon,
} from '@mui/icons-material';
import { DataGrid, type GridColDef, type GridRenderCellParams } from '@mui/x-data-grid';
import { api } from '../../services/api';
import type { Token } from '../../types';
import { useAuth } from '../../contexts/AuthContext';

export function TokenList() {
  const [tokens, setTokens] = useState<Token[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchLastFour, setSearchLastFour] = useState('');
  const [searchCardType, setSearchCardType] = useState('');
  const [searchActive, setSearchActive] = useState<boolean | ''>('');
  const [paginationModel, setPaginationModel] = useState({
    page: 0,
    pageSize: 25,
  });
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [tokenToRevoke, setTokenToRevoke] = useState<string | null>(null);
  const { user } = useAuth();

  const canRevoke = user?.role === 'admin' || user?.role === 'operator';

  const loadTokens = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: any = {
        limit: paginationModel.pageSize,
        offset: paginationModel.page * paginationModel.pageSize,
      };

      if (searchLastFour || searchCardType || searchActive !== '') {
        params.lastFour = searchLastFour;
        params.cardType = searchCardType;
        if (searchActive !== '') params.active = searchActive;
        
        const result = await api.searchTokens(params);
        setTokens(result.tokens);
        setTotal(result.total);
      } else {
        const result = await api.getTokens(params.limit, params.offset);
        setTokens(result.tokens);
        setTotal(result.total);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load tokens');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTokens();
  }, [paginationModel]);

  const handleSearch = () => {
    setPaginationModel({ ...paginationModel, page: 0 });
    loadTokens();
  };

  const handleRevokeClick = (token: string) => {
    setTokenToRevoke(token);
    setRevokeDialogOpen(true);
  };

  const handleRevokeConfirm = async () => {
    if (!tokenToRevoke) return;

    try {
      await api.revokeToken(tokenToRevoke);
      setRevokeDialogOpen(false);
      setTokenToRevoke(null);
      loadTokens();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to revoke token');
    }
  };

  const columns: GridColDef[] = [
    {
      field: 'token',
      headerName: 'Token',
      flex: 1,
      minWidth: 200,
    },
    {
      field: 'card_type',
      headerName: 'Card Type',
      width: 120,
    },
    {
      field: 'last_four',
      headerName: 'Last 4',
      width: 100,
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
      field: 'actions',
      headerName: 'Actions',
      width: 100,
      sortable: false,
      renderCell: (params: GridRenderCellParams) => (
        <Box>
          {params.row.is_active && canRevoke && (
            <IconButton
              size="small"
              onClick={() => handleRevokeClick(params.row.token)}
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
      <Typography variant="h4" gutterBottom>
        Tokens
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Search Tokens
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <TextField
            label="Last 4 Digits"
            value={searchLastFour}
            onChange={(e) => setSearchLastFour(e.target.value)}
            size="small"
            sx={{ minWidth: 150 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Card Type</InputLabel>
            <Select
              value={searchCardType}
              onChange={(e) => setSearchCardType(e.target.value)}
              label="Card Type"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="Visa">Visa</MenuItem>
              <MenuItem value="Mastercard">Mastercard</MenuItem>
              <MenuItem value="American Express">American Express</MenuItem>
              <MenuItem value="Discover">Discover</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={searchActive}
              onChange={(e) => setSearchActive(e.target.value as boolean | '')}
              label="Status"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value={true as any}>Active</MenuItem>
              <MenuItem value={false as any}>Revoked</MenuItem>
            </Select>
          </FormControl>
          <Button
            variant="contained"
            onClick={handleSearch}
            startIcon={<SearchIcon />}
          >
            Search
          </Button>
          <Button
            variant="outlined"
            onClick={() => {
              setSearchLastFour('');
              setSearchCardType('');
              setSearchActive('');
              loadTokens();
            }}
          >
            Clear
          </Button>
          <Box sx={{ flexGrow: 1 }} />
          <IconButton onClick={loadTokens} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ height: 600, width: '100%' }}>
        <DataGrid
          rows={tokens}
          columns={columns}
          rowCount={total}
          loading={loading}
          pageSizeOptions={[25, 50, 100]}
          paginationModel={paginationModel}
          paginationMode="server"
          onPaginationModelChange={setPaginationModel}
          getRowId={(row) => row.token}
          disableRowSelectionOnClick
        />
      </Paper>

      <Dialog
        open={revokeDialogOpen}
        onClose={() => setRevokeDialogOpen(false)}
      >
        <DialogTitle>Revoke Token</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to revoke this token? This action cannot be undone.
            <br />
            <br />
            Token: <strong>{tokenToRevoke}</strong>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevokeDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleRevokeConfirm} color="error" variant="contained">
            Revoke
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}