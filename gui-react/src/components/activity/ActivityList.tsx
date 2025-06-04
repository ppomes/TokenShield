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
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Chip,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';
import { DataGrid, type GridColDef } from '@mui/x-data-grid';
import { api } from '../../services/api';
import type { Activity } from '../../types';

export function ActivityList() {
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(50);
  const [filterType, setFilterType] = useState('');
  const [filterIP, setFilterIP] = useState('');

  const loadActivities = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.getActivity(limit);
      let filtered = result.activities;
      
      // Client-side filtering since API doesn't support it yet
      if (filterType) {
        filtered = filtered.filter(a => a.type === filterType);
      }
      if (filterIP) {
        filtered = filtered.filter(a => a.source_ip.includes(filterIP));
      }
      
      setActivities(filtered);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to load activities');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadActivities();
  }, [limit]);

  const handleFilter = () => {
    loadActivities();
  };

  const getRequestTypeChip = (type: string) => {
    const chipProps: any = {
      label: type.charAt(0).toUpperCase() + type.slice(1),
      size: 'small',
    };
    
    switch (type) {
      case 'tokenize':
        chipProps.color = 'primary';
        break;
      case 'detokenize':
        chipProps.color = 'secondary';
        break;
      case 'search':
        chipProps.color = 'info';
        break;
      default:
        chipProps.color = 'default';
    }
    
    return <Chip {...chipProps} />;
  };

  const columns: GridColDef[] = [
    {
      field: 'timestamp',
      headerName: 'Timestamp',
      width: 180,
      valueFormatter: (value: string) => {
        return new Date(value).toLocaleString();
      },
    },
    {
      field: 'type',
      headerName: 'Type',
      width: 140,
      renderCell: (params) => getRequestTypeChip(params.value),
    },
    {
      field: 'source_ip',
      headerName: 'Source IP',
      width: 150,
    },
    {
      field: 'token',
      headerName: 'Token',
      flex: 1,
      minWidth: 200,
      renderCell: (params) => (
        <code style={{ fontSize: '0.875rem' }}>
          {params.value?.substring(0, 8)}...{params.value?.substring(params.value.length - 4)}
        </code>
      ),
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 100,
      renderCell: (params) => (
        params.value ? (
          <Chip
            label={params.value}
            color={params.value < 400 ? 'success' : 'error'}
            size="small"
          />
        ) : null
      ),
    },
    {
      field: 'destination',
      headerName: 'Destination',
      width: 150,
    },
  ];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Activity Log
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Filter Activity
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Request Type</InputLabel>
            <Select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              label="Request Type"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="tokenize">Tokenize</MenuItem>
              <MenuItem value="detokenize">Detokenize</MenuItem>
              <MenuItem value="search">Search</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Source IP"
            value={filterIP}
            onChange={(e) => setFilterIP(e.target.value)}
            size="small"
            sx={{ minWidth: 150 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <FilterIcon />
                </InputAdornment>
              ),
            }}
          />
          <FormControl size="small" sx={{ minWidth: 100 }}>
            <InputLabel>Limit</InputLabel>
            <Select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              label="Limit"
            >
              <MenuItem value={25}>25</MenuItem>
              <MenuItem value={50}>50</MenuItem>
              <MenuItem value={100}>100</MenuItem>
              <MenuItem value={250}>250</MenuItem>
            </Select>
          </FormControl>
          <Button
            variant="contained"
            onClick={handleFilter}
            startIcon={<SearchIcon />}
          >
            Apply Filter
          </Button>
          <Button
            variant="outlined"
            onClick={() => {
              setFilterType('');
              setFilterIP('');
              loadActivities();
            }}
          >
            Clear
          </Button>
          <Box sx={{ flexGrow: 1 }} />
          <IconButton onClick={loadActivities} disabled={loading}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ height: 600, width: '100%' }}>
        <DataGrid
          rows={activities}
          columns={columns}
          loading={loading}
          pageSizeOptions={[25, 50, 100]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 25 },
            },
          }}
          getRowId={(row) => `${row.timestamp}-${row.token}-${row.source_ip}`}
          disableRowSelectionOnClick
        />
      </Paper>
    </Box>
  );
}