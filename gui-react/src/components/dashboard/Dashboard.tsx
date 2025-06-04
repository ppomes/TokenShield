import React, { useEffect, useState } from 'react';
import {
  Paper,
  Typography,
  Box,
  Card,
  CardContent,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  Token as TokenIcon,
  TrendingUp,
  Search,
  SwapHoriz,
} from '@mui/icons-material';
import { api } from '../../services/api';
import type { Stats } from '../../types';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactElement;
  color: string;
}

function StatCard({ title, value, icon, color }: StatCardProps) {
  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 48,
              height: 48,
              borderRadius: 1,
              bgcolor: `${color}.100`,
              color: `${color}.main`,
              mr: 2,
            }}
          >
            {icon}
          </Box>
          <Box sx={{ flexGrow: 1 }}>
            <Typography color="text.secondary" variant="body2">
              {title}
            </Typography>
            <Typography variant="h4" component="div">
              {value}
            </Typography>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

export function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await api.getStats();
        setStats(data);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load statistics');
      } finally {
        setLoading(false);
      }
    };

    loadStats();
    const interval = setInterval(loadStats, 30000); // Refresh every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  const totalRequests = stats
    ? Object.values(stats.requests_24h || {}).reduce((sum, count) => sum + count, 0)
    : 0;
    
  const getRequestCount = (type: string) => {
    return stats?.requests_24h?.[type] || 0;
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        System overview and statistics
      </Typography>

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: '1fr 1fr 1fr 1fr' }, gap: 3, mb: 3 }}>
        <StatCard
          title="Active Tokens"
          value={stats?.active_tokens || 0}
          icon={<TokenIcon />}
          color="primary"
        />
        <StatCard
          title="Total Requests (24h)"
          value={totalRequests}
          icon={<TrendingUp />}
          color="success"
        />
        <StatCard
          title="Tokenizations (24h)"
          value={getRequestCount('tokenize')}
          icon={<SwapHoriz />}
          color="info"
        />
        <StatCard
          title="Searches (24h)"
          value={getRequestCount('search')}
          icon={<Search />}
          color="warning"
        />
      </Box>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Request Distribution (24 hours)
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1fr' }, gap: 3, mt: 2 }}>
          <Box>
            <Typography variant="body2" color="text.secondary">
              Tokenization Requests
            </Typography>
            <Typography variant="h5">
              {getRequestCount('tokenize')}
            </Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">
              Detokenization Requests
            </Typography>
            <Typography variant="h5">
              {getRequestCount('detokenize')}
            </Typography>
          </Box>
          <Box>
            <Typography variant="body2" color="text.secondary">
              Search Requests
            </Typography>
            <Typography variant="h5">
              {getRequestCount('search')}
            </Typography>
          </Box>
        </Box>
      </Paper>
    </Box>
  );
}