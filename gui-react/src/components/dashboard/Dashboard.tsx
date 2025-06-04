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
import type { Stats, SystemInfo } from '../../types';

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
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadDashboardData = async () => {
      try {
        const [statsData, versionData] = await Promise.all([
          api.getStats(),
          api.getVersion()
        ]);
        setStats(statsData);
        setSystemInfo(versionData);
      } catch (err: any) {
        setError(err.response?.data?.error || 'Failed to load dashboard data');
      } finally {
        setLoading(false);
      }
    };

    loadDashboardData();
    const interval = setInterval(loadDashboardData, 30000); // Refresh every 30 seconds

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

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Request Distribution (24 hours)
          </Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr', gap: 2, mt: 2 }}>
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

        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            System Information
          </Typography>
          {systemInfo ? (
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr', gap: 2, mt: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  Version
                </Typography>
                <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                  {systemInfo.version}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  Token Format
                </Typography>
                <Typography variant="body1">
                  {systemInfo.token_format}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  KEK/DEK Enabled
                </Typography>
                <Typography variant="body1">
                  {systemInfo.kek_dek_enabled ? 'Yes' : 'No'}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  Features
                </Typography>
                <Typography variant="body1" sx={{ textAlign: 'right', wordBreak: 'break-word' }}>
                  {systemInfo.features.join(', ')}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  API Status
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box
                    sx={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      bgcolor: 'success.main',
                      mr: 1,
                    }}
                  />
                  <Typography variant="body1" color="success.main">
                    Active
                  </Typography>
                </Box>
              </Box>
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Loading system information...
            </Typography>
          )}
        </Paper>
      </Box>
    </Box>
  );
}