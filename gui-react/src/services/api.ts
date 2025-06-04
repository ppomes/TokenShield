import axios, { type AxiosInstance, AxiosError } from 'axios';
import type { Session, Token, Activity, Stats, User, ApiKey, SystemInfo, ApiError } from '../types';

class TokenShieldAPI {
  private client: AxiosInstance;
  private sessionId: string | null = null;
  private currentApiUrl: string;

  constructor() {
    // Get API URL from localStorage (like legacy UI) or environment variable
    this.currentApiUrl = localStorage.getItem('tokenshield_api_url') || 
                        import.meta.env.VITE_API_URL || 
                        '/api/v1';
    
    this.client = axios.create({
      baseURL: this.currentApiUrl,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Load session from localStorage
    const stored = localStorage.getItem('tokenshield_session');
    if (stored) {
      const { sessionId, expiresAt } = JSON.parse(stored);
      if (new Date(expiresAt) > new Date()) {
        this.sessionId = sessionId;
      } else {
        localStorage.removeItem('tokenshield_session');
      }
    }

    // Add auth header to all requests
    this.client.interceptors.request.use((config) => {
      if (this.sessionId) {
        config.headers.Authorization = `Bearer ${this.sessionId}`;
      }
      return config;
    });

    // Handle auth errors
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ApiError>) => {
        if (error.response?.status === 401) {
          this.clearSession();
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  private saveSession(sessionId: string, expiresAt: string) {
    this.sessionId = sessionId;
    localStorage.setItem('tokenshield_session', JSON.stringify({ sessionId, expiresAt }));
  }

  private clearSession() {
    this.sessionId = null;
    localStorage.removeItem('tokenshield_session');
  }

  // Authentication
  async login(username: string, password: string): Promise<Session> {
    const { data } = await this.client.post<Session>('/auth/login', { username, password });
    this.saveSession(data.session_id, data.expires_at);
    return data;
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } finally {
      this.clearSession();
    }
  }

  async getCurrentUser(): Promise<User> {
    const { data } = await this.client.get<User>('/auth/me');
    return data;
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.client.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  // Tokens
  async getTokens(limit = 100, offset = 0): Promise<{ tokens: Token[]; total: number }> {
    const { data } = await this.client.get('/tokens', { params: { limit, offset } });
    return data;
  }

  async searchTokens(params: {
    lastFour?: string;
    cardType?: string;
    active?: boolean;
    limit?: number;
  }): Promise<{ tokens: Token[]; total: number }> {
    const { data } = await this.client.post('/tokens/search', params);
    return data;
  }

  async revokeToken(token: string): Promise<void> {
    await this.client.post(`/tokens/${token}/revoke`);
  }

  // Activity
  async getActivity(limit = 50): Promise<{ activities: Activity[] }> {
    const { data } = await this.client.get('/activity', { params: { limit } });
    return data;
  }

  // Statistics
  async getStats(): Promise<Stats> {
    const { data } = await this.client.get('/stats');
    return data;
  }

  // Users
  async getUsers(): Promise<{ users: User[] }> {
    const { data } = await this.client.get('/users');
    return data;
  }

  async createUser(userData: {
    username: string;
    email: string;
    password: string;
    full_name: string;
    role: string;
  }): Promise<User> {
    const { data } = await this.client.post('/users', userData);
    return data;
  }

  async deleteUser(username: string): Promise<void> {
    await this.client.delete(`/users/${username}`);
  }

  // API Keys
  async getApiKeys(): Promise<{ api_keys: ApiKey[] }> {
    const { data } = await this.client.get('/api-keys');
    return data;
  }

  async createApiKey(clientName: string, permissions: string[]): Promise<ApiKey> {
    const { data } = await this.client.post('/api-keys', {
      client_name: clientName,
      permissions,
    });
    return data;
  }

  async revokeApiKey(apiKey: string): Promise<void> {
    await this.client.delete(`/api-keys/${apiKey}`);
  }

  // Utility
  isAuthenticated(): boolean {
    return !!this.sessionId;
  }

  // Configuration methods
  getApiUrl(): string {
    return this.currentApiUrl;
  }

  setApiUrl(newUrl: string): void {
    this.currentApiUrl = newUrl;
    this.client.defaults.baseURL = newUrl;
    localStorage.setItem('tokenshield_api_url', newUrl);
  }

  createTestInstance(testUrl: string): TokenShieldAPI {
    const testInstance = new TokenShieldAPI();
    testInstance.currentApiUrl = testUrl;
    testInstance.client = axios.create({
      baseURL: testUrl,
      headers: { 'Content-Type': 'application/json' },
      timeout: 5000, // 5 second timeout for connection tests
    });
    return testInstance;
  }

  // Version endpoint for connection testing and system info
  async getVersion(): Promise<SystemInfo> {
    const { data } = await this.client.get('/version');
    return data;
  }
}

export const api = new TokenShieldAPI();