// API Types matching the backend responses

export interface User {
  user_id: string;
  username: string;
  email: string;
  full_name: string;
  role: 'admin' | 'operator' | 'viewer';
  permissions: string[];
  is_active: boolean;
  created_at: string;
  last_login_at?: string;
}

export interface Session {
  session_id: string;
  user: User;
  expires_at: string;
  require_password_change: boolean;
}

export interface Token {
  token: string;
  card_type: string;
  last_four: string;
  is_active: boolean;
  created_at: string;
}

export interface Activity {
  id: number;
  token: string;
  timestamp: string;
  type: string;
  source_ip: string;
  destination?: string;
  status?: number;
  last_four?: string;
}

export interface Stats {
  active_tokens: number;
  requests_24h: { [key: string]: number };
}

export interface ApiKey {
  api_key: string;
  client_name: string;
  permissions: string[];
  is_active: boolean;
  created_at: string;
  last_used_at?: string;
}

export interface SystemInfo {
  version: string;
  token_format: string;
  kek_dek_enabled: boolean;
  features: string[];
  status: string;
}

export interface ApiError {
  error: string;
  details?: string;
}