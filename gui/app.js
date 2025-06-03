// TokenShield Dashboard JavaScript

class TokenShieldDashboard {
    constructor() {
        this.config = {
            apiUrl: localStorage.getItem('tokenshield_api_url') || 'http://localhost:8090',
            apiKey: localStorage.getItem('tokenshield_api_key') || '',
            adminSecret: localStorage.getItem('tokenshield_admin_secret') || '',
            sessionId: localStorage.getItem('tokenshield_session_id') || ''
        };
        
        this.currentUser = null;
        this.refreshInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuthentication();
    }

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // User dropdown menu
        const userMenuBtn = document.getElementById('user-menu-btn');
        if (userMenuBtn) {
            userMenuBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                document.getElementById('user-menu').classList.toggle('active');
            });
        }

        // Close dropdown when clicking outside
        document.addEventListener('click', () => {
            document.getElementById('user-menu')?.classList.remove('active');
        });

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.handleLogout();
            });
        }

        // Profile button
        const profileBtn = document.getElementById('profile-btn');
        if (profileBtn) {
            profileBtn.addEventListener('click', (e) => {
                e.preventDefault();
                // Navigate to settings with user section
                document.querySelector('[data-section="settings"]').click();
            });
        }

        // Settings button in dropdown
        const settingsBtn = document.getElementById('settings-btn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                document.querySelector('[data-section="settings"]').click();
            });
        }

        // User management
        const createUserBtn = document.getElementById('create-user-btn');
        if (createUserBtn) {
            createUserBtn.addEventListener('click', () => this.openUserModal());
        }

        const refreshUsersBtn = document.getElementById('refresh-users-btn');
        if (refreshUsersBtn) {
            refreshUsersBtn.addEventListener('click', () => this.loadUsers());
        }

        this.setupNavigation();
    }

    async checkAuthentication() {
        // Check if we have a session
        if (!this.config.sessionId) {
            this.showLogin();
            return;
        }

        try {
            const response = await this.makeRequest('/api/v1/auth/me');
            if (response.ok) {
                this.currentUser = await response.json();
                this.showDashboard();
                this.updateUserMenu();
                this.checkConnection();
                this.loadDashboard();
            } else {
                // Session expired or invalid
                this.clearSession();
                this.showLogin();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            this.showLogin();
        }
    }

    showLogin() {
        document.getElementById('login-section').classList.add('active');
        document.getElementById('main-nav').style.display = 'none';
        document.getElementById('user-menu').style.display = 'none';
        
        // Hide all other sections
        const sections = document.querySelectorAll('.content-section:not(#login-section)');
        sections.forEach(section => section.classList.remove('active'));
    }

    showDashboard() {
        document.getElementById('login-section').classList.remove('active');
        document.getElementById('main-nav').style.display = 'flex';
        document.getElementById('user-menu').style.display = 'flex';
        
        // Show dashboard by default
        document.getElementById('dashboard-section').classList.add('active');
        
        // Update nav to show dashboard as active
        const navLinks = document.querySelectorAll('.nav-link');
        navLinks.forEach(link => link.classList.remove('active'));
        document.querySelector('[data-section="dashboard"]').classList.add('active');
    }

    updateUserMenu() {
        if (this.currentUser) {
            document.getElementById('current-username').textContent = this.currentUser.username;
            document.getElementById('user-email').textContent = this.currentUser.email;
            
            const roleElement = document.getElementById('user-role');
            roleElement.textContent = this.currentUser.role.charAt(0).toUpperCase() + this.currentUser.role.slice(1);
            roleElement.className = `user-role-badge ${this.currentUser.role}`;
        }
    }

    async handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('login-error');

        try {
            const response = await fetch(`${this.config.apiUrl}/api/v1/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                const authData = await response.json();
                this.config.sessionId = authData.session_id;
                this.currentUser = authData.user;
                
                // Store session
                localStorage.setItem('tokenshield_session_id', authData.session_id);
                
                // Clear old API key to prevent conflicts
                localStorage.removeItem('tokenshield_api_key');
                this.config.apiKey = '';
                
                this.showDashboard();
                this.updateUserMenu();
                this.checkConnection();
                this.loadDashboard();
                errorDiv.style.display = 'none';
            } else {
                const errorData = await response.json();
                errorDiv.textContent = errorData.error || 'Login failed';
                errorDiv.style.display = 'block';
            }
        } catch (error) {
            console.error('Login failed:', error);
            errorDiv.textContent = 'Connection error. Please check the API URL.';
            errorDiv.style.display = 'block';
        }
    }

    async handleLogout() {
        try {
            await this.makeRequest('/api/v1/auth/logout', { method: 'POST' });
        } catch (error) {
            console.log('Logout request failed, clearing session anyway');
        }
        
        this.clearSession();
        this.showLogin();
    }

    clearSession() {
        this.config.sessionId = '';
        this.currentUser = null;
        localStorage.removeItem('tokenshield_session_id');
    }

    async makeRequest(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // Use session if available, otherwise fall back to API key
        if (this.config.sessionId) {
            headers['Authorization'] = `Bearer ${this.config.sessionId}`;
            // Don't send API key if we have a session
        } else if (this.config.apiKey) {
            headers['X-API-Key'] = this.config.apiKey;
        }

        if (this.config.adminSecret) {
            headers['X-Admin-Secret'] = this.config.adminSecret;
        }

        const response = await fetch(`${this.config.apiUrl}${endpoint}`, {
            ...options,
            headers
        });

        // If unauthorized, clear session and redirect to login
        if (response.status === 401) {
            this.clearSession();
            this.showLogin();
        }

        return response;
    }

    // User Management Methods
    async loadUsers() {
        try {
            const response = await this.makeRequest('/api/v1/users');
            if (response.ok) {
                const data = await response.json();
                this.displayUsers(data.users);
            } else {
                this.showError('Failed to load users');
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.showError('Error loading users');
        }
    }

    displayUsers(users) {
        const container = document.getElementById('users-table');
        
        if (!users || users.length === 0) {
            container.innerHTML = '<div class="no-data">No users found</div>';
            return;
        }

        const table = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Full Name</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${users.map(user => `
                        <tr>
                            <td class="font-mono">${user.username}</td>
                            <td>${user.email}</td>
                            <td>${user.full_name || '-'}</td>
                            <td><span class="user-role-badge ${user.role}">${user.role}</span></td>
                            <td>
                                <span class="user-status ${user.is_active ? 'active' : 'inactive'}">
                                    <i class="fas fa-circle"></i>
                                    ${user.is_active ? 'Active' : 'Inactive'}
                                </span>
                            </td>
                            <td>${user.last_login_at ? new Date(user.last_login_at).toLocaleString() : 'Never'}</td>
                            <td>
                                <div class="user-actions">
                                    <button class="btn btn-secondary btn-xs" onclick="dashboard.editUser('${user.user_id}')">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    ${user.username !== 'admin' ? `
                                        <button class="btn btn-danger btn-xs" onclick="dashboard.deleteUser('${user.user_id}', '${user.username}')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    ` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
        container.innerHTML = table;
    }

    openUserModal(userId = null) {
        const modal = document.getElementById('user-modal');
        const title = document.getElementById('user-modal-title');
        const form = document.getElementById('user-form');
        
        if (userId) {
            title.textContent = 'Edit User';
            // Load user data for editing
            this.loadUserForEdit(userId);
        } else {
            title.textContent = 'Create User';
            form.reset();
            document.getElementById('user-active').checked = true;
        }
        
        modal.style.display = 'block';
    }

    async saveUser() {
        const form = document.getElementById('user-form');
        const formData = new FormData(form);
        
        const userData = {
            username: document.getElementById('user-username').value,
            email: document.getElementById('user-email').value,
            password: document.getElementById('user-password').value,
            full_name: document.getElementById('user-full-name').value,
            role: document.getElementById('user-role').value
        };

        // Validate required fields
        if (!userData.username || !userData.email || !userData.password) {
            this.showError('Please fill in all required fields');
            return;
        }

        try {
            const response = await this.makeRequest('/api/v1/users', {
                method: 'POST',
                body: JSON.stringify(userData)
            });

            if (response.ok) {
                this.showToast('User created successfully', 'success');
                this.closeUserModal();
                this.loadUsers();
            } else {
                const error = await response.json();
                this.showError(error.error || 'Failed to create user');
            }
        } catch (error) {
            console.error('Error creating user:', error);
            this.showError('Error creating user');
        }
    }

    async deleteUser(userId, username) {
        if (!confirm(`Are you sure you want to delete user '${username}'?`)) {
            return;
        }

        try {
            const response = await this.makeRequest(`/api/v1/users/${username}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                this.showToast('User deleted successfully', 'success');
                this.loadUsers();
            } else {
                const error = await response.json();
                this.showError(error.error || 'Failed to delete user');
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            this.showError('Error deleting user');
        }
    }

    closeUserModal() {
        document.getElementById('user-modal').style.display = 'none';
    }

    showError(message) {
        this.showToast('Error', message, 'error');
    }

    setupNavigation() {
        const navLinks = document.querySelectorAll('.nav-link');
        const sections = document.querySelectorAll('.content-section');

        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                
                // Update active nav link
                navLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
                
                // Show corresponding section
                const sectionId = link.dataset.section + '-section';
                sections.forEach(s => s.classList.remove('active'));
                document.getElementById(sectionId)?.classList.add('active');
                
                // Load section data
                this.loadSection(link.dataset.section);
            });
        });
    }

    async loadSection(section) {
        switch (section) {
            case 'dashboard':
                await this.loadDashboard();
                break;
            case 'tokens':
                await this.loadTokens();
                break;
            case 'apikeys':
                await this.loadAPIKeys();
                break;
            case 'users':
                await this.loadUsers();
                break;
            case 'activity':
                await this.loadActivity();
                break;
            case 'keys':
                await this.loadKeys();
                break;
            case 'settings':
                this.loadSettings();
                break;
        }
    }

    // Legacy method - calls makeRequest but returns JSON directly
    async makeAPIRequest(endpoint, options = {}) {
        const response = await this.makeRequest(endpoint, options);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return await response.json();
    }

    async checkConnection() {
        try {
            await this.makeAPIRequest('/api/v1/version');
            this.updateConnectionStatus(true);
        } catch (error) {
            this.updateConnectionStatus(false);
        }
    }

    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        if (connected) {
            statusElement.className = 'status-indicator online';
            statusElement.innerHTML = '<i class="fas fa-circle"></i> Connected';
        } else {
            statusElement.className = 'status-indicator offline';
            statusElement.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
        }
    }

    async loadDashboard() {
        try {
            // Load system info and stats in parallel
            const [versionData, statsData] = await Promise.all([
                this.makeAPIRequest('/api/v1/version'),
                this.makeAPIRequest('/api/v1/stats')
            ]);

            // Update stats cards
            document.getElementById('total-tokens').textContent = statsData.active_tokens || '0';
            
            // Calculate total requests
            const totalRequests = Object.values(statsData.requests_24h || {}).reduce((sum, count) => sum + count, 0);
            document.getElementById('requests-24h').textContent = totalRequests.toString();
            
            document.getElementById('system-status').textContent = 'Online';

            // Update system info
            this.renderSystemInfo(versionData);
            
            // Load recent activity
            await this.loadRecentActivity();
            
            // Try to get API keys count (admin only)
            try {
                const apiKeysData = await this.makeAPIRequest('/api/v1/api-keys');
                document.getElementById('api-keys-count').textContent = apiKeysData.total || '0';
            } catch (error) {
                document.getElementById('api-keys-count').textContent = 'N/A';
            }

        } catch (error) {
            console.error('Failed to load dashboard:', error);
        }
    }

    renderSystemInfo(data) {
        const container = document.getElementById('system-info');
        container.innerHTML = `
            <div class="info-list">
                <div class="info-item">
                    <span class="info-label">Version</span>
                    <span class="info-value">${data.version}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Token Format</span>
                    <span class="info-value">${data.token_format}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">KEK/DEK Enabled</span>
                    <span class="info-value">${data.kek_dek_enabled ? 'Yes' : 'No'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Features</span>
                    <span class="info-value">${data.features.join(', ')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">API Status</span>
                    <span class="info-value status-badge active">Active</span>
                </div>
            </div>
        `;
    }

    async loadRecentActivity() {
        try {
            const data = await this.makeAPIRequest('/api/v1/activity?limit=10');
            this.renderRecentActivity(data.activities);
        } catch (error) {
            document.getElementById('recent-activity').innerHTML = '<div class="empty-state">Unable to load activity</div>';
        }
    }

    renderRecentActivity(activities) {
        const container = document.getElementById('recent-activity');
        
        if (!activities || activities.length === 0) {
            container.innerHTML = '<div class="empty-state">No recent activity</div>';
            return;
        }

        container.innerHTML = activities.map(activity => `
            <div class="activity-item">
                <div class="activity-icon ${activity.type.toLowerCase()}">
                    <i class="fas fa-${activity.type === 'tokenize' ? 'lock' : 'unlock'}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${this.capitalizeFirst(activity.type)} Request</div>
                    <div class="activity-meta">
                        ${activity.card_last_four ? `Card ending ${activity.card_last_four} • ` : ''}
                        ${activity.source_ip} • ${this.formatTimestamp(activity.timestamp)}
                        ${activity.status ? ` • Status ${activity.status}` : ''}
                    </div>
                </div>
            </div>
        `).join('');
    }

    async loadTokens() {
        const container = document.getElementById('tokens-table');
        container.innerHTML = '<div class="loading">Loading tokens...</div>';
        
        try {
            const data = await this.makeAPIRequest('/api/v1/tokens?limit=100');
            this.renderTokensTable(data.tokens);
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Unable to load tokens</div>';
        }
    }

    renderTokensTable(tokens) {
        const container = document.getElementById('tokens-table');
        
        if (!tokens || tokens.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-credit-card"></i><h3>No Tokens Found</h3><p>No tokens have been created yet</p></div>';
            return;
        }

        container.innerHTML = `
            <table class="table">
                <thead>
                    <tr>
                        <th>Token</th>
                        <th>Card Type</th>
                        <th>Last 4</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${tokens.map(token => `
                        <tr>
                            <td><span class="token-display">${this.truncateToken(token.token)}</span></td>
                            <td>${token.card_type || 'Unknown'}</td>
                            <td>${token.last_four}</td>
                            <td><span class="status-badge ${token.is_active ? 'active' : 'inactive'}">${token.is_active ? 'Active' : 'Revoked'}</span></td>
                            <td>${this.formatTimestamp(token.created_at)}</td>
                            <td>
                                <div class="table-actions">
                                    ${token.is_active ? `<button class="btn btn-sm btn-danger" onclick="dashboard.revokeToken('${token.token}')"><i class="fas fa-ban"></i></button>` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    async searchTokens() {
        const lastFour = document.getElementById('token-search').value;
        const cardType = document.getElementById('card-type-filter').value;
        
        const container = document.getElementById('tokens-table');
        container.innerHTML = '<div class="loading">Searching tokens...</div>';
        
        try {
            const searchData = { limit: 100 };
            if (lastFour) searchData.last_four = lastFour;
            if (cardType) searchData.card_type = cardType;
            
            const data = await this.makeAPIRequest('/api/v1/tokens/search', {
                method: 'POST',
                body: JSON.stringify(searchData)
            });
            
            this.renderTokensTable(data.tokens);
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Search failed</div>';
        }
    }

    async revokeToken(token) {
        if (!confirm(`Are you sure you want to revoke token ${this.truncateToken(token)}?`)) {
            return;
        }
        
        try {
            await this.makeAPIRequest(`/api/v1/tokens/${token}`, { method: 'DELETE' });
            this.showToast('Success', 'Token revoked successfully', 'success');
            await this.loadTokens(); // Refresh the table
        } catch (error) {
            this.showToast('Error', 'Failed to revoke token', 'error');
        }
    }

    async loadAPIKeys() {
        const container = document.getElementById('apikeys-table');
        container.innerHTML = '<div class="loading">Loading API keys...</div>';
        
        try {
            const data = await this.makeAPIRequest('/api/v1/api-keys');
            this.renderAPIKeysTable(data.api_keys);
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Unable to load API keys (Admin privileges required)</div>';
        }
    }

    renderAPIKeysTable(apiKeys) {
        const container = document.getElementById('apikeys-table');
        
        if (!apiKeys || apiKeys.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-key"></i><h3>No API Keys Found</h3><p>No API keys have been created yet</p></div>';
            return;
        }

        container.innerHTML = `
            <table class="table">
                <thead>
                    <tr>
                        <th>API Key</th>
                        <th>Client Name</th>
                        <th>Permissions</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Last Used</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${apiKeys.map(key => `
                        <tr>
                            <td><span class="token-display">${this.truncateToken(key.api_key)}</span></td>
                            <td>${key.client_name}</td>
                            <td>${(key.permissions || []).join(', ')}</td>
                            <td><span class="status-badge ${key.is_active ? 'active' : 'inactive'}">${key.is_active ? 'Active' : 'Revoked'}</span></td>
                            <td>${this.formatTimestamp(key.created_at)}</td>
                            <td>${key.last_used_at ? this.formatTimestamp(key.last_used_at) : 'Never'}</td>
                            <td>
                                <div class="table-actions">
                                    ${key.is_active ? `<button class="btn btn-sm btn-danger" onclick="dashboard.revokeAPIKey('${key.api_key}')"><i class="fas fa-ban"></i></button>` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    async revokeAPIKey(apiKey) {
        if (!confirm(`Are you sure you want to revoke API key ${this.truncateToken(apiKey)}?`)) {
            return;
        }
        
        try {
            await this.makeAPIRequest(`/api/v1/api-keys/${apiKey}`, { method: 'DELETE' });
            this.showToast('Success', 'API key revoked successfully', 'success');
            await this.loadAPIKeys(); // Refresh the table
        } catch (error) {
            this.showToast('Error', 'Failed to revoke API key', 'error');
        }
    }

    showCreateAPIKeyModal() {
        document.getElementById('create-apikey-modal').classList.add('show');
    }

    hideCreateAPIKeyModal() {
        document.getElementById('create-apikey-modal').classList.remove('show');
        document.getElementById('new-client-name').value = '';
        document.querySelectorAll('#create-apikey-modal input[type="checkbox"]').forEach(cb => {
            cb.checked = cb.value !== 'admin';
        });
    }

    async createAPIKey() {
        const clientName = document.getElementById('new-client-name').value.trim();
        if (!clientName) {
            this.showToast('Error', 'Client name is required', 'error');
            return;
        }

        const permissions = Array.from(document.querySelectorAll('#create-apikey-modal input[type="checkbox"]:checked'))
            .map(cb => cb.value);

        try {
            const data = await this.makeAPIRequest('/api/v1/api-keys', {
                method: 'POST',
                body: JSON.stringify({
                    client_name: clientName,
                    permissions: permissions
                })
            });

            this.showToast('Success', 'API key created successfully', 'success');
            this.hideCreateAPIKeyModal();
            await this.loadAPIKeys(); // Refresh the table
            
            // Show the new API key
            alert(`New API Key: ${data.api_key}\n\nPlease copy this key as it won't be shown again.`);
        } catch (error) {
            this.showToast('Error', 'Failed to create API key', 'error');
        }
    }

    async loadActivity() {
        const container = document.getElementById('activity-table');
        container.innerHTML = '<div class="loading">Loading activity...</div>';
        
        const limit = document.getElementById('activity-limit')?.value || 50;
        
        try {
            const data = await this.makeAPIRequest(`/api/v1/activity?limit=${limit}`);
            this.renderActivityTable(data.activities);
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Unable to load activity</div>';
        }
    }

    renderActivityTable(activities) {
        const container = document.getElementById('activity-table');
        
        if (!activities || activities.length === 0) {
            container.innerHTML = '<div class="empty-state"><i class="fas fa-chart-line"></i><h3>No Activity Found</h3><p>No recent activity to display</p></div>';
            return;
        }

        container.innerHTML = `
            <table class="table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Type</th>
                        <th>Token</th>
                        <th>Card Last 4</th>
                        <th>Source IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${activities.map(activity => `
                        <tr>
                            <td>${this.formatTimestamp(activity.timestamp)}</td>
                            <td><span class="status-badge ${activity.type}">${this.capitalizeFirst(activity.type)}</span></td>
                            <td><span class="token-display">${this.truncateToken(activity.token)}</span></td>
                            <td>${activity.card_last_four || 'N/A'}</td>
                            <td>${activity.source_ip}</td>
                            <td>${activity.status || 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    loadSettings() {
        document.getElementById('api-url').value = this.config.apiUrl;
        document.getElementById('api-key').value = this.config.apiKey;
        document.getElementById('admin-secret').value = this.config.adminSecret;
        
        const refreshInterval = localStorage.getItem('tokenshield_refresh_interval') || '0';
        document.getElementById('refresh-interval').value = refreshInterval;
        
        const itemsPerPage = localStorage.getItem('tokenshield_items_per_page') || '50';
        document.getElementById('items-per-page').value = itemsPerPage;
    }

    saveSettings() {
        this.config.apiUrl = document.getElementById('api-url').value.trim();
        this.config.apiKey = document.getElementById('api-key').value.trim();
        this.config.adminSecret = document.getElementById('admin-secret').value.trim();
        
        // Save to localStorage
        localStorage.setItem('tokenshield_api_url', this.config.apiUrl);
        localStorage.setItem('tokenshield_api_key', this.config.apiKey);
        localStorage.setItem('tokenshield_admin_secret', this.config.adminSecret);
        
        const refreshInterval = document.getElementById('refresh-interval').value;
        localStorage.setItem('tokenshield_refresh_interval', refreshInterval);
        
        const itemsPerPage = document.getElementById('items-per-page').value;
        localStorage.setItem('tokenshield_items_per_page', itemsPerPage);
        
        this.showToast('Success', 'Settings saved successfully', 'success');
        
        // Update auto-refresh
        this.setAutoRefresh(parseInt(refreshInterval));
        
        // Test new connection
        this.checkConnection();
    }

    async testConnection() {
        try {
            const tempConfig = {
                apiUrl: document.getElementById('api-url').value.trim(),
                apiKey: document.getElementById('api-key').value.trim(),
                adminSecret: document.getElementById('admin-secret').value.trim()
            };
            
            const url = `${tempConfig.apiUrl}/api/v1/version`;
            const headers = { 'Content-Type': 'application/json' };
            
            if (tempConfig.apiKey) headers['X-API-Key'] = tempConfig.apiKey;
            if (tempConfig.adminSecret) headers['X-Admin-Secret'] = tempConfig.adminSecret;
            
            const response = await fetch(url, { headers });
            
            if (response.ok) {
                this.showToast('Success', 'Connection test successful', 'success');
            } else {
                this.showToast('Error', `Connection failed: ${response.status}`, 'error');
            }
        } catch (error) {
            this.showToast('Error', `Connection failed: ${error.message}`, 'error');
        }
    }

    async loadKeys() {
        console.log('loadKeys called');
        try {
            await this.loadKeyStatus();
            console.log('loadKeyStatus completed, calling loadRotationHistory');
            await this.loadRotationHistory();
            console.log('loadRotationHistory completed');
        } catch (error) {
            console.error('Error in loadKeys:', error);
        }
    }

    async loadKeyStatus() {
        const container = document.getElementById('key-status');
        const statusBadge = document.getElementById('kek-dek-status');
        
        container.innerHTML = '<div class="loading">Loading key status...</div>';
        statusBadge.textContent = 'KEK/DEK Status: Loading...';
        
        try {
            // Check if KEK/DEK is enabled first
            const versionData = await this.makeAPIRequest('/api/v1/version');
            
            if (!versionData.kek_dek_enabled) {
                console.log('KEK/DEK is disabled, returning early');
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-info-circle"></i>
                        <h3>KEK/DEK Not Enabled</h3>
                        <p>KEK/DEK encryption is not enabled on this system. Key rotation is only available when KEK/DEK encryption is active.</p>
                    </div>
                `;
                statusBadge.className = 'status-badge warning';
                statusBadge.textContent = 'KEK/DEK Status: Disabled';
                return;
            }
            console.log('KEK/DEK is enabled, continuing...');
            
            const data = await this.makeAPIRequest('/api/v1/keys/status');
            this.renderKeyStatus(data);
            
            statusBadge.className = 'status-badge active';
            statusBadge.textContent = 'KEK/DEK Status: Enabled';
            
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Unable to load key status</div>';
            statusBadge.className = 'status-badge inactive';
            statusBadge.textContent = 'KEK/DEK Status: Error';
        }
    }

    renderKeyStatus(data) {
        const container = document.getElementById('key-status');
        
        if (!data.kek && !data.dek) {
            container.innerHTML = '<div class="empty-state">No encryption keys found</div>';
            return;
        }

        container.innerHTML = `
            <div class="key-info">
                ${data.kek ? `
                    <div class="key-card">
                        <h4>KEK (Key Encryption Key)</h4>
                        <div class="key-detail">
                            <span>Key ID:</span>
                            <span class="font-mono">${this.truncateToken(data.kek.key_id)}</span>
                        </div>
                        <div class="key-detail">
                            <span>Version:</span>
                            <span>${data.kek.version}</span>
                        </div>
                        <div class="key-detail">
                            <span>Status:</span>
                            <span class="status-badge ${data.kek.status}">${this.capitalizeFirst(data.kek.status)}</span>
                        </div>
                        <div class="key-detail">
                            <span>Created:</span>
                            <span>${this.formatTimestamp(data.kek.created_at)}</span>
                        </div>
                    </div>
                ` : '<div class="key-card"><h4>KEK</h4><p>No KEK found</p></div>'}
                
                ${data.dek ? `
                    <div class="key-card">
                        <h4>DEK (Data Encryption Key)</h4>
                        <div class="key-detail">
                            <span>Key ID:</span>
                            <span class="font-mono">${this.truncateToken(data.dek.key_id)}</span>
                        </div>
                        <div class="key-detail">
                            <span>Version:</span>
                            <span>${data.dek.version}</span>
                        </div>
                        <div class="key-detail">
                            <span>Status:</span>
                            <span class="status-badge ${data.dek.status}">${this.capitalizeFirst(data.dek.status)}</span>
                        </div>
                        <div class="key-detail">
                            <span>Created:</span>
                            <span>${this.formatTimestamp(data.dek.created_at)}</span>
                        </div>
                        ${data.dek.cards_encrypted ? `
                            <div class="key-detail">
                                <span>Cards Encrypted:</span>
                                <span>${data.dek.cards_encrypted}</span>
                            </div>
                        ` : ''}
                    </div>
                ` : '<div class="key-card"><h4>DEK</h4><p>No DEK found</p></div>'}
            </div>
        `;
    }

    async loadRotationHistory() {
        const container = document.getElementById('rotation-history');
        container.innerHTML = '<div class="loading">Loading rotation history...</div>';
        
        try {
            const data = await this.makeAPIRequest('/api/v1/keys/rotations?limit=20');
            console.log('Rotation history data:', data);
            
            if (!data.rotations || data.rotations.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-history"></i>
                        <h3>No Rotation History</h3>
                        <p>Key rotation history will appear here after rotations are performed.</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Rotation ID</th>
                            <th>Key Type</th>
                            <th>Status</th>
                            <th>Started</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.rotations.map(rotation => `
                            <tr>
                                <td><span class="font-mono text-sm">${this.truncateToken(rotation.rotation_id)}</span></td>
                                <td><span class="status-badge">${rotation.key_type}</span></td>
                                <td><span class="rotation-status ${rotation.status}">
                                    <i class="fas fa-${rotation.status === 'completed' ? 'check-circle' : rotation.status === 'failed' ? 'times-circle' : 'spinner fa-spin'}"></i>
                                    ${this.capitalizeFirst(rotation.status)}
                                </span></td>
                                <td>${this.formatTimestamp(rotation.started_at)}</td>
                                <td>${rotation.duration_ms ? `${rotation.duration_ms}ms` : '-'}</td>
                            </tr>
                            ${rotation.error_message ? `
                                <tr>
                                    <td colspan="5" class="text-sm" style="color: var(--error-color); padding-left: 2rem;">
                                        Error: ${rotation.error_message}
                                    </td>
                                </tr>
                            ` : ''}
                        `).join('')}
                    </tbody>
                </table>
            `;
            
        } catch (error) {
            container.innerHTML = '<div class="empty-state">Unable to load rotation history</div>';
        }
    }

    async rotateKeys() {
        const rotationType = document.getElementById('rotation-type').value;
        const rotateBtn = document.getElementById('rotate-btn');
        
        // Confirm the operation
        if (!confirm(`Are you sure you want to rotate ${rotationType === 'both' ? 'both KEK and DEK' : rotationType}? This is a critical operation that cannot be undone.`)) {
            return;
        }
        
        // Disable button and show loading state
        rotateBtn.disabled = true;
        rotateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Rotating...';
        
        try {
            const response = await this.makeAPIRequest('/api/v1/keys/rotate', {
                method: 'POST',
                body: JSON.stringify({
                    key_type: rotationType
                })
            });
            
            if (response.status === 'completed') {
                this.showToast('Success', `Key rotation completed successfully. Rotated: ${response.rotated_keys.join(', ')}`, 'success');
            } else {
                this.showToast('Warning', `Key rotation finished with issues: ${response.errors ? response.errors.join(', ') : 'Unknown error'}`, 'warning');
            }
            
            // Refresh key status and rotation history
            await this.loadKeyStatus();
            await this.loadRotationHistory();
            
        } catch (error) {
            this.showToast('Error', `Key rotation failed: ${error.message}`, 'error');
        } finally {
            // Re-enable button
            rotateBtn.disabled = false;
            rotateBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Rotate Keys';
        }
    }

    setAutoRefresh(seconds) {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
        
        if (seconds > 0) {
            this.refreshInterval = setInterval(() => {
                const activeSection = document.querySelector('.nav-link.active')?.dataset.section;
                if (activeSection) {
                    this.loadSection(activeSection);
                }
            }, seconds * 1000);
        }
    }

    // Utility functions
    truncateToken(token) {
        if (!token) return 'N/A';
        return token.length > 20 ? `${token.substring(0, 20)}...` : token;
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        return new Date(timestamp).toLocaleString();
    }

    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    showToast(title, message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        `;
        
        container.appendChild(toast);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);
    }
}

// Global functions for onclick handlers
function refreshTokens() { dashboard.loadTokens(); }
function refreshAPIKeys() { dashboard.loadAPIKeys(); }
function refreshActivity() { dashboard.loadRecentActivity(); }
function refreshActivityFull() { dashboard.loadActivity(); }
function searchTokens() { dashboard.searchTokens(); }
function showCreateAPIKeyModal() { dashboard.showCreateAPIKeyModal(); }
function hideCreateAPIKeyModal() { dashboard.hideCreateAPIKeyModal(); }
function createAPIKey() { dashboard.createAPIKey(); }
function saveSettings() { dashboard.saveSettings(); }
function testConnection() { dashboard.testConnection(); }
function refreshKeyStatus() { dashboard.loadKeyStatus(); }
function rotateKeys() { dashboard.rotateKeys(); }

// User management global functions
function closeUserModal() { dashboard.closeUserModal(); }
function saveUser() { dashboard.saveUser(); }

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new TokenShieldDashboard();
});