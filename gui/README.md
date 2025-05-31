# TokenShield GUI Dashboard

A modern web interface for managing TokenShield credit card tokenization system. The dashboard provides a comprehensive view of tokens, API keys, activity monitoring, and system statistics.

## Features

- **Dashboard Overview**: Real-time statistics and system status
- **Token Management**: View, search, and revoke credit card tokens
- **API Key Management**: Create and manage API keys (admin privileges required)
- **Activity Monitoring**: Track system activity and token usage
- **Settings**: Configure API connection and dashboard preferences
- **Responsive Design**: Works on desktop and mobile devices

## Quick Start

### Local Development

1. **Serve files locally**:
   ```bash
   # Using Python
   python3 -m http.server 8000
   
   # Using Node.js
   npx serve .
   
   # Using PHP
   php -S localhost:8000
   ```

2. **Open in browser**:
   ```
   http://localhost:8000
   ```

### Docker Deployment

1. **Build the image**:
   ```bash
   docker build -t tokenshield-gui .
   ```

2. **Run the container**:
   ```bash
   docker run -d -p 8080:80 --name tokenshield-gui tokenshield-gui
   ```

3. **Access the dashboard**:
   ```
   http://localhost:8080
   ```

### Docker Compose Integration

Add to your existing `docker-compose.yml`:

```yaml
services:
  # ... existing services ...
  
  tokenshield-gui:
    build: ./gui
    ports:
      - "8080:80"
    networks:
      - tokenshield-net
    depends_on:
      - tokenshield-unified
```

## Configuration

### First Time Setup

1. **Open Settings**: Click the Settings tab in the navigation
2. **Configure API Connection**:
   - API URL: `http://localhost:8090` (or your TokenShield API URL)
   - API Key: Your TokenShield API key (create one using the CLI)
   - Admin Secret: Your admin secret for privileged operations
3. **Test Connection**: Click "Test Connection" to verify settings
4. **Save Settings**: Click "Save Settings" to store configuration

### API Key Setup

Before using the dashboard, you need an API key:

```bash
# Using the CLI tool
./tokenshield apikey create "Dashboard" --permissions read,write,admin

# Or using direct API call
curl -X POST http://localhost:8090/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: your-admin-secret" \
  -d '{"client_name":"Dashboard","permissions":["read","write","admin"]}'
```

### Environment Variables

For Docker deployments, you can set default values:

```bash
docker run -d \
  -p 8080:80 \
  -e TOKENSHIELD_API_URL=http://tokenshield-unified:8090 \
  -e TOKENSHIELD_API_KEY=your-api-key \
  tokenshield-gui
```

## Dashboard Sections

### 1. Dashboard
- **System Statistics**: Active tokens, 24h requests, API keys count
- **Recent Activity**: Latest tokenization/detokenization requests
- **System Information**: Version, features, status

### 2. Token Management
- **View Tokens**: List all credit card tokens with pagination
- **Search Functionality**: Filter by last 4 digits, card type, status
- **Token Operations**: Revoke active tokens
- **Real-time Updates**: Auto-refresh capabilities

### 3. API Key Management
- **List API Keys**: View all API keys and their status
- **Create Keys**: Generate new API keys with specific permissions
- **Revoke Keys**: Disable API keys when no longer needed
- **Permission Management**: Control read, write, and admin access

### 4. Activity Monitoring
- **Request Tracking**: Monitor all tokenization requests
- **Source Analysis**: View request sources and patterns
- **Status Monitoring**: Track success/failure rates
- **Historical Data**: Configurable time ranges

### 5. Settings
- **API Configuration**: Manage connection settings
- **Dashboard Preferences**: Auto-refresh intervals, items per page
- **Connection Testing**: Verify API connectivity

## Features

### Security
- **API Key Authentication**: Secure access to TokenShield API
- **Admin Privileges**: Separate admin functions require additional authentication
- **Local Storage**: Settings stored locally in browser
- **HTTPS Support**: Ready for production HTTPS deployment

### User Experience
- **Responsive Design**: Works on all screen sizes
- **Real-time Updates**: Live data refresh capabilities
- **Toast Notifications**: User-friendly success/error messages
- **Loading States**: Clear feedback during API operations
- **Error Handling**: Graceful handling of API failures

### Performance
- **Lazy Loading**: Sections load data only when viewed
- **Caching**: Efficient API request management
- **Pagination**: Handle large datasets efficiently
- **Compression**: Gzipped static assets

## API Integration

The dashboard consumes the TokenShield REST API endpoints:

- `GET /api/v1/version` - System information
- `GET /api/v1/stats` - System statistics
- `GET /api/v1/tokens` - List tokens
- `POST /api/v1/tokens/search` - Search tokens
- `DELETE /api/v1/tokens/{token}` - Revoke token
- `GET /api/v1/api-keys` - List API keys (admin)
- `POST /api/v1/api-keys` - Create API key (admin)
- `DELETE /api/v1/api-keys/{key}` - Revoke API key (admin)
- `GET /api/v1/activity` - Activity monitoring

## Browser Support

- **Modern Browsers**: Chrome 70+, Firefox 65+, Safari 12+, Edge 79+
- **Mobile Browsers**: iOS Safari 12+, Chrome Mobile 70+
- **Features Used**: Fetch API, CSS Grid, Flexbox, ES6+

## Customization

### Styling
The dashboard uses CSS custom properties (variables) for easy theming:

```css
:root {
    --primary-color: #3b82f6;
    --background: #f8fafc;
    --surface: #ffffff;
    /* ... more variables */
}
```

### Configuration
Settings are stored in browser localStorage:

```javascript
localStorage.setItem('tokenshield_api_url', 'https://api.tokenshield.com');
localStorage.setItem('tokenshield_api_key', 'ts_your-key');
```

### Extensions
The dashboard is built with modularity in mind. You can:
- Add new sections by extending the navigation
- Create custom API integrations
- Implement additional visualizations
- Add export/import functionality

## Troubleshooting

### Connection Issues
1. **Verify API URL**: Ensure TokenShield API is running and accessible
2. **Check CORS**: API must allow requests from dashboard domain
3. **Network Access**: Verify no firewall blocking requests
4. **SSL/TLS**: Match HTTP/HTTPS between dashboard and API

### Authentication Issues
1. **API Key Validity**: Ensure API key is active and has correct permissions
2. **Admin Secret**: Verify admin secret for privileged operations
3. **Token Expiration**: Check if API keys have expiration dates

### Data Display Issues
1. **Browser Console**: Check for JavaScript errors
2. **Network Tab**: Verify API responses in browser dev tools
3. **Clear Cache**: Refresh browser cache and localStorage

### Performance Issues
1. **Limit Queries**: Use appropriate limits for large datasets
2. **Auto-refresh**: Disable auto-refresh for better performance
3. **Browser Resources**: Close unused tabs and applications

## Development

### File Structure
```
gui/
├── index.html          # Main HTML structure
├── styles.css          # CSS styling and responsive design
├── app.js             # JavaScript application logic
├── Dockerfile         # Container configuration
├── nginx.conf         # Web server configuration
└── README.md          # This documentation
```

### Building
No build process required - the dashboard uses vanilla HTML, CSS, and JavaScript.

### Contributing
1. **Code Style**: Follow existing patterns and conventions
2. **Testing**: Test in multiple browsers and screen sizes
3. **Documentation**: Update README for new features
4. **Accessibility**: Ensure WCAG compliance for new elements

## Production Deployment

### HTTPS Setup
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    # ... rest of nginx config
}
```

### Reverse Proxy
If deploying behind a reverse proxy, ensure proper headers:

```nginx
location /tokenshield/ {
    proxy_pass http://tokenshield-gui/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Monitoring
Monitor the dashboard with standard web metrics:
- Response times
- Error rates
- User sessions
- API call patterns

## Support

For issues and feature requests:
1. Check the TokenShield main repository
2. Review API documentation
3. Verify browser compatibility
4. Check console logs for errors

The dashboard is designed to be self-contained and easy to deploy alongside your TokenShield infrastructure.