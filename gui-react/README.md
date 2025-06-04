# TokenShield React GUI

A modern React-based GUI for TokenShield using TypeScript, Material-UI, and Vite.

## Features

- 🎨 **Modern UI** with Material-UI components
- 📊 **Real-time Dashboard** with statistics
- 🔐 **Secure Authentication** with session management
- 📱 **Responsive Design** for mobile and desktop
- 🚀 **Fast Development** with Vite and HMR
- 🔍 **Type Safety** with TypeScript

## Tech Stack

- **React 19** - UI framework
- **TypeScript** - Type safety
- **Material-UI v5** - Component library
- **React Router v6** - Client-side routing
- **Axios** - HTTP client
- **Vite** - Build tool
- **MUI DataGrid** - Advanced data tables

## Development

### Prerequisites

- Node.js 18+
- npm or yarn
- TokenShield backend running on http://localhost:8090

### Installation

```bash
cd gui-react
npm install
```

### Running in Development

```bash
npm run dev
```

The app will be available at http://localhost:3000

### Building for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

### Preview Production Build

```bash
npm run preview
```

## Project Structure

```
src/
├── components/          # React components
│   ├── auth/           # Authentication components
│   ├── dashboard/      # Dashboard components
│   ├── layout/         # Layout components
│   └── tokens/         # Token management
├── contexts/           # React contexts
│   └── AuthContext.tsx # Authentication state
├── services/           # API services
│   └── api.ts         # API client
├── types/             # TypeScript types
│   └── index.ts       # Shared types
├── App.tsx            # Main app component
└── main.tsx           # Entry point
```

## Component Overview

### Authentication
- **LoginForm** - Session-based login
- **PasswordChangeDialog** - Force password change on first login
- **ProtectedRoute** - Route guard for authenticated pages

### Dashboard
- **Dashboard** - Main statistics view
- Real-time stats updates every 30 seconds

### Token Management
- **TokenList** - DataGrid with search, filter, and revoke
- Server-side pagination
- Advanced filtering by card type, last 4 digits, and status

### Layout
- **AppLayout** - Main app layout with sidebar
- Responsive navigation
- User menu with profile options

## API Integration

The app uses a type-safe API client (`services/api.ts`) that:
- Handles session management automatically
- Adds auth headers to all requests
- Redirects to login on 401 errors
- Provides typed responses

## Authentication Flow

1. User logs in with username/password
2. Session token stored in localStorage
3. Token included in all API requests
4. Auto-redirect to login on session expiry
5. Password change enforced on first login

## Environment Variables

Create a `.env` file for custom configuration:

```env
VITE_API_URL=http://localhost:8090/api/v1
```

## Docker Deployment

```dockerfile
# Build stage
FROM node:18-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

## Comparison with Current GUI

### Advantages
- ✅ Type safety prevents runtime errors
- ✅ Component-based architecture
- ✅ Better state management
- ✅ Modern development experience
- ✅ Better performance with virtual DOM
- ✅ Easier to test and maintain
- ✅ Rich component library (Material-UI)

### Migration Status
- ✅ Authentication (login/logout)
- ✅ Dashboard with stats
- ✅ Token list with search/filter/revoke
- ✅ Password change dialog
- ✅ Responsive layout
- 🚧 Activity monitoring
- 🚧 User management
- 🚧 API key management
- 🚧 Settings page

## Next Steps

1. Complete remaining pages (users, API keys, activity, settings)
2. Add unit tests with Jest and React Testing Library
3. Add E2E tests with Playwright
4. Implement real-time updates with WebSocket
5. Add dark mode support
6. Create Docker image for production