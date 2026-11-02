import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, Spin, theme as antdTheme } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { ThemeProvider, useTheme } from './hooks/useTheme';
import { AuthProvider, RequireAuth } from './auth/AuthContext';
import MainLayout from './components/Layout/MainLayout';
import Login from './pages/Login/Login';

// Workspace pages are split into their own chunks so the login screen does not ship charts and tables.
const Dashboard = lazy(() => import('./pages/Dashboard/Dashboard'));
const Alerts = lazy(() => import('./pages/Alerts/Alerts'));
const Reports = lazy(() => import('./pages/Reports/Reports'));
const MitreCoverage = lazy(() => import('./pages/MitreCoverage/MitreCoverage'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1, staleTime: 5 * 60 * 1000 },
  },
});

const ThemeApplier: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { mode } = useTheme();
  const dark = mode === 'dark';

  useEffect(() => {
    document.body.classList.toggle('dark', dark);
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);

  return (
    <ConfigProvider
      theme={{
        algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
        token: {
          colorPrimary: dark ? '#9d83ff' : '#6652dc',
          colorInfo: dark ? '#3ac0d9' : '#0f7188',
          colorSuccess: dark ? '#3bcf91' : '#0f7a4e',
          colorWarning: dark ? '#e2b45b' : '#946115',
          colorError: dark ? '#ec6b78' : '#c84b5d',
          colorBgBase: dark ? '#0a0f1e' : '#f5f7fa',
          colorBgContainer: dark ? '#131c2e' : '#ffffff',
          colorBgElevated: dark ? '#172237' : '#ffffff',
          colorBorder: dark ? '#243047' : '#e0e6ed',
          colorBorderSecondary: dark ? '#202b41' : '#e8edf2',
          colorText: dark ? '#f0f4fd' : '#17212b',
          colorTextSecondary: dark ? '#b0bdd3' : '#607184',
          borderRadius: 10,
          borderRadiusLG: 14,
          controlHeight: 36,
          controlHeightSM: 30,
          fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        },
        components: {
          Card: { bodyPadding: 20 },
          Table: { headerBg: dark ? '#18243b' : '#f8fafc' },
        },
      }}
    >
      {children}
    </ConfigProvider>
  );
};

function AppContent() {
  return (
    <ThemeApplier>
      <AuthProvider>
        <BrowserRouter basename="/panel">
          <Suspense fallback={<Spin size="large" fullscreen />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route element={<RequireAuth />}>
              <Route path="/" element={<MainLayout />}>
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="dashboard" element={<Dashboard />} />
                <Route path="alerts" element={<Alerts />} />
                <Route path="reports" element={<Reports />} />
                <Route path="mitre-coverage" element={<MitreCoverage />} />
                <Route path="analytics" element={<PlaceholderPage eyebrow="ANALYTICS" title="Security Analytics" description="Advanced trend analysis and reporting will live here. The current dashboard continues to show production-backed operational metrics." />} />
                <Route path="settings" element={<PlaceholderPage eyebrow="SYSTEM" title="Settings" description="Panel and integration settings are not exposed in V1 yet. Existing runtime configuration remains server-managed." />} />
              </Route>
            </Route>
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
          </Suspense>
        </BrowserRouter>
      </AuthProvider>
    </ThemeApplier>
  );
}

function PlaceholderPage({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return (
    <section className="soc-placeholder-page">
      <span>{eyebrow}</span>
      <h1>{title}</h1>
      <p>{description}</p>
      <div>V1 · Planned workspace</div>
    </section>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
      {import.meta.env.DEV ? <ReactQueryDevtools initialIsOpen={false} /> : null}
    </QueryClientProvider>
  );
}

export default App;
