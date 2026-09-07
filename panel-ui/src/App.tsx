import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme as antdTheme } from 'antd';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { ThemeProvider, useTheme } from './hooks/useTheme';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './pages/Dashboard/Dashboard';
import Alerts from './pages/Alerts/Alerts';
import MitreCoverage from './pages/MitreCoverage/MitreCoverage';

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
          colorPrimary: '#38bdf8',
          colorInfo: '#38bdf8',
          colorSuccess: '#34d399',
          colorWarning: '#fbbf24',
          colorError: '#fb7185',
          colorBgBase: dark ? '#091017' : '#f6f8fb',
          colorBgContainer: dark ? '#0f1720' : '#ffffff',
          colorBgElevated: dark ? '#131d28' : '#ffffff',
          colorBorder: dark ? '#263342' : '#dfe5ec',
          colorBorderSecondary: dark ? '#1d2936' : '#e9edf2',
          colorText: dark ? '#e7edf4' : '#15202b',
          colorTextSecondary: dark ? '#8da0b4' : '#637286',
          borderRadius: 10,
          borderRadiusLG: 14,
          fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
        },
        components: {
          Card: { paddingLG: 20 },
          Button: { controlHeight: 36 },
          Input: { controlHeight: 36 },
          Select: { controlHeight: 36 },
          Table: { headerBg: dark ? '#101923' : '#f8fafc' },
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
      <BrowserRouter basename="/panel">
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="mitre-coverage" element={<MitreCoverage />} />
            <Route path="analytics" element={<div className="p-6">Analytics Page Coming Soon</div>} />
            <Route path="settings" element={<div className="p-6">Settings Page Coming Soon</div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeApplier>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  );
}

export default App;
