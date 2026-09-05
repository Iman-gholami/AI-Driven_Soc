import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { ThemeProvider, useTheme } from './hooks/useTheme';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './pages/Dashboard/Dashboard';
import Alerts from './pages/Alerts/Alerts';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1, staleTime: 5 * 60 * 1000 },
  },
});

const ThemeApplier: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { mode } = useTheme();
  useEffect(() => {
    document.body.classList.toggle('dark', mode === 'dark');
    document.documentElement.classList.toggle('dark', mode === 'dark');
  }, [mode]);
  return <>{children}</>;
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
