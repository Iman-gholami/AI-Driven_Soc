import React, { createContext, useContext, useEffect, useState } from 'react';
import type { ThemeMode } from '../types';

interface ThemeContextValue { mode: ThemeMode; toggleTheme: () => void; }
const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setMode] = useState<ThemeMode>(() => (localStorage.getItem('soc-theme') as ThemeMode) || 'light');
  useEffect(() => localStorage.setItem('soc-theme', mode), [mode]);
  return <ThemeContext.Provider value={{ mode, toggleTheme: () => setMode(v => v === 'dark' ? 'light' : 'dark') }}>{children}</ThemeContext.Provider>;
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used inside ThemeProvider');
  return context;
};
