import React, { useEffect, useState } from 'react';
import { Layout, Tooltip } from 'antd';
import {
  ColumnHeightOutlined,
  LogoutOutlined,
  MoonOutlined,
  SearchOutlined,
  SunOutlined,
} from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTheme } from '../../hooks/useTheme';
import { useAuth } from '../../auth/AuthContext';

const { Header: AntHeader } = Layout;
const DENSITY_KEY = 'soc_ui_density';

type UiDensity = 'comfortable' | 'compact';

const PAGE_META: Record<string, { eyebrow: string; title: string }> = {
  '/dashboard': { eyebrow: 'OPERATIONS', title: 'Command Center' },
  '/alerts': { eyebrow: 'DETECTION', title: 'Investigation Queue' },
  '/reports': { eyebrow: 'INTELLIGENCE', title: 'Historical Reports' },
  '/mitre-coverage': { eyebrow: 'DETECTION ENGINE', title: 'ATT&CK Coverage' },
  '/analytics': { eyebrow: 'ANALYTICS', title: 'Workspace' },
  '/settings': { eyebrow: 'SYSTEM', title: 'Configuration' },
};

const Header: React.FC<{ collapsed: boolean; onOpenCommand: () => void }> = ({ collapsed, onOpenCommand }) => {
  const { mode, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [density, setDensity] = useState<UiDensity>(() =>
    localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable',
  );
  const meta = PAGE_META[location.pathname] || { eyebrow: 'SOC', title: 'Security Operations Center' };

  useEffect(() => {
    document.documentElement.dataset.density = density;
    localStorage.setItem(DENSITY_KEY, density);
  }, [density]);

  const signOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  const identity = user?.displayName || user?.username || 'Analyst';
  const initial = identity.slice(0, 1).toUpperCase();
  const nextDensity: UiDensity = density === 'compact' ? 'comfortable' : 'compact';

  return (
    <AntHeader
      className="soc-topbar"
      style={{ left: collapsed ? 76 : 232 }}
    >
      <div className="soc-topbar-title">
        <span>{meta.eyebrow}</span>
        <strong>{meta.title}</strong>
      </div>

      <button type="button" className="soc-command-trigger" onClick={onOpenCommand} aria-label="Open command palette">
        <SearchOutlined />
        <span>Jump to workspace</span>
        <kbd>{navigator.platform.toLowerCase().includes('mac') ? '⌘ K' : 'Ctrl K'}</kbd>
      </button>

      <div className="soc-topbar-actions">
        <div className="soc-live-pill" title="Panel session active">
          <i />
          <span>SOC ONLINE</span>
        </div>

        {user && (
          <div className="soc-user-chip" title={`${identity} · ${user.role}`}>
            <span className="soc-user-avatar">{initial}</span>
            <span className="soc-user-copy">
              <strong>{identity}</strong>
              <small>{user.role}</small>
            </span>
          </div>
        )}

        <Tooltip title={`Switch to ${nextDensity} density`}>
          <button
            type="button"
            className={`panel-theme-btn soc-density-btn is-${density}`}
            onClick={() => setDensity(nextDensity)}
            aria-label={`Switch to ${nextDensity} density`}
            aria-pressed={density === 'compact'}
          >
            <ColumnHeightOutlined />
          </button>
        </Tooltip>

        <Tooltip title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
          <button
            type="button"
            className="panel-theme-btn"
            onClick={toggleTheme}
            aria-label={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {mode === 'dark' ? <SunOutlined /> : <MoonOutlined />}
          </button>
        </Tooltip>
        <Tooltip title="Sign out">
          <button
            type="button"
            className="panel-theme-btn"
            onClick={signOut}
            aria-label="Sign out"
          >
            <LogoutOutlined />
          </button>
        </Tooltip>
      </div>
    </AntHeader>
  );
};

export default Header;
