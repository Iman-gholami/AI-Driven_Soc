import React from 'react';
import { Layout, Tag, Typography } from 'antd';
import { LogoutOutlined, MoonOutlined, SunOutlined } from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTheme } from '../../hooks/useTheme';
import { useAuth } from '../../auth/AuthContext';

const { Header: AntHeader } = Layout;
const { Text } = Typography;

const PAGE_META: Record<string, { eyebrow: string; title: string }> = {
  '/dashboard': { eyebrow: 'OPERATIONS', title: 'Overview' },
  '/alerts': { eyebrow: 'DETECTION', title: 'Investigation queue' },
  '/reports': { eyebrow: 'INTELLIGENCE', title: 'Historical reports' },
  '/mitre-coverage': { eyebrow: 'DETECTION ENGINE', title: 'ATT&CK matrix' },
  '/analytics': { eyebrow: 'ANALYTICS', title: 'Workspace' },
  '/settings': { eyebrow: 'SYSTEM', title: 'Configuration' },
};

const Header: React.FC<{ collapsed: boolean }> = ({ collapsed }) => {
  const { mode, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const meta = PAGE_META[location.pathname] || { eyebrow: 'SOC', title: 'Security Operations Center' };

  const signOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <AntHeader
      className="soc-topbar"
      style={{ left: collapsed ? 76 : 232 }}
    >
      <div className="soc-topbar-title">
        <span>{meta.eyebrow}</span>
        <strong>{meta.title}</strong>
      </div>

      <div className="soc-topbar-actions">
        {user && <Tag className="soc-topbar-tag">{user.displayName || user.username} · {user.role}</Tag>}
        <Tag className="soc-topbar-tag">V1</Tag>
        <Text type="secondary" className="soc-theme-label">
          {mode === 'dark' ? 'Dark' : 'Light'}
        </Text>
        <button
          type="button"
          className="panel-theme-btn"
          onClick={toggleTheme}
          aria-label={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {mode === 'dark' ? <SunOutlined /> : <MoonOutlined />}
        </button>
        <button
          type="button"
          className="panel-theme-btn"
          onClick={signOut}
          aria-label="Sign out"
          title="Sign out"
        >
          <LogoutOutlined />
        </button>
      </div>
    </AntHeader>
  );
};

export default Header;
