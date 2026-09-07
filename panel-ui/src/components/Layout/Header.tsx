import React from 'react';
import { Layout, Tag, Typography } from 'antd';
import { MoonOutlined, SunOutlined } from '@ant-design/icons';
import { useLocation } from 'react-router-dom';
import { useTheme } from '../../hooks/useTheme';

const { Header: AntHeader } = Layout;
const { Text } = Typography;

const PAGE_META: Record<string, { eyebrow: string; title: string }> = {
  '/dashboard': { eyebrow: 'OPERATIONS', title: 'Command Center' },
  '/alerts': { eyebrow: 'DETECTION', title: 'Security Alerts' },
  '/mitre-coverage': { eyebrow: 'DETECTION ENGINE', title: 'MITRE ATT&CK Coverage' },
  '/analytics': { eyebrow: 'ANALYTICS', title: 'Security Analytics' },
  '/settings': { eyebrow: 'SYSTEM', title: 'Settings' },
};

const Header: React.FC<{ collapsed: boolean }> = ({ collapsed }) => {
  const { mode, toggleTheme } = useTheme();
  const location = useLocation();
  const meta = PAGE_META[location.pathname] || { eyebrow: 'SOC', title: 'Security Operations Center' };

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
      </div>
    </AntHeader>
  );
};

export default Header;
