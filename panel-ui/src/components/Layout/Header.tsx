import React from 'react';
import { Layout, Space, Typography, Tag } from 'antd';
import { useTheme } from '../../hooks/useTheme';

const { Header: AntHeader } = Layout;
const { Text } = Typography;

const Header: React.FC<{ collapsed: boolean }> = ({ collapsed: _collapsed }) => {
  const { mode, toggleTheme } = useTheme();
  return <AntHeader style={{ position: 'fixed', top: 0, right: 0, left: 0, zIndex: 900, padding: '0 24px', background: 'var(--panel-header-bg)', borderBottom: '1px solid var(--panel-border)' }}>
    <div className="h-full flex items-center justify-between"><div><Text strong>Security Operations Center</Text><Tag color="green" className="ml-3">V1</Tag></div><Space><Text type="secondary">{mode === 'dark' ? 'Dark' : 'Light'} mode</Text><button className="panel-theme-btn" onClick={toggleTheme}>{mode === 'dark' ? '☀️' : '🌙'}</button></Space></div>
  </AntHeader>;
};

export default Header;
