import React from 'react';
import { Layout, Menu, Tooltip } from 'antd';
import {
  BarChartOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  FileTextOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';

const { Sider } = Layout;

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
  onOpenCommand: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed, onOpenCommand }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const operations = [
    { key: '/dashboard', icon: <DashboardOutlined />, label: 'Command Center' },
    { key: '/alerts', icon: <FileTextOutlined />, label: 'Alerts' },
  ];
  const intelligence = [
    { key: '/reports', icon: <FileSearchOutlined />, label: 'Reports' },
    { key: '/mitre-coverage', icon: <RadarChartOutlined />, label: 'MITRE Coverage' },
  ];
  const platform = [
    { key: '/analytics', icon: <BarChartOutlined />, label: 'Analytics' },
    { key: '/settings', icon: <SettingOutlined />, label: 'Settings' },
  ];

  const menu = (items: typeof operations) => (
    <Menu
      theme="dark"
      mode="inline"
      selectedKeys={[location.pathname]}
      items={items}
      onClick={({ key }) => navigate(key)}
      className="soc-nav"
    />
  );

  return (
    <Sider
      collapsible
      collapsed={collapsed}
      onCollapse={setCollapsed}
      theme="dark"
      width={232}
      collapsedWidth={76}
      breakpoint="lg"
      onBreakpoint={(broken) => { if (broken) setCollapsed(true); }}
      className="soc-sidebar"
      trigger={null}
    >
      <div className={'soc-brand' + (collapsed ? ' is-collapsed' : '')}>
        <div className="soc-brand-mark"><SafetyCertificateOutlined /></div>
        {!collapsed && (
          <div className="soc-brand-copy">
            <strong>AI-Driven SOC</strong>
            <span>Security Operations</span>
          </div>
        )}
      </div>

      <div className="soc-nav-scroll">
        <div className="soc-nav-label">{collapsed ? '•••' : 'OPERATIONS'}</div>
        {menu(operations)}
        <div className="soc-nav-label">{collapsed ? '•••' : 'INTELLIGENCE'}</div>
        {menu(intelligence)}
        <div className="soc-nav-label">{collapsed ? '•••' : 'PLATFORM'}</div>
        {menu(platform)}
      </div>

      <div className="soc-sidebar-footer">
        {!collapsed ? (
          <button type="button" className="soc-sidebar-command" onClick={onOpenCommand}>
            <SearchOutlined />
            <span>Quick switch</span>
            <kbd>⌘K</kbd>
          </button>
        ) : (
          <Tooltip title="Quick switch (Ctrl/Cmd + K)" placement="right">
            <button type="button" className="soc-sidebar-command is-icon" onClick={onOpenCommand} aria-label="Quick switch">
              <SearchOutlined />
            </button>
          </Tooltip>
        )}
        <button
          type="button"
          onClick={() => setCollapsed(!collapsed)}
          className="soc-collapse-btn"
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        >
          {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
        </button>
      </div>
    </Sider>
  );
};

export default Sidebar;
