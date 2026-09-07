import React from 'react';
import { Layout, Menu } from 'antd';
import {
  BarChartOutlined,
  DashboardOutlined,
  FileTextOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';

const { Sider } = Layout;

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
    { key: '/dashboard', icon: <DashboardOutlined />, label: 'Command Center' },
    { key: '/alerts', icon: <FileTextOutlined />, label: 'Alerts' },
    { key: '/mitre-coverage', icon: <RadarChartOutlined />, label: 'MITRE Coverage' },
    { key: '/analytics', icon: <BarChartOutlined />, label: 'Analytics' },
    { key: '/settings', icon: <SettingOutlined />, label: 'Settings' },
  ];

  return (
    <Sider
      collapsible
      collapsed={collapsed}
      onCollapse={setCollapsed}
      theme="dark"
      width={232}
      collapsedWidth={76}
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

      <div className="soc-nav-label">{collapsed ? '•••' : 'OPERATIONS'}</div>
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
        items={menuItems}
        onClick={({ key }) => navigate(key)}
        className="soc-nav"
      />

      <div className="soc-sidebar-footer">
        {!collapsed && <div className="soc-version-chip"><span /> ENGINE V1</div>}
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
