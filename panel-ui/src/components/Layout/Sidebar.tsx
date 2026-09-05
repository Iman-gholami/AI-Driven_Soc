import React from 'react';
import { Layout, Menu } from 'antd';
import { DashboardOutlined, FileTextOutlined, SettingOutlined, MenuFoldOutlined, MenuUnfoldOutlined, BarChartOutlined } from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';

const { Sider } = Layout;

interface SidebarProps { collapsed: boolean; setCollapsed: (collapsed: boolean) => void; }

const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const menuItems = [
    { key: '/dashboard', icon: <DashboardOutlined />, label: 'Dashboard' },
    { key: '/alerts', icon: <FileTextOutlined />, label: 'Alerts' },
    { key: '/analytics', icon: <BarChartOutlined />, label: 'Analytics' },
    { key: '/settings', icon: <SettingOutlined />, label: 'Settings' },
  ];
  return <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark" width={220} collapsedWidth={80} style={{ height: '100vh', position: 'fixed', left: 0, top: 0, bottom: 0, zIndex: 1000 }} trigger={null}>
    <div className="h-16 flex items-center justify-center text-white text-lg font-bold border-b border-gray-700">{collapsed ? 'SOC' : 'AI-Driven SOC'}</div>
    <Menu theme="dark" mode="inline" selectedKeys={[location.pathname]} items={menuItems} onClick={({ key }) => navigate(key)} className="border-r-0" />
    <div className="absolute bottom-4 left-0 right-0 flex justify-center"><button onClick={() => setCollapsed(!collapsed)} className="text-gray-300 hover:text-white p-2 rounded hover:bg-gray-700 transition-colors">{collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}</button></div>
  </Sider>;
};

export default Sidebar;
