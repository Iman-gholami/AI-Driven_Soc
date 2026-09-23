import React, { useState } from 'react';
import { Layout } from 'antd';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import SocCopilot from '../AI/SocCopilot';

const { Content } = Layout;
const EXPANDED_WIDTH = 232;
const COLLAPSED_WIDTH = 76;

const MainLayout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const sidebarWidth = collapsed ? COLLAPSED_WIDTH : EXPANDED_WIDTH;

  return (
    <Layout className="soc-shell">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <Layout className="soc-main-layout" style={{ marginLeft: sidebarWidth }}>
        <Header collapsed={collapsed} />
        <Content className="soc-content">
          <div className="soc-route-content">
            <Outlet />
          </div>
        </Content>
      </Layout>
      <SocCopilot />
    </Layout>
  );
};

export default MainLayout;
