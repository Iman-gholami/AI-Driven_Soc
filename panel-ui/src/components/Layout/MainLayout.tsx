import React, { useEffect, useState } from 'react';
import { Layout, Spin } from 'antd';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import SocCopilot from '../AI/SocCopilot';

const { Content } = Layout;
const EXPANDED_WIDTH = 232;
const COLLAPSED_WIDTH = 76;

const MainLayout: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const sidebarWidth = collapsed ? COLLAPSED_WIDTH : EXPANDED_WIDTH;

  useEffect(() => {
    setLoading(true);
    const timer = window.setTimeout(() => setLoading(false), 180);
    return () => window.clearTimeout(timer);
  }, [location.pathname]);

  return (
    <Layout className="soc-shell">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <Layout className="soc-main-layout" style={{ marginLeft: sidebarWidth }}>
        <Header collapsed={collapsed} />
        <Content className="soc-content">
          <Spin spinning={loading} size="large">
            <div className="soc-route-content">
              <Outlet />
            </div>
          </Spin>
        </Content>
      </Layout>
      <SocCopilot />
    </Layout>
  );
};

export default MainLayout;
