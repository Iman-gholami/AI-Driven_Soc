import React, { useEffect, useState } from 'react';
import { Layout } from 'antd';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import CommandPalette from './CommandPalette';
import SocCopilot from '../AI/SocCopilot';

const { Content } = Layout;
const EXPANDED_WIDTH = 232;
const COLLAPSED_WIDTH = 76;

const MainLayout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const sidebarWidth = collapsed ? COLLAPSED_WIDTH : EXPANDED_WIDTH;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen((current) => !current);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  return (
    <Layout className="soc-shell">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} onOpenCommand={() => setCommandOpen(true)} />
      <Layout className="soc-main-layout" style={{ marginLeft: sidebarWidth }}>
        <Header collapsed={collapsed} onOpenCommand={() => setCommandOpen(true)} />
        <Content className="soc-content">
          <div className="soc-route-content">
            <Outlet />
          </div>
        </Content>
      </Layout>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />
      <SocCopilot />
    </Layout>
  );
};

export default MainLayout;
