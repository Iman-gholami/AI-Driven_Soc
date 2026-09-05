import React, { useEffect, useState } from 'react';
import { Layout, Spin } from 'antd';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

const { Content } = Layout;

const MainLayout: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setLoading(true);
    const timer = window.setTimeout(() => setLoading(false), 250);
    return () => window.clearTimeout(timer);
  }, [location.pathname]);

  return <Layout className="min-h-screen"><Sidebar collapsed={collapsed} setCollapsed={setCollapsed} /><Layout style={{ marginLeft: collapsed ? 80 : 220, transition: 'margin-left 0.2s ease-in-out', background: 'transparent' }}><Header collapsed={collapsed} /><Content style={{ marginTop: 64, padding: 24, minHeight: 'calc(100vh - 64px)' }}><Spin spinning={loading} size="large"><div className="min-h-[calc(100vh-120px)]"><Outlet /></div></Spin></Content></Layout></Layout>;
};

export default MainLayout;
