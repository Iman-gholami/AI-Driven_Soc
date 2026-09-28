import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Input, Modal, Typography } from 'antd';
import {
  BarChartOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  FileTextOutlined,
  RadarChartOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router-dom';

const { Text } = Typography;

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

const destinations = [
  { path: '/dashboard', title: 'Command Center', hint: 'Operational overview', icon: <DashboardOutlined />, keywords: 'dashboard overview command center posture' },
  { path: '/alerts', title: 'Alerts', hint: 'Detection & investigation queue', icon: <FileTextOutlined />, keywords: 'alerts detections investigations splunk siem' },
  { path: '/reports', title: 'Reports', hint: 'Historical threat intelligence', icon: <FileSearchOutlined />, keywords: 'reports intelligence historical documents' },
  { path: '/mitre-coverage', title: 'MITRE Coverage', hint: 'ATT&CK detection coverage', icon: <RadarChartOutlined />, keywords: 'mitre attack coverage detection rules techniques' },
  { path: '/analytics', title: 'Analytics', hint: 'Security analytics workspace', icon: <BarChartOutlined />, keywords: 'analytics trends metrics' },
  { path: '/settings', title: 'Settings', hint: 'System configuration', icon: <SettingOutlined />, keywords: 'settings system configuration integrations' },
];

const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onClose }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<React.ElementRef<typeof Input>>(null);

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return destinations;
    return destinations.filter((item) => `${item.title} ${item.hint} ${item.keywords}`.toLowerCase().includes(needle));
  }, [query]);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setActiveIndex(0);
    window.setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  useEffect(() => {
    setActiveIndex((current) => Math.min(current, Math.max(0, matches.length - 1)));
  }, [matches.length]);

  const go = (path: string) => {
    onClose();
    if (path !== location.pathname) navigate(path);
  };

  return (
    <Modal
      open={open}
      onCancel={onClose}
      footer={null}
      closable={false}
      centered={false}
      width={620}
      className="soc-command-modal"
      styles={{ mask: { backdropFilter: 'blur(5px)' } }}
    >
      <div className="soc-command-shell">
        <div className="soc-command-search">
          <SearchOutlined />
          <Input
            ref={inputRef}
            variant="borderless"
            value={query}
            placeholder="Jump to a workspace…"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowDown') {
                event.preventDefault();
                setActiveIndex((current) => Math.min(current + 1, matches.length - 1));
              } else if (event.key === 'ArrowUp') {
                event.preventDefault();
                setActiveIndex((current) => Math.max(current - 1, 0));
              } else if (event.key === 'Enter' && matches[activeIndex]) {
                event.preventDefault();
                go(matches[activeIndex].path);
              } else if (event.key === 'Escape') {
                onClose();
              }
            }}
          />
          <kbd>ESC</kbd>
        </div>

        <div className="soc-command-section-label">WORKSPACES</div>
        <div className="soc-command-results">
          {matches.map((item, index) => (
            <button
              type="button"
              key={item.path}
              className={`soc-command-item ${index === activeIndex ? 'is-active' : ''}`}
              onMouseEnter={() => setActiveIndex(index)}
              onClick={() => go(item.path)}
            >
              <span className="soc-command-icon">{item.icon}</span>
              <span className="soc-command-copy">
                <strong>{item.title}</strong>
                <small>{item.hint}</small>
              </span>
              {item.path === location.pathname ? <Text className="soc-command-current">CURRENT</Text> : <span className="soc-command-arrow">↵</span>}
            </button>
          ))}
          {!matches.length && (
            <div className="soc-command-empty">
              <SearchOutlined />
              <strong>No workspace found</strong>
              <span>Try alerts, reports, MITRE, or dashboard.</span>
            </div>
          )}
        </div>

        <div className="soc-command-footer">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span>Command palette</span>
        </div>
      </div>
    </Modal>
  );
};

export default CommandPalette;
