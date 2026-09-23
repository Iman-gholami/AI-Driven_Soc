import React, { useMemo, useState } from 'react';
import { Alert, Button, Checkbox, Form, Input, Typography } from 'antd';
import {
  ArrowRightOutlined,
  AuditOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { getErrorMessage } from '../../api/client';
import { useAuth } from '../../auth/AuthContext';
import './Login.css';

const { Text } = Typography;

interface LoginFormValues {
  username: string;
  password: string;
  otp?: string;
  remember?: boolean;
}

const Login: React.FC = () => {
  const { isAuthenticated, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const destination = useMemo(() => {
    const state = location.state as { from?: string } | null;
    return state?.from && state.from.startsWith('/') ? state.from : '/dashboard';
  }, [location.state]);

  if (isAuthenticated) return <Navigate to={destination} replace />;

  const onFinish = async (values: LoginFormValues) => {
    setError(null);
    setSubmitting(true);
    try {
      await login({
        username: values.username,
        password: values.password,
        otp: values.otp || '',
        remember: Boolean(values.remember),
      });
      navigate(destination, { replace: true });
    } catch (requestError) {
      setError(getErrorMessage(requestError, 'Sign-in failed. Check your credentials and try again.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="soc-login-shell">
      <div className="soc-login-grid" aria-hidden="true" />
      <div className="soc-login-glow soc-login-glow-one" aria-hidden="true" />
      <div className="soc-login-glow soc-login-glow-two" aria-hidden="true" />

      <div className="soc-login-status">
        <span className="soc-login-status-dot" />
        <span>System Online</span>
      </div>

      <div className="soc-login-tagline">Secure today. Resilient tomorrow.</div>

      <section className="soc-login-hero">
        <div className="soc-login-kicker">AI-DRIVEN SECURITY OPERATIONS</div>
        <h1>
          <span>SOC</span> Command Portal
        </h1>
        <p className="soc-login-subtitle">See faster. Respond smarter. Protect everything.</p>

        <div className="soc-login-features">
          <article>
            <div className="soc-login-feature-icon"><TeamOutlined /></div>
            <strong>Role-Based Access</strong>
            <span>Controlled workspace permissions</span>
          </article>
          <article>
            <div className="soc-login-feature-icon"><AuditOutlined /></div>
            <strong>Audit-Ready Login Logs</strong>
            <span>Security events recorded by design</span>
          </article>
          <article>
            <div className="soc-login-feature-icon"><SafetyCertificateOutlined /></div>
            <strong>Multi-Factor Ready</strong>
            <span>Optional one-time-code validation</span>
          </article>
        </div>

        <div className="soc-login-orbit" aria-hidden="true">
          <div className="soc-login-earth" />
          <span className="soc-login-node node-a" />
          <span className="soc-login-node node-b" />
          <span className="soc-login-node node-c" />
          <span className="soc-login-node node-d" />
          <div className="soc-login-orbit-ring ring-a" />
          <div className="soc-login-orbit-ring ring-b" />
        </div>

        <div className="soc-login-hud">
          <span>DETECT</span>
          <span>INVESTIGATE</span>
          <span>RESPOND</span>
          <span>HUNT</span>
          <span>CONTAIN</span>
          <span>RECOVER</span>
        </div>

        <div className="soc-login-telemetry-card">
          <div>
            <span>SECURITY OPERATIONS</span>
            <strong>Continuous monitoring</strong>
          </div>
          <div className="soc-login-bars" aria-hidden="true">
            {[42, 58, 36, 76, 52, 88, 65, 94, 71, 84].map((height, index) => (
              <i key={index} style={{ height: `${height}%` }} />
            ))}
          </div>
        </div>

        <footer className="soc-login-hero-footer">
          <span>Continuous monitoring for mission-critical environments.</span>
          <small>Security is not optional.</small>
        </footer>
      </section>

      <section className="soc-login-panel-wrap">
        <div className="soc-login-panel">
          <div className="soc-login-panel-accent" aria-hidden="true" />
          <div className="soc-login-panel-kicker">SECURE ACCESS</div>
          <h2>Sign in to your workspace</h2>
          <p className="soc-login-panel-copy">
            Authorized analysts only. Access to security operations is continuously monitored.
          </p>

          {error && (
            <Alert
              type="error"
              showIcon
              closable
              onClose={() => setError(null)}
              message={error}
              className="soc-login-alert"
            />
          )}

          <Form<LoginFormValues>
            layout="vertical"
            onFinish={onFinish}
            requiredMark={false}
            autoComplete="off"
            className="soc-login-form"
            initialValues={{ remember: false }}
          >
            <Form.Item
              name="username"
              label="Username"
              rules={[{ required: true, message: 'Enter your username' }]}
            >
              <Input
                size="large"
                prefix={<UserOutlined />}
                placeholder="Enter your username"
                autoComplete="username"
              />
            </Form.Item>

            <Form.Item
              name="password"
              label="Password"
              rules={[{ required: true, message: 'Enter your password' }]}
            >
              <Input.Password
                size="large"
                prefix={<LockOutlined />}
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </Form.Item>

            <Form.Item name="otp" label="One-Time Code">
              <Input
                size="large"
                prefix={<SafetyCertificateOutlined />}
                placeholder="Enter OTP if enabled"
                inputMode="numeric"
                maxLength={12}
                autoComplete="one-time-code"
              />
            </Form.Item>

            <div className="soc-login-form-row">
              <Form.Item name="remember" valuePropName="checked" noStyle>
                <Checkbox>Remember this device</Checkbox>
              </Form.Item>
              <Text type="secondary">Encrypted bearer session</Text>
            </div>

            <Button
              htmlType="submit"
              type="primary"
              size="large"
              loading={submitting}
              className="soc-login-submit"
              icon={<ArrowRightOutlined />}
            >
              Access Dashboard
            </Button>
          </Form>

          <div className="soc-login-restricted">
            <LockOutlined />
            Restricted to authorized users
          </div>

          <div className="soc-login-security-strip">
            <div><SafetyCertificateOutlined /><span>MFA</span></div>
            <div><AuditOutlined /><span>Audit Logs</span></div>
            <div><TeamOutlined /><span>RBAC</span></div>
          </div>

          <div className="soc-login-monitoring-note">
            <span className="soc-login-pulse" />
            All sign-ins are monitored and recorded.
          </div>
        </div>
      </section>
    </main>
  );
};

export default Login;
