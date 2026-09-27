import React, { useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Divider,
  Modal,
  Progress,
  Space,
  Spin,
  Tag,
  Typography,
} from 'antd';
import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  ExperimentOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import type { Alert as AlertType } from '../../types';

const { Text, Paragraph } = Typography;

type StepStatus = 'pending' | 'running' | 'completed';

interface DemoStep {
  id: string;
  title: string;
  status: StepStatus;
  query?: string;
  result?: string[];
  analysis?: string;
}

interface Props {
  alert: AlertType;
  steps: unknown[];
}

const AutomatedInvestigationDemo: React.FC<Props> = ({ alert, steps }) => {
  const [open, setOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [plan, setPlan] = useState<DemoStep[]>([]);
  const [finalAnalysis, setFinalAnalysis] = useState('');
  const runToken = useRef(0);

  const runDemo = async () => {
    const token = ++runToken.current;
    const initialPlan = buildPlan(steps);

    setOpen(true);
    setRunning(true);
    setFinalAnalysis('');
    setPlan(initialPlan);

    for (let index = 0; index < initialPlan.length; index += 1) {
      if (token !== runToken.current) return;

      setPlan((current) => current.map((step, stepIndex) => (
        stepIndex === index ? { ...step, status: 'running' } : step
      )));

      await wait(900);
      if (token !== runToken.current) return;

      const output = buildDemoOutput(alert, initialPlan[index].title, index);
      setPlan((current) => current.map((step, stepIndex) => (
        stepIndex === index
          ? {
              ...step,
              status: 'completed',
              query: output.query,
              result: output.result,
              analysis: output.analysis,
            }
          : step
      )));

      await wait(550);
    }

    if (token !== runToken.current) return;
    setFinalAnalysis(buildFinalAnalysis(alert, initialPlan.length));
    setRunning(false);
  };

  const close = () => {
    runToken.current += 1;
    setRunning(false);
    setOpen(false);
  };

  const completed = plan.filter((step) => step.status === 'completed').length;
  const percent = plan.length ? Math.round((completed / plan.length) * 100) : 0;

  return (
    <>
      <Button
        type="primary"
        icon={<PlayCircleOutlined />}
        onClick={runDemo}
        disabled={!steps.length}
      >
        Run Investigation
      </Button>

      <Modal
        title={
          <Space>
            <ExperimentOutlined />
            Automated Investigation
            <Tag color="gold">DEMO</Tag>
          </Space>
        }
        open={open}
        onCancel={close}
        width={900}
        footer={[
          <Button key="close" onClick={close}>Close</Button>,
          <Button
            key="rerun"
            icon={<ReloadOutlined />}
            onClick={runDemo}
            disabled={running}
          >
            Run again
          </Button>,
        ]}
      >
        <Alert
          type="warning"
          showIcon
          message="Demo / test mode"
          description="No real Splunk search is executed yet. The runner simulates each investigation step so the workflow and UI can be validated before real playbooks are connected."
          style={{ marginBottom: 16 }}
        />

        <Space direction="vertical" style={{ width: '100%' }} size={4}>
          <Text strong>{alert.signature || 'Security alert'}</Text>
          <Text type="secondary">
            {alert.host ? `Host: ${alert.host}` : 'Host unavailable'} · Alert: {alert.alertId}
          </Text>
        </Space>

        <Progress
          percent={percent}
          status={running ? 'active' : percent === 100 ? 'success' : 'normal'}
          style={{ marginTop: 14, marginBottom: 14 }}
        />

        <div style={{ display: 'grid', gap: 10 }}>
          {plan.map((step, index) => (
            <Card
              key={step.id}
              size="small"
              title={
                <Space>
                  {step.status === 'completed'
                    ? <CheckCircleOutlined />
                    : step.status === 'running'
                      ? <Spin size="small" />
                      : <ClockCircleOutlined />}
                  <span>{index + 1}. {step.title}</span>
                </Space>
              }
              extra={<StepTag status={step.status} />}
            >
              {step.status === 'pending' && (
                <Text type="secondary">Waiting for the previous investigation step.</Text>
              )}

              {step.status === 'running' && (
                <Space direction="vertical" size={4}>
                  <Text>Preparing demo Splunk search...</Text>
                  <Text type="secondary">Collecting evidence for this investigation step.</Text>
                </Space>
              )}

              {step.status === 'completed' && (
                <>
                  <Text strong>Demo SPL</Text>
                  <Paragraph
                    code
                    copyable
                    style={{ display: 'block', whiteSpace: 'pre-wrap', marginTop: 6 }}
                  >
                    {step.query}
                  </Paragraph>

                  <Divider style={{ marginBlock: 12 }} />
                  <Text strong>Result</Text>
                  <div style={{ marginTop: 6 }}>
                    {(step.result || []).map((line, lineIndex) => (
                      <div key={lineIndex}>• {line}</div>
                    ))}
                  </div>

                  <Divider style={{ marginBlock: 12 }} />
                  <Text strong>Analysis</Text>
                  <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 6, marginBottom: 0 }}>
                    {step.analysis}
                  </Paragraph>
                </>
              )}
            </Card>
          ))}
        </div>

        {finalAnalysis && (
          <Card title="Final Investigation Analysis" style={{ marginTop: 16 }}>
            <Tag color="orange">DEMO ASSESSMENT</Tag>
            <Paragraph style={{ whiteSpace: 'pre-wrap', marginTop: 10, marginBottom: 0 }}>
              {finalAnalysis}
            </Paragraph>
          </Card>
        )}
      </Modal>
    </>
  );
};

function StepTag({ status }: { status: StepStatus }) {
  if (status === 'completed') return <Tag color="success">Completed</Tag>;
  if (status === 'running') return <Tag color="processing">In progress</Tag>;
  return <Tag>Pending</Tag>;
}

function buildPlan(steps: unknown[]): DemoStep[] {
  return steps.slice(0, 8).map((step, index) => ({
    id: `demo-step-${index + 1}`,
    title: typeof step === 'string' ? step : safeString(step),
    status: 'pending',
  }));
}

function buildDemoOutput(alert: AlertType, title: string, index: number) {
  const lower = title.toLowerCase();
  const host = splunkValue(alert.host || 'affected-host');
  const ip = splunkValue(findCandidateIp(alert) || '198.51.100.25');
  const window = 'earliest=-15m latest=+15m';

  if (/(process|endpoint|activex|execution|edr|host)/.test(lower)) {
    return {
      query: `index=endpoint host="${host}" ${window}\n| table _time host process_name parent_process command_line\n| sort _time`,
      result: [
        `${12 + index * 3} endpoint events returned for ${alert.host || 'the affected host'}.`,
        'Process activity was observed inside the alert investigation window.',
        'One child-process chain would be highlighted for analyst review in the real integration.',
      ],
      analysis: 'The demo endpoint evidence shows activity close to the alert time. In the production playbook this step will evaluate the real process tree, parent/child relationships, command line and endpoint telemetry before assigning a finding.',
    };
  }

  if (/(browser|http|web|application|url)/.test(lower)) {
    return {
      query: `index=proxy OR index=web host="${host}" ${window}\n| table _time host src_ip dest_ip url status user_agent\n| sort _time`,
      result: [
        `${8 + index * 4} web/application events returned.`,
        `Traffic related to ${ip} is represented in the demo result set.`,
        'Request timing can be correlated with the original alert event.',
      ],
      analysis: 'The demo indicates that browser or application telemetry can be correlated with the alert. The real playbook will determine whether the requested content, response, user agent and timing support or weaken the original detection.',
    };
  }

  if (/(correlat|other alert|telemetry|follow-up|related)/.test(lower)) {
    return {
      query: `index=* host="${host}" ${window}\n| stats count values(signature) as signatures values(sourcetype) as sources by host\n| sort - count`,
      result: [
        `${2 + index} related demo events/alerts grouped around the same host.`,
        'Multiple telemetry sources are available for correlation.',
        'The demo timeline places related activity inside the same investigation window.',
      ],
      analysis: 'The simulated correlation step shows how multiple alerts and telemetry sources will be grouped into a single investigation context. In production, only evidence returned by Splunk will be used for the correlation conclusion.',
    };
  }

  if (/(source ip|destination ip|\bip\b|threat|reputation|known benign|test system)/.test(lower)) {
    return {
      query: `index=* (src_ip="${ip}" OR dest_ip="${ip}") earliest=-24h latest=now\n| stats count dc(host) as hosts values(signature) as signatures by src_ip dest_ip`,
      result: [
        `Demo lookup completed for IP ${ip}.`,
        `${4 + index * 2} matching historical events would be reviewed.`,
        'No production reputation verdict is assigned in demo mode.',
      ],
      analysis: 'This step demonstrates the IP validation workflow without inventing a real reputation result. The production version will combine Splunk observations with the project threat-intelligence and asset context before presenting a conclusion.',
    };
  }

  return {
    query: `index=* alert_id="${splunkValue(alert.alertId)}" ${window}\n| table _time host source sourcetype signature _raw\n| sort _time`,
    result: [
      `${10 + index * 5} demo events returned for the requested investigation check.`,
      'Relevant fields were normalized for analyst review.',
      'The result is mock data and is not evidence from Splunk.',
    ],
    analysis: 'The investigation runner completed this demo step and produced a structured result. When a real playbook is connected, this section will contain the analysis of the actual Splunk response for this specific check.',
  };
}

function buildFinalAnalysis(alert: AlertType, stepCount: number) {
  return [
    `Demo investigation completed ${stepCount} of ${stepCount} configured checks for ${alert.signature || alert.alertId}.`,
    '',
    'The workflow successfully demonstrated sequential execution, per-step query visibility, returned findings and step-level analysis.',
    '',
    'This is not a security verdict. No real Splunk data was queried. After production playbooks are defined, the same UI can execute those searches and the final analysis will be generated only from returned evidence.',
  ].join('\n');
}

function findCandidateIp(alert: AlertType) {
  const intelIp = alert.soc?.networkIntelligence?.ips?.[0]?.ip;
  if (intelIp) return intelIp;

  const raw = JSON.stringify(alert.rawEvent || {});
  const match = raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match?.[0] || null;
}

function splunkValue(value: string) {
  return value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
}

function safeString(value: unknown) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function wait(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export default AutomatedInvestigationDemo;
