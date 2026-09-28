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
  CodeOutlined,
  DatabaseOutlined,
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
  const activeStep = plan.findIndex((step) => step.status === 'running');

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
        width={960}
        className="automated-investigation-modal"
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
          className="investigation-demo-alert"
        />

        <section className="investigation-run-summary">
          <div className="investigation-run-identity">
            <span className="investigation-run-icon"><DatabaseOutlined /></span>
            <div>
              <Text strong>{alert.signature || 'Security alert'}</Text>
              <Text type="secondary">
                {alert.host ? `Host: ${alert.host}` : 'Host unavailable'} · Alert: {alert.alertId}
              </Text>
            </div>
          </div>
          <div className="investigation-run-counters">
            <div><span>PLAYBOOK STEPS</span><strong>{plan.length || steps.length}</strong></div>
            <div><span>COMPLETED</span><strong>{completed}</strong></div>
            <div><span>MODE</span><strong>DEMO</strong></div>
          </div>
        </section>

        <div className="investigation-progress-row">
          <div>
            <Text strong>{running ? `Running step ${activeStep + 1} of ${plan.length}` : percent === 100 ? 'Investigation complete' : 'Ready to investigate'}</Text>
            <Text type="secondary">Sequential playbook execution</Text>
          </div>
          <span>{percent}%</span>
        </div>
        <Progress
          percent={percent}
          showInfo={false}
          status={running ? 'active' : percent === 100 ? 'success' : 'normal'}
          className="investigation-progress"
        />

        <div className="investigation-step-list">
          {plan.map((step, index) => (
            <Card
              key={step.id}
              size="small"
              className={`investigation-step-card is-${step.status}`}
              title={
                <div className="investigation-step-title">
                  <span className="investigation-step-index">{String(index + 1).padStart(2, '0')}</span>
                  <span className="investigation-step-state">
                    {step.status === 'completed'
                      ? <CheckCircleOutlined />
                      : step.status === 'running'
                        ? <Spin size="small" />
                        : <ClockCircleOutlined />}
                  </span>
                  <span>{step.title}</span>
                </div>
              }
              extra={<StepTag status={step.status} />}
            >
              {step.status === 'pending' && (
                <div className="investigation-step-placeholder">
                  <Text type="secondary">Waiting for the previous investigation step.</Text>
                </div>
              )}

              {step.status === 'running' && (
                <div className="investigation-step-running">
                  <Spin size="small" />
                  <div>
                    <Text strong>Preparing demo Splunk search</Text>
                    <Text type="secondary">Collecting and normalizing evidence for this investigation step.</Text>
                  </div>
                </div>
              )}

              {step.status === 'completed' && (
                <div className="investigation-evidence-grid">
                  <section className="investigation-evidence-block query-block">
                    <div className="investigation-evidence-heading"><CodeOutlined /><span>DEMO SPL</span></div>
                    <Paragraph code copyable className="investigation-query-code">
                      {step.query}
                    </Paragraph>
                  </section>

                  <section className="investigation-evidence-block result-block">
                    <div className="investigation-evidence-heading"><DatabaseOutlined /><span>RETURNED FINDINGS</span></div>
                    <div className="investigation-result-list">
                      {(step.result || []).map((line, lineIndex) => (
                        <div key={lineIndex}><i /> <span>{line}</span></div>
                      ))}
                    </div>
                  </section>

                  <Divider className="investigation-step-divider" />

                  <section className="investigation-analysis-block">
                    <span>STEP ANALYSIS</span>
                    <Paragraph>{step.analysis}</Paragraph>
                  </section>
                </div>
              )}
            </Card>
          ))}
        </div>

        {finalAnalysis && (
          <Card title="Final Investigation Analysis" className="investigation-final-card">
            <div className="investigation-final-head">
              <Tag color="orange">DEMO ASSESSMENT</Tag>
              <Text type="secondary">Generated after all configured checks completed</Text>
            </div>
            <Paragraph>{finalAnalysis}</Paragraph>
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
