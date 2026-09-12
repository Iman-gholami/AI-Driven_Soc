import React, { useMemo, useRef, useState } from 'react';
import {
  Alert as AntAlert,
  Button,
  Card,
  Col,
  Collapse,
  Empty,
  Input,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Timeline,
  Typography,
  message,
} from 'antd';
import {
  AimOutlined,
  AlertOutlined,
  CheckCircleOutlined,
  CodeOutlined,
  ExperimentOutlined,
  LoadingOutlined,
  PlayCircleOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  ThunderboltOutlined,
  ToolOutlined,
} from '@ant-design/icons';
import { api } from '../../api/client';
import './ThreatHunting.css';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

type HuntFinding = {
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  summary: string;
  evidenceRefs: string[];
  entities?: string[];
};

type HuntReport = {
  verdict: 'no_significant_finding' | 'suspicious' | 'likely_malicious' | 'inconclusive';
  confidence: number;
  summary: string;
  findings: HuntFinding[];
  recommendedNextSteps: string[];
  limitations: string[];
};

type HuntEvent = {
  type: string;
  huntId?: string;
  step?: number;
  maxSteps?: number;
  rationale?: string;
  tool?: string;
  arguments?: unknown;
  observation?: any;
  report?: HuntReport;
  observations?: any[];
  metadata?: any;
  durationMs?: number;
  terminationReason?: string;
  error?: string;
};

const suggestedHunts = [
  'در 7 روز گذشته رفتار مشکوک شبیه C2 یا beaconing را بررسی کن و مهم‌ترین شواهد را پیدا کن.',
  'بررسی کن کدام IPهای دارای direct threat intelligence در 24 ساعت گذشته روی assetهای داخلی Alert ایجاد کرده‌اند.',
  'به دنبال افزایش غیرعادی Alertهای high یا critical و منابع تکرارشونده در 48 ساعت گذشته بگرد.',
];

const ThreatHunting: React.FC = () => {
  const [goal, setGoal] = useState(suggestedHunts[0]);
  const [maxSteps, setMaxSteps] = useState(6);
  const [events, setEvents] = useState<HuntEvent[]>([]);
  const [report, setReport] = useState<HuntReport | null>(null);
  const [huntMeta, setHuntMeta] = useState<any>(null);
  const [running, setRunning] = useState(false);
  const [huntError, setHuntError] = useState('');
  const abortRef = useRef<AbortController | null>(null);

  const [detection, setDetection] = useState<any>(null);
  const [detectionLoading, setDetectionLoading] = useState(false);
  const [backtestDays, setBacktestDays] = useState(30);

  const [dimension, setDimension] = useState<'signature' | 'host' | 'source' | 'rule'>('signature');
  const [behaviorHours, setBehaviorHours] = useState(24);
  const [baselineDays, setBaselineDays] = useState(7);
  const [behaviorLoading, setBehaviorLoading] = useState(false);
  const [behaviorResult, setBehaviorResult] = useState<any>(null);

  const timelineEvents = useMemo(
    () => events.filter((event) => [
      'step_planned',
      'tool_started',
      'tool_completed',
      'tool_failed',
      'step_rejected',
      'planning_failed',
    ].includes(event.type)),
    [events],
  );

  const completedObservations = useMemo(
    () => events
      .filter((event) => event.type === 'tool_completed' && event.observation)
      .map((event) => event.observation),
    [events],
  );

  const runHunt = async (overrideGoal?: string) => {
    const huntGoal = String(overrideGoal ?? goal).trim();
    if (!huntGoal) return message.warning('Hunt goal is required');
    if (running) return;

    setGoal(huntGoal);
    setEvents([]);
    setReport(null);
    setHuntMeta(null);
    setDetection(null);
    setHuntError('');
    setRunning(true);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await api.streamThreatHunt({
        goal: huntGoal,
        maxSteps,
        signal: controller.signal,
        onEvent: (event: HuntEvent) => {
          setEvents((current) => [...current, event]);
          if (event.type === 'hunt_started') setHuntMeta(event);
          if (event.type === 'hunt_completed') {
            setReport(event.report || null);
            setHuntMeta((current: any) => ({ ...current, ...event }));
          }
          if (event.type === 'hunt_failed') setHuntError(event.error || 'Threat hunt failed');
        },
      });
    } catch (error: any) {
      if (error?.name !== 'AbortError') {
        setHuntError(error?.message || 'Threat hunt failed');
      }
    } finally {
      abortRef.current = null;
      setRunning(false);
    }
  };

  const stopHunt = () => {
    abortRef.current?.abort();
    setRunning(false);
  };

  const generateDetection = async () => {
    if (!report) return;
    setDetectionLoading(true);
    try {
      const result = await api.generateDetectionProposal({ goal, report, days: backtestDays });
      setDetection(result);
      message.success('Draft detection generated and backtested');
    } catch (error: any) {
      message.error(error?.response?.data?.detail || error?.message || 'Detection proposal failed');
    } finally {
      setDetectionLoading(false);
    }
  };

  const scanBehavior = async () => {
    setBehaviorLoading(true);
    try {
      setBehaviorResult(await api.getBehaviorAnomalies({
        dimension,
        hours: behaviorHours,
        baselineDays,
        limit: 20,
      }));
    } catch (error: any) {
      message.error(error?.response?.data?.detail || error?.message || 'Behavior scan failed');
    } finally {
      setBehaviorLoading(false);
    }
  };

  const status = running ? 'RUNNING' : report ? 'COMPLETE' : huntError ? 'FAILED' : 'READY';

  return (
    <main className="hunt-page">
      <header className="hunt-heading">
        <div>
          <div className="hunt-eyebrow"><AimOutlined /> AGENTIC SECURITY OPERATIONS</div>
          <Title level={2}>AI Threat Hunter</Title>
          <Text type="secondary">Autonomous, read-only investigation across validated MCP capabilities with evidence-bound conclusions.</Text>
        </div>
        <div className={`hunt-status is-${status.toLowerCase()}`}>
          <span />
          {status}
        </div>
      </header>

      <Card className="hunt-command-card">
        <div className="hunt-command-grid">
          <div>
            <Text className="hunt-command-label">HUNT GOAL</Text>
            <TextArea
              value={goal}
              onChange={(event) => setGoal(event.target.value)}
              autoSize={{ minRows: 3, maxRows: 6 }}
              disabled={running}
              dir="auto"
              placeholder="Describe what the agent should investigate…"
            />
          </div>
          <div className="hunt-command-actions">
            <Select
              value={maxSteps}
              disabled={running}
              onChange={setMaxSteps}
              options={[4, 6, 8].map((value) => ({ value, label: `${value} max steps` }))}
            />
            {!running ? (
              <Button type="primary" size="large" icon={<PlayCircleOutlined />} onClick={() => void runHunt()}>
                Launch Hunt
              </Button>
            ) : (
              <Button danger size="large" icon={<StopOutlined />} onClick={stopHunt}>
                Stop
              </Button>
            )}
          </div>
        </div>
        <div className="hunt-suggestions">
          {suggestedHunts.map((item) => (
            <button key={item} type="button" disabled={running} onClick={() => setGoal(item)} dir="auto">
              {item}
            </button>
          ))}
        </div>
      </Card>

      {huntError && <AntAlert type="error" showIcon message="Hunt failed" description={huntError} />}

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card
            className="hunt-agent-card"
            title={<span><ThunderboltOutlined /> Live Investigation Stream</span>}
            extra={huntMeta?.metadata?.model ? <Tag>{huntMeta.metadata.model}</Tag> : null}
          >
            {!timelineEvents.length && !running ? (
              <Empty description="Launch a hunt to watch the agent plan, query, observe and refine its hypothesis." />
            ) : (
              <Timeline
                className="hunt-timeline"
                items={timelineEvents.map((event, index) => ({
                  key: `${event.type}-${event.step || index}-${index}`,
                  dot: timelineDot(event),
                  children: <TimelineEvent event={event} />,
                }))}
              />
            )}
            {running && (
              <div className="hunt-thinking">
                <LoadingOutlined spin /> Agent is deciding the next minimum-sufficient investigation step…
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} xl={10}>
          <Card className="hunt-report-card" title={<span><SafetyCertificateOutlined /> Hunt Assessment</span>}>
            {!report ? (
              <div className="hunt-report-empty">
                <RadarChartOutlined />
                <strong>No final assessment yet</strong>
                <span>The verdict appears only after the agent can cite collected SOC evidence.</span>
              </div>
            ) : (
              <HuntReportView report={report} observations={completedObservations} meta={huntMeta} />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Card
            className="hunt-feature-card"
            title={<span><ExperimentOutlined /> Detection Engineer</span>}
            extra={<Tag>draft only</Tag>}
          >
            <Paragraph type="secondary">
              Turn the completed hunt into a constrained detection hypothesis, then backtest it against historical alerts before any human considers deployment.
            </Paragraph>
            <Space wrap>
              <Select
                value={backtestDays}
                onChange={setBacktestDays}
                options={[7, 30, 90].map((value) => ({ value, label: `${value} day backtest` }))}
                style={{ width: 160 }}
              />
              <Button
                type="primary"
                icon={<CodeOutlined />}
                disabled={!report}
                loading={detectionLoading}
                onClick={() => void generateDetection()}
              >
                Generate + Backtest
              </Button>
            </Space>
            {detection && <DetectionResult data={detection} />}
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card className="hunt-feature-card" title={<span><RadarChartOutlined /> Behavioral Hunting</span>}>
            <Paragraph type="secondary">
              Deterministically compare recent activity with a normalized historical baseline, then launch the agent on the anomalies that matter.
            </Paragraph>
            <Space wrap>
              <Select
                value={dimension}
                onChange={setDimension}
                options={[
                  { value: 'signature', label: 'Signature' },
                  { value: 'host', label: 'Host' },
                  { value: 'source', label: 'Source' },
                  { value: 'rule', label: 'Rule ID' },
                ]}
                style={{ width: 130 }}
              />
              <Select
                value={behaviorHours}
                onChange={setBehaviorHours}
                options={[12, 24, 48, 72].map((value) => ({ value, label: `Last ${value}h` }))}
                style={{ width: 120 }}
              />
              <Select
                value={baselineDays}
                onChange={setBaselineDays}
                options={[7, 14, 30].map((value) => ({ value, label: `${value}d baseline` }))}
                style={{ width: 130 }}
              />
              <Button icon={<RadarChartOutlined />} loading={behaviorLoading} onClick={() => void scanBehavior()}>
                Scan
              </Button>
            </Space>
            {behaviorResult && (
              <BehaviorTable
                data={behaviorResult}
                running={running}
                onHunt={(huntGoal) => void runHunt(huntGoal)}
              />
            )}
          </Card>
        </Col>
      </Row>
    </main>
  );
};

const TimelineEvent: React.FC<{ event: HuntEvent }> = ({ event }) => {
  const observation = event.observation;
  if (event.type === 'step_planned') {
    return (
      <div className="hunt-event">
        <div className="hunt-event-head"><Tag>STEP {event.step}</Tag><strong>Hypothesis / next move</strong></div>
        <p dir="auto">{event.rationale}</p>
        <div className="hunt-tool-call"><ToolOutlined /> {event.tool}</div>
      </div>
    );
  }
  if (event.type === 'tool_started') {
    return <div className="hunt-event is-muted"><strong>{event.tool}</strong><span> executing validated MCP operation…</span></div>;
  }
  if (event.type === 'tool_completed') {
    return (
      <div className="hunt-event is-success">
        <div className="hunt-event-head"><Tag color="success">{observation?.id}</Tag><strong>{observation?.tool}</strong><span>{observation?.durationMs} ms</span></div>
        <p>{observation?.summary}</p>
        <Collapse
          ghost
          size="small"
          items={[{
            key: 'evidence',
            label: 'Inspect structured observation',
            children: <pre className="hunt-json">{JSON.stringify(observation?.result, null, 2)}</pre>,
          }]}
        />
      </div>
    );
  }
  if (event.type === 'tool_failed') {
    return <div className="hunt-event is-error"><strong>{observation?.tool}</strong><p>{observation?.error}</p></div>;
  }
  return <div className="hunt-event is-error"><strong>{event.type.replaceAll('_', ' ')}</strong><p>{event.error || event.rationale}</p></div>;
};

const HuntReportView: React.FC<{ report: HuntReport; observations: any[]; meta: any }> = ({ report, observations, meta }) => {
  const evidenceMap = new Map(observations.map((item) => [item.id, item]));
  return (
    <div className="hunt-report">
      <div className="hunt-verdict-row">
        <Tag color={verdictColor(report.verdict)}>{report.verdict.replaceAll('_', ' ').toUpperCase()}</Tag>
        <div><strong>{report.confidence}%</strong><span>confidence</span></div>
      </div>
      <Progress percent={report.confidence} showInfo={false} status={report.verdict === 'likely_malicious' ? 'exception' : 'active'} />
      <Paragraph className="hunt-summary" dir="auto">{report.summary}</Paragraph>

      <div className="hunt-findings">
        {(report.findings || []).map((finding, index) => (
          <article key={`${finding.title}-${index}`} className={`hunt-finding severity-${finding.severity}`}>
            <div className="hunt-finding-title">
              <Tag color={severityColor(finding.severity)}>{finding.severity}</Tag>
              <strong>{finding.title}</strong>
            </div>
            <p dir="auto">{finding.summary}</p>
            <div className="hunt-evidence-refs">
              {finding.evidenceRefs.map((ref) => (
                <span key={ref} title={evidenceMap.get(ref)?.summary || ref}>{ref}</span>
              ))}
            </div>
            {!!finding.entities?.length && <div className="hunt-entities">{finding.entities.map((entity) => <Tag key={entity}>{entity}</Tag>)}</div>}
          </article>
        ))}
      </div>

      {!!report.recommendedNextSteps?.length && (
        <div className="hunt-report-list">
          <strong>Recommended analyst follow-up</strong>
          <ol>{report.recommendedNextSteps.map((item) => <li key={item} dir="auto">{item}</li>)}</ol>
        </div>
      )}
      {!!report.limitations?.length && (
        <div className="hunt-limitations">
          <AlertOutlined />
          <div><strong>Evidence limitations</strong>{report.limitations.map((item) => <span key={item} dir="auto">{item}</span>)}</div>
        </div>
      )}
      {meta?.durationMs !== undefined && <Text type="secondary">Hunt duration: {Number(meta.durationMs).toLocaleString()} ms · {meta.terminationReason || 'completed'}</Text>}
    </div>
  );
};

const DetectionResult: React.FC<{ data: any }> = ({ data }) => {
  const proposal = data.proposal || {};
  const backtest = data.backtest || {};
  return (
    <div className="detection-result">
      <div className="detection-title">
        <div><strong>{proposal.title}</strong><span>{proposal.description}</span></div>
        <Tag color={severityColor(proposal.severity)}>{proposal.severity}</Tag>
      </div>
      <Row gutter={[10, 10]}>
        <Col span={8}><Statistic title="Historical matches" value={backtest.matchedCount || 0} /></Col>
        <Col span={8}><Statistic title="High/Critical" value={backtest.highRiskCount || 0} /></Col>
        <Col span={8}><Statistic title="High-risk ratio" value={backtest.highRiskPercent || 0} suffix="%" /></Col>
      </Row>
      <div className="detection-filters">
        <strong>Backtested logic</strong>
        {(proposal.filters || []).map((filter: any, index: number) => (
          <code key={`${filter.field}-${index}`}>{filter.field} {filter.operator} {formatValue(filter.value)}</code>
        ))}
      </div>
      <Paragraph>{proposal.rationale}</Paragraph>
      {proposal.suricataDraft && (
        <Collapse
          items={[{
            key: 'suricata',
            label: 'Review Suricata draft (never auto-deployed)',
            children: <pre className="hunt-json">{proposal.suricataDraft}</pre>,
          }]}
        />
      )}
      {!!backtest.samples?.length && (
        <Collapse
          items={[{
            key: 'samples',
            label: `Inspect ${backtest.sampleCount} historical sample(s)`,
            children: <pre className="hunt-json">{JSON.stringify(backtest.samples, null, 2)}</pre>,
          }]}
        />
      )}
    </div>
  );
};

const BehaviorTable: React.FC<{ data: any; running: boolean; onHunt: (goal: string) => void }> = ({ data, running, onHunt }) => (
  <div className="behavior-result">
    <AntAlert
      type="info"
      showIcon
      message={data.scoring?.note || 'Deterministic behavioral prioritization signal'}
      className="behavior-note"
    />
    <Table
      size="small"
      pagination={{ pageSize: 6, hideOnSinglePage: true }}
      rowKey={(row: any) => `${row.dimension}-${row.key}`}
      dataSource={data.anomalies || []}
      scroll={{ x: 720 }}
      columns={[
        { title: 'Entity', dataIndex: 'key', width: 220, render: (value: string) => <Text ellipsis={{ tooltip: value }}>{value}</Text> },
        { title: 'Recent', dataIndex: 'recentCount', width: 80 },
        { title: 'Expected', dataIndex: 'expectedRecentCount', width: 90 },
        { title: 'Lift', dataIndex: 'ratio', width: 80, render: (value: number | null) => value === null ? 'new' : `${value}×` },
        { title: 'Signal', dataIndex: 'classification', width: 90, render: (value: string) => <Tag>{value}</Tag> },
        { title: 'Score', dataIndex: 'anomalyScore', width: 120, render: (value: number) => <Progress percent={Math.round(Number(value || 0) * 10)} size="small" format={() => `${value}/10`} /> },
        { title: '', key: 'hunt', width: 95, render: (_: unknown, row: any) => <Button size="small" type="link" disabled={running} onClick={() => onHunt(row.huntGoal)}>Hunt it</Button> },
      ]}
    />
  </div>
);

function timelineDot(event: HuntEvent) {
  if (event.type === 'tool_completed') return <CheckCircleOutlined />;
  if (event.type === 'tool_failed' || event.type === 'planning_failed' || event.type === 'step_rejected') return <AlertOutlined />;
  if (event.type === 'tool_started') return <LoadingOutlined spin />;
  return <ThunderboltOutlined />;
}

function verdictColor(verdict: HuntReport['verdict']) {
  if (verdict === 'likely_malicious') return 'error';
  if (verdict === 'suspicious') return 'warning';
  if (verdict === 'no_significant_finding') return 'success';
  return 'default';
}

function severityColor(severity: string) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  if (severity === 'low') return 'processing';
  return 'default';
}

function formatValue(value: unknown) {
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

export default ThreatHunting;
