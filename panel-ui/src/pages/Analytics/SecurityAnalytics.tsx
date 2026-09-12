import React, { useMemo, useState } from 'react';
import { Alert as AntAlert, Button, Card, Col, Input, Progress, Row, Select, Space, Statistic, Table, Tag, Typography, message } from 'antd';
import { ApartmentOutlined, BarChartOutlined, ExperimentOutlined, SafetyCertificateOutlined, SearchOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import './SecurityAnalytics.css';

const { Title, Text } = Typography;

type EntityType = 'alert' | 'ip' | 'organization' | 'rule' | 'mitre_technique';

const SecurityAnalytics: React.FC = () => {
  const [days, setDays] = useState(30);
  const [ruleId, setRuleId] = useState('');
  const [ruleLookup, setRuleLookup] = useState('');
  const [entityType, setEntityType] = useState<EntityType>('alert');
  const [entityId, setEntityId] = useState('');
  const [entityLookup, setEntityLookup] = useState('');

  const evaluationQuery = useQuery({
    queryKey: ['ai-evaluation', days],
    queryFn: () => api.getAiEvaluation(days),
  });

  const ruleQuery = useQuery({
    queryKey: ['rule-insights', ruleLookup, days],
    queryFn: () => api.getRuleInsights(ruleLookup, days),
    enabled: Boolean(ruleLookup),
    retry: false,
  });

  const entityQuery = useQuery({
    queryKey: ['entity-context', entityType, entityLookup],
    queryFn: () => api.getEntityContext(entityType, entityLookup),
    enabled: Boolean(entityLookup),
    retry: false,
  });

  const evaluation = evaluationQuery.data;
  const maxRuns = useMemo(
    () => Math.max(...(evaluation?.models || []).map((item: any) => Number(item.runs || 0)), 1),
    [evaluation],
  );

  const lookupRule = () => {
    const value = ruleId.trim();
    if (!value) return message.warning('Rule ID را وارد کنید');
    setRuleLookup(value);
  };

  const lookupEntity = () => {
    const value = entityId.trim();
    if (!value) return message.warning('Entity ID را وارد کنید');
    setEntityLookup(value);
  };

  return (
    <main className="security-analytics-page">
      <header className="security-analytics-heading">
        <div>
          <div className="security-analytics-eyebrow"><ExperimentOutlined /> AI SECURITY WORKBENCH</div>
          <Title level={2}>AI Security Analytics</Title>
          <Text type="secondary">Evidence-backed exploration, model observability and deterministic rule-quality signals.</Text>
        </div>
        <Select
          value={days}
          onChange={setDays}
          options={[7, 30, 90].map((value) => ({ value, label: `${value} days` }))}
          style={{ width: 120 }}
        />
      </header>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}><Card><Statistic title="AI coverage" value={evaluation?.summary?.coveragePercent || 0} suffix="%" /></Card></Col>
        <Col xs={24} sm={12} lg={6}><Card><Statistic title="Successful analyses" value={evaluation?.summary?.analyzed || 0} /></Card></Col>
        <Col xs={24} sm={12} lg={6}><Card><Statistic title="Failed analyses" value={evaluation?.summary?.failed || 0} /></Card></Col>
        <Col xs={24} sm={12} lg={6}><Card><Statistic title="Avg analysis latency" value={evaluation?.summary?.avgLatencyMs || 0} suffix="ms" /></Card></Col>
      </Row>

      <Card className="workbench-card" title={<span><BarChartOutlined /> Model Evaluation</span>} loading={evaluationQuery.isLoading}>
        <AntAlert
          type="info"
          showIcon
          message="Operational evaluation only"
          description="Accuracy is intentionally not inferred until analyst feedback exists. These metrics are calculated from persisted provider/model/status/latency fields."
          className="workbench-note"
        />
        <div className="model-bars">
          {(evaluation?.models || []).map((model: any) => (
            <div className="model-bar-row" key={`${model.provider}-${model.model}`}>
              <div className="model-bar-label"><strong>{model.model}</strong><span>{model.provider}</span></div>
              <Progress percent={Math.round((Number(model.runs || 0) / maxRuns) * 100)} showInfo={false} />
              <span className="model-bar-value">{Number(model.runs || 0).toLocaleString()} runs</span>
            </div>
          ))}
          {!evaluation?.models?.length && <Text type="secondary">No persisted model runs in this window.</Text>}
        </div>
        <Table
          size="small"
          pagination={false}
          rowKey={(row: any) => `${row.provider}-${row.model}`}
          dataSource={evaluation?.models || []}
          columns={[
            { title: 'Provider', dataIndex: 'provider' },
            { title: 'Model', dataIndex: 'model' },
            { title: 'Runs', dataIndex: 'runs' },
            { title: 'Success', dataIndex: 'successPercent', render: (value: number) => `${value || 0}%` },
            { title: 'Avg latency', dataIndex: 'avgLatencyMs', render: (value: number) => `${Number(value || 0).toLocaleString()} ms` },
          ]}
        />
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Card className="workbench-card" title={<span><SafetyCertificateOutlined /> Detection Rule Copilot</span>}>
            <Space.Compact block>
              <Input value={ruleId} onChange={(event) => setRuleId(event.target.value)} onPressEnter={lookupRule} placeholder="Rule ID, e.g. 2100498" />
              <Button type="primary" icon={<SearchOutlined />} onClick={lookupRule}>Inspect</Button>
            </Space.Compact>
            {ruleQuery.isError && <AntAlert className="workbench-inline-alert" type="error" showIcon message="Rule insight lookup failed" />}
            {ruleQuery.data && <RuleInsights data={ruleQuery.data} />}
          </Card>
        </Col>

        <Col xs={24} xl={12}>
          <Card className="workbench-card" title={<span><ApartmentOutlined /> Entity Graph & Evidence</span>}>
            <Space.Compact block>
              <Select
                value={entityType}
                onChange={setEntityType}
                style={{ minWidth: 150 }}
                options={['alert', 'ip', 'organization', 'rule', 'mitre_technique'].map((value) => ({ value, label: value.replace('_', ' ') }))}
              />
              <Input value={entityId} onChange={(event) => setEntityId(event.target.value)} onPressEnter={lookupEntity} placeholder="Entity ID" />
              <Button type="primary" icon={<SearchOutlined />} onClick={lookupEntity}>Explore</Button>
            </Space.Compact>
            {entityQuery.isError && <AntAlert className="workbench-inline-alert" type="error" showIcon message="Entity context lookup failed" />}
            {entityQuery.data && <EntityEvidence context={entityQuery.data} />}
          </Card>
        </Col>
      </Row>
    </main>
  );
};

const RuleInsights: React.FC<{ data: any }> = ({ data }) => (
  <div className="rule-insights">
    <div className="rule-insights-title">
      <div><strong>{data.rule?.title || data.rule?.ruleId}</strong><span>Rule {data.rule?.ruleId} · rev {data.rule?.revision}</span></div>
      <Tag>{data.rule?.tier || 'unknown'}</Tag>
    </div>
    <Row gutter={[12, 12]}>
      <Col span={8}><Statistic title="Hits" value={data.stats?.total || 0} /></Col>
      <Col span={8}><Statistic title="High-risk ratio" value={data.stats?.highRiskPercent || 0} suffix="%" /></Col>
      <Col span={8}><Statistic title="AI coverage" value={data.stats?.aiCoveragePercent || 0} suffix="%" /></Col>
    </Row>
    <div className="signal-list">
      {(data.signals || []).map((signal: any) => <div key={signal.code} className={`signal is-${signal.level}`}><Tag>{signal.code}</Tag><span>{signal.message}</span></div>)}
    </div>
    {!!data.topHosts?.length && <div className="compact-ranking"><Text type="secondary">Top affected hosts</Text>{data.topHosts.map((item: any) => <div key={item.host}><span>{item.host}</span><strong>{item.count}</strong></div>)}</div>}
  </div>
);

const EntityEvidence: React.FC<{ context: any }> = ({ context }) => {
  const related = context.relatedEntities || {};
  const nodes = [
    { type: context.entity?.type, id: context.entity?.id, primary: true },
    related.sourceIp ? { type: 'source IP', id: related.sourceIp } : null,
    related.destinationIp ? { type: 'destination IP', id: related.destinationIp } : null,
    related.organization ? { type: 'organization', id: related.organization } : null,
    related.ruleId ? { type: 'rule', id: related.ruleId } : null,
    ...(related.mitreTechniques || []).slice(0, 4).map((id: string) => ({ type: 'MITRE', id })),
  ].filter(Boolean) as Array<{ type: string; id: string; primary?: boolean }>;

  const evidence = [
    context.evidencePolicy?.persistedAnalysis ? 'Persisted AI analysis' : null,
    context.evidencePolicy?.deterministicNetworkIntelligence ? 'Deterministic network intelligence' : null,
    context.analysisAvailable ? 'Stored analysis payload' : null,
    Array.isArray(context.iocs) && context.iocs.length ? `${context.iocs.length} persisted IOC(s)` : null,
    Array.isArray(context.correlations) && context.correlations.length ? `${context.correlations.length} correlation record(s)` : null,
  ].filter(Boolean);

  return <div className="entity-evidence">
    <div className="entity-graph">
      {nodes.map((node, index) => <React.Fragment key={`${node.type}-${node.id}`}>
        {index > 0 && <span className="graph-edge">→</span>}
        <div className={`graph-node ${node.primary ? 'is-primary' : ''}`}><span>{node.type}</span><strong>{node.id}</strong></div>
      </React.Fragment>)}
    </div>
    <div className="evidence-ledger">
      <Text strong>Evidence trace</Text>
      {evidence.length ? evidence.map((item) => <div key={String(item)}><SafetyCertificateOutlined /><span>{item}</span></div>) : <Text type="secondary">No explicit persisted evidence markers were found for this entity.</Text>}
    </div>
    {context.analysis && <details className="context-json"><summary>Verified analysis context</summary><pre>{JSON.stringify(context.analysis, null, 2)}</pre></details>}
  </div>;
};

export default SecurityAnalytics;
