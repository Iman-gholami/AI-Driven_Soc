import React, { useMemo, useState } from 'react';
import { Button, Card, Drawer, Empty, Space, Spin, Table, Tag, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { MitreTechniqueCoverage } from '../../types';
import './MitreCoverage.css';

const { Title, Text, Paragraph } = Typography;
type Tier = 'all' | 'native' | 'imported' | 'community';

const MitreCoverage: React.FC = () => {
  const [tier, setTier] = useState<Tier>('all');
  const [selected, setSelected] = useState<MitreTechniqueCoverage | null>(null);
  const [rulePage, setRulePage] = useState(1);

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ['mitre-rule-coverage', tier],
    queryFn: () => api.getMitreCoverage(tier),
    staleTime: 60_000,
  });

  const detail = useQuery({
    queryKey: ['mitre-technique-rules', selected?.techniqueId, tier, rulePage],
    queryFn: () => api.getMitreTechniqueRules(selected!.techniqueId, { tier, page: rulePage, limit: 20 }),
    enabled: Boolean(selected),
  });

  const snapshot = data;
  const summary = snapshot?.summary;
  const tierCounts = summary?.rules.byTier || { native: 0, imported: 0, community: 0 };
  const generated = snapshot?.generatedAt ? new Date(snapshot.generatedAt).toLocaleString() : 'Not built';

  const cards = useMemo(() => [
    {
      label: 'Techniques Covered',
      value: summary?.techniques.covered ?? 0,
      detail: summary?.techniques.total
        ? `of ${summary.techniques.total} active Enterprise techniques`
        : 'MITRE dataset not imported',
    },
    {
      label: 'Rules With MITRE',
      value: summary?.rules.withMitre ?? 0,
      detail: summary?.rules.total
        ? `${summary.rules.mappingCoveragePercent}% mapped · ${summary.rules.explicitReference ?? 0} explicit/ref · ${summary.rules.curated ?? 0} curated · ${summary.rules.legacyOnly ?? 0} legacy-only`
        : 'No current rules in this scope',
    },
    {
      label: 'Detection Rules',
      value: summary?.rules.total ?? 0,
      detail: `Native ${tierCounts.native} · Imported ${tierCounts.imported} · Community ${tierCounts.community}`,
    },
    {
      label: 'Unmapped Rules',
      value: summary?.rules.unmapped ?? 0,
      detail: `${summary?.rules.quarantined ?? 0} quarantined`,
    },
  ], [summary, tierCounts]);

  const openTechnique = (technique: MitreTechniqueCoverage) => {
    setRulePage(1);
    setSelected(technique);
  };

  return <div className="mitre-coverage-page">
    <div className="mitre-page-heading">
      <div>
        <Title level={2}>MITRE ATT&amp;CK Coverage</Title>
        <Paragraph>
          Rule-level coverage calculated from the latest revision of detection rules stored in MongoDB.
          Counts represent deterministic rule mappings, not AI alert mappings.
        </Paragraph>
      </div>
      <div className="mitre-refresh-meta">
        <span>{isFetching ? 'Refreshing…' : 'Snapshot'}</span>
        <strong>{generated}</strong>
        {snapshot?.attackVersion && <small>ATT&amp;CK object version {snapshot.attackVersion}</small>}
      </div>
    </div>

    <Spin spinning={isLoading}>
      <div className="mitre-summary-grid">
        {cards.map((item) => <Card key={item.label} className="mitre-summary-card">
          <span className="mitre-card-label">{item.label}</span>
          <strong>{Number(item.value).toLocaleString()}</strong>
          <small>{item.detail}</small>
        </Card>)}
      </div>

      <div className="mitre-toolbar">
        <Space wrap>
          {([
            ['all','All tiers'],
            ['native','Native'],
            ['imported','Imported'],
            ['community','Community'],
          ] as [Tier,string][]).map(([value,label]) =>
            <Button
              key={value}
              type={tier === value ? 'primary' : 'default'}
              onClick={() => setTier(value)}
              shape="round"
              size="small"
            >
              {label}
            </Button>
          )}
        </Space>
        <div className="mitre-legend">
          <span>Heat intensity = rules covering technique</span>
          <i className="level-one" /> 1
          <i className="level-low" /> 2–4
          <i className="level-medium" /> 5–9
          <i className="level-high" /> 10+
        </div>
      </div>

      {!snapshot?.summary.techniques.total ? <Card className="mitre-setup-card">
        <Empty
          description={
            <span>
              MITRE Enterprise ATT&amp;CK data is not available yet.
              Run <code>npm run import:mitre</code> and then <code>npm run mitre:coverage</code>.
            </span>
          }
        />
      </Card> : <div className="mitre-matrix">
        {snapshot.tactics.map((tactic) => <section className="mitre-tactic-column" key={tactic.tacticId}>
          <header>
            <span>{tactic.tacticId}</span>
            <strong>{tactic.name}</strong>
            <small>
              {tactic.coveredTechniques}/{tactic.totalTechniques} techniques · {tactic.coveragePercent}%
            </small>
          </header>
          <div className="mitre-technique-list">
            {tactic.techniques.map((technique) => <button
              key={technique.techniqueId}
              className={`mitre-technique ${heatClass(technique.ruleCount)}`}
              onClick={() => openTechnique(technique)}
            >
              <span>
                <strong>{technique.techniqueId}</strong>
                <small>{technique.name}</small>
              </span>
              <b>{technique.ruleCount}</b>
              <em><i style={{ width: `${heatWidth(technique.ruleCount)}%` }} /></em>
            </button>)}
          </div>
        </section>)}
      </div>}
    </Spin>

    <Drawer
      title={selected ? `${selected.techniqueId} — ${selected.name}` : 'MITRE Technique'}
      width={760}
      open={Boolean(selected)}
      onClose={() => setSelected(null)}
    >
      {selected && <>
        <Card size="small" className="mitre-detail-card">
          <Space wrap>
            <Tag color={selected.ruleCount ? 'green' : 'default'}>{selected.ruleCount} current rules</Tag>
            {selected.isSubTechnique && <Tag>Sub-technique</Tag>}
            {detail.data?.technique.tactics?.map((tactic) =>
              <Tag color="blue" key={tactic.id}>{tactic.id} {tactic.name}</Tag>
            )}
          </Space>
          {detail.data?.technique.description &&
            <Paragraph className="mitre-description">{detail.data.technique.description}</Paragraph>}
          {detail.data?.technique.platforms?.length ? <Text type="secondary">
            Platforms: {detail.data.technique.platforms.join(', ')}
          </Text> : null}
        </Card>

        <Title level={4} style={{ marginTop: 20 }}>Detection rules covering this technique</Title>
        <Table
          size="small"
          rowKey={(record) => `${record.ruleId}-${record.revision}`}
          loading={detail.isLoading}
          dataSource={detail.data?.rules || []}
          columns={[
            { title: 'Rule ID', dataIndex: 'ruleId', width: 110 },
            { title: 'Rev', dataIndex: 'revision', width: 65 },
            { title: 'Title', dataIndex: 'title' },
            { title: 'Tier', dataIndex: 'tier', width: 100, render: (value: string | undefined) => <Tag>{value || 'imported'}</Tag> },
            {
              title: 'Mapping',
              key: 'mapping',
              width: 120,
              render: (_value: unknown, record) => {
                const sources = [...new Set((record.mitre?.mappings || []).map((mapping: any) => mapping.source))];
                return sources.map((source) => <Tag key={source}>{source}</Tag>);
              },
            },
            { title: 'Protocol', dataIndex: 'protocol', width: 100 },
          ]}
          pagination={{
            current: detail.data?.pagination.page || rulePage,
            pageSize: detail.data?.pagination.limit || 20,
            total: detail.data?.pagination.total || 0,
            showSizeChanger: false,
            onChange: setRulePage,
          }}
        />
      </>}
    </Drawer>
  </div>;
};

function heatClass(count:number) {
  if (count >= 10) return 'heat-high';
  if (count >= 5) return 'heat-medium';
  if (count >= 2) return 'heat-low';
  if (count === 1) return 'heat-one';
  return 'heat-gap';
}

function heatWidth(count:number) {
  if (!count) return 0;
  return Math.min(100, 18 + Math.log2(count + 1) * 13);
}

export default MitreCoverage;
