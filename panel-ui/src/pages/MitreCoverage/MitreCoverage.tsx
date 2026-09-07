import React, { useMemo, useState } from 'react';
import { Card, Drawer, Empty, Input, Segmented, Space, Spin, Table, Tag, Typography } from 'antd';
import {
  ClockCircleOutlined,
  DatabaseOutlined,
  RadarChartOutlined,
  SearchOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { MitreTechniqueCoverage } from '../../types';
import './MitreCoverage.css';

const { Title, Text, Paragraph } = Typography;
type Tier = 'all' | 'native' | 'imported' | 'community';
type CoverageFilter = 'all' | 'covered' | 'gaps';

const MitreCoverage: React.FC = () => {
  const [tier, setTier] = useState<Tier>('all');
  const [coverageFilter, setCoverageFilter] = useState<CoverageFilter>('all');
  const [search, setSearch] = useState('');
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
  const mappedPercent = summary?.rules.mappingCoveragePercent ?? 0;
  const techniquePercent = summary?.techniques.coveragePercent ?? 0;
  const unmappedPercent = summary?.rules.total
    ? Math.round((summary.rules.unmapped / summary.rules.total) * 1000) / 10
    : 0;

  const cards = useMemo(() => [
    {
      label: 'Techniques Covered',
      value: summary?.techniques.covered ?? 0,
      detail: summary?.techniques.total
        ? `${summary.techniques.covered} of ${summary.techniques.total} active techniques`
        : 'MITRE dataset not imported',
      percent: techniquePercent,
      tone: 'cyan',
      icon: <RadarChartOutlined />,
    },
    {
      label: 'Rules With MITRE',
      value: summary?.rules.withMitre ?? 0,
      detail: summary?.rules.total
        ? `${mappedPercent}% of current detection rules`
        : 'No current rules in this scope',
      percent: mappedPercent,
      tone: 'blue',
      icon: <SafetyCertificateOutlined />,
    },
    {
      label: 'Detection Rules',
      value: summary?.rules.total ?? 0,
      detail: `Native ${tierCounts.native} · Imported ${tierCounts.imported} · Community ${tierCounts.community}`,
      percent: null,
      tone: 'neutral',
      icon: <DatabaseOutlined />,
    },
    {
      label: 'Unmapped Rules',
      value: summary?.rules.unmapped ?? 0,
      detail: summary?.rules.total
        ? `${unmappedPercent}% remain without ATT&CK mapping`
        : 'No current rules in this scope',
      percent: unmappedPercent,
      tone: 'warning',
      icon: <WarningOutlined />,
    },
  ], [summary, tierCounts, mappedPercent, techniquePercent, unmappedPercent]);

  const filteredTactics = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return (snapshot?.tactics || [])
      .map((tactic) => ({
        ...tactic,
        techniques: tactic.techniques.filter((technique) => {
          const matchesSearch = !needle
            || technique.techniqueId.toLowerCase().includes(needle)
            || technique.name.toLowerCase().includes(needle);
          const matchesCoverage = coverageFilter === 'all'
            || (coverageFilter === 'covered' && technique.ruleCount > 0)
            || (coverageFilter === 'gaps' && technique.ruleCount === 0);
          return matchesSearch && matchesCoverage;
        }),
      }))
      .filter((tactic) => tactic.techniques.length > 0);
  }, [snapshot?.tactics, search, coverageFilter]);

  const visibleTechniqueCount = filteredTactics.reduce(
    (total, tactic) => total + tactic.techniques.length,
    0,
  );

  const openTechnique = (technique: MitreTechniqueCoverage) => {
    setRulePage(1);
    setSelected(technique);
  };

  return (
    <main className="mitre-coverage-page">
      <header className="mitre-page-heading">
        <div className="mitre-title-block">
          <div className="mitre-eyebrow"><RadarChartOutlined /> DETECTION COVERAGE / ENTERPRISE ATT&amp;CK</div>
          <Title level={2}>MITRE ATT&amp;CK Coverage</Title>
          <Paragraph>
            Rule-level coverage from the latest revision of detection rules in MongoDB.
            Mappings are deterministic and provenance-aware; AI alert mappings are intentionally excluded.
          </Paragraph>
        </div>

        <div className="mitre-refresh-meta">
          <div className="mitre-snapshot-status">
            <i className={isFetching ? 'is-fetching' : ''} />
            <span>{isFetching ? 'Refreshing snapshot' : 'Coverage snapshot'}</span>
          </div>
          <strong>{generated}</strong>
          <small><ClockCircleOutlined /> {snapshot?.attackVersion ? `ATT&CK object version ${snapshot.attackVersion}` : 'ATT&CK catalog version unavailable'}</small>
        </div>
      </header>

      <Spin spinning={isLoading}>
        <section className="mitre-summary-grid" aria-label="MITRE coverage summary">
          {cards.map((item) => (
            <Card key={item.label} className={`mitre-summary-card tone-${item.tone}`}>
              <div className="mitre-card-top">
                <span className="mitre-card-label">{item.label}</span>
                <i className="mitre-card-icon">{item.icon}</i>
              </div>
              <strong>{Number(item.value).toLocaleString()}</strong>
              <small>{item.detail}</small>
              {typeof item.percent === 'number' && (
                <div className="mitre-card-meter" aria-hidden="true">
                  <i style={{ width: `${Math.max(0, Math.min(100, item.percent))}%` }} />
                </div>
              )}
            </Card>
          ))}
        </section>

        {summary?.rules.total ? (
          <section className="mitre-provenance-strip" aria-label="Mapping provenance">
            <div>
              <span>Mapping provenance</span>
              <small>Every mapped rule keeps its source and evidence path.</small>
            </div>
            <div className="mitre-provenance-stats">
              <span><i className="prov-explicit" /> <strong>{(summary.rules.explicitReference ?? 0).toLocaleString()}</strong> explicit / reference</span>
              <span><i className="prov-curated" /> <strong>{(summary.rules.curated ?? 0).toLocaleString()}</strong> curated</span>
              <span><i className="prov-gap" /> <strong>{(summary.rules.gapCurated ?? 0).toLocaleString()}</strong> gap-curated</span>
              <span><i className="prov-legacy" /> <strong>{(summary.rules.legacyOnly ?? 0).toLocaleString()}</strong> legacy-only</span>
            </div>
          </section>
        ) : null}

        <section className="mitre-controls" aria-label="MITRE coverage filters">
          <div className="mitre-control-block">
            <label>Rule scope</label>
            <Segmented
              value={tier}
              onChange={(value) => setTier(value as Tier)}
              options={[
                { label: 'All tiers', value: 'all' },
                { label: 'Native', value: 'native' },
                { label: 'Imported', value: 'imported' },
                { label: 'Community', value: 'community' },
              ]}
            />
          </div>

          <div className="mitre-control-spacer" />

          <Input
            className="mitre-search"
            prefix={<SearchOutlined />}
            placeholder="Search technique ID or name"
            allowClear
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />

          <Segmented
            value={coverageFilter}
            onChange={(value) => setCoverageFilter(value as CoverageFilter)}
            options={[
              { label: 'All', value: 'all' },
              { label: 'Covered', value: 'covered' },
              { label: 'Gaps', value: 'gaps' },
            ]}
          />
        </section>

        {!snapshot?.summary.techniques.total ? (
          <Card className="mitre-setup-card">
            <Empty
              description={
                <span>
                  MITRE Enterprise ATT&amp;CK data is not available yet.
                  Run <code>npm run import:mitre</code> and then <code>npm run mitre:coverage</code>.
                </span>
              }
            />
          </Card>
        ) : (
          <section className="mitre-matrix-shell">
            <div className="mitre-matrix-heading">
              <div>
                <span>ATT&amp;CK MATRIX</span>
                <strong>Coverage by tactic and technique</strong>
                <small>{visibleTechniqueCount.toLocaleString()} techniques visible</small>
              </div>
              <div className="mitre-legend" aria-label="Heat legend">
                <span>Rule density</span>
                <i className="level-one" /> 1
                <i className="level-low" /> 2–4
                <i className="level-medium" /> 5–9
                <i className="level-high" /> 10+
              </div>
            </div>

            {filteredTactics.length ? (
              <div className="mitre-matrix">
                {filteredTactics.map((tactic) => (
                  <section className="mitre-tactic-column" key={tactic.tacticId}>
                    <header>
                      <div className="mitre-tactic-code">{tactic.tacticId}</div>
                      <strong>{tactic.name}</strong>
                      <small>{tactic.coveredTechniques}/{tactic.totalTechniques} techniques · {tactic.coveragePercent}%</small>
                      <div className="mitre-tactic-meter">
                        <i style={{ width: `${tactic.coveragePercent}%` }} />
                      </div>
                    </header>
                    <div className="mitre-technique-list">
                      {tactic.techniques.map((technique) => (
                        <button
                          type="button"
                          key={technique.techniqueId}
                          className={`mitre-technique ${heatClass(technique.ruleCount)}`}
                          onClick={() => openTechnique(technique)}
                          title={`${technique.techniqueId} — ${technique.name} · ${technique.ruleCount} current rules`}
                          aria-label={`${technique.techniqueId} ${technique.name}, ${technique.ruleCount} current rules`}
                        >
                          <span>
                            <strong>{technique.techniqueId}</strong>
                            <small>{technique.name}</small>
                          </span>
                          <b>{technique.ruleCount.toLocaleString()}</b>
                          <em><i style={{ width: `${heatWidth(technique.ruleCount)}%` }} /></em>
                        </button>
                      ))}
                    </div>
                  </section>
                ))}
              </div>
            ) : (
              <div className="mitre-filter-empty">
                <Empty description="No ATT&CK techniques match the current filters" />
              </div>
            )}
          </section>
        )}
      </Spin>

      <Drawer
        title={selected ? <div className="mitre-drawer-title"><span>{selected.techniqueId}</span><strong>{selected.name}</strong></div> : 'MITRE Technique'}
        width="min(880px, 100vw)"
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
      >
        {selected && (
          <>
            <Card size="small" className="mitre-detail-card">
              <div className="mitre-detail-summary">
                <div>
                  <span>CURRENT COVERAGE</span>
                  <strong>{selected.ruleCount.toLocaleString()}</strong>
                  <small>detection rules</small>
                </div>
                <Space wrap>
                  <Tag color={selected.ruleCount ? 'cyan' : 'default'}>{selected.ruleCount ? 'Covered' : 'Coverage gap'}</Tag>
                  {selected.isSubTechnique && <Tag>Sub-technique</Tag>}
                  {detail.data?.technique.tactics?.map((tactic) => (
                    <Tag color="blue" key={tactic.id}>{tactic.id} {tactic.name}</Tag>
                  ))}
                </Space>
              </div>
              {detail.data?.technique.description && (
                <Paragraph className="mitre-description">{detail.data.technique.description}</Paragraph>
              )}
              {detail.data?.technique.platforms?.length ? (
                <Text type="secondary">Platforms: {detail.data.technique.platforms.join(', ')}</Text>
              ) : null}
            </Card>

            <div className="mitre-rule-table-heading">
              <div>
                <span>DETECTION RULES</span>
                <Title level={4}>Rules covering this technique</Title>
              </div>
              <Text type="secondary">{detail.data?.pagination.total ?? selected.ruleCount} current rules</Text>
            </div>

            <Table
              size="small"
              rowKey={(record) => `${record.ruleId}-${record.revision}`}
              loading={detail.isLoading}
              dataSource={detail.data?.rules || []}
              scroll={{ x: 1000 }}
              columns={[
                { title: 'Rule ID', dataIndex: 'ruleId', width: 105 },
                { title: 'Rev', dataIndex: 'revision', width: 60 },
                { title: 'Title', dataIndex: 'title', width: 320 },
                { title: 'Source', dataIndex: 'sourceFile', width: 150, render: (value: string | undefined) => value || '—' },
                { title: 'Tier', dataIndex: 'tier', width: 95, render: (value: string | undefined) => <Tag>{value || 'imported'}</Tag> },
                {
                  title: 'Mapping',
                  key: 'mapping',
                  width: 145,
                  render: (_value: unknown, record) => {
                    const sources = [...new Set((record.mitre?.mappings || []).map((mapping: any) => mapping.source))];
                    return sources.map((source) => (
                      <Tag color={mappingColor(source)} key={source}>{mappingLabel(source)}</Tag>
                    ));
                  },
                },
                { title: 'Protocol', dataIndex: 'protocol', width: 90, render: (value: string | undefined) => value?.toUpperCase() || '—' },
              ]}
              pagination={{
                current: detail.data?.pagination.page || rulePage,
                pageSize: detail.data?.pagination.limit || 20,
                total: detail.data?.pagination.total || 0,
                showSizeChanger: false,
                showTotal: (total) => `${total} rules`,
                onChange: setRulePage,
              }}
            />
          </>
        )}
      </Drawer>
    </main>
  );
};

function heatClass(count: number) {
  if (count >= 10) return 'heat-high';
  if (count >= 5) return 'heat-medium';
  if (count >= 2) return 'heat-low';
  if (count === 1) return 'heat-one';
  return 'heat-gap';
}

function heatWidth(count: number) {
  if (!count) return 0;
  return Math.min(100, 18 + Math.log2(count + 1) * 13);
}

function mappingColor(source?: string) {
  if (source === 'explicit') return 'blue';
  if (source === 'reference') return 'cyan';
  if (source === 'curated') return 'purple';
  if (source === 'curated-gap') return 'gold';
  return 'default';
}

function mappingLabel(source?: string) {
  if (source === 'curated-gap') return 'gap-curated';
  return source || 'unknown';
}

export default MitreCoverage;
