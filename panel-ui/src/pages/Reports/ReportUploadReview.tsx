import React, { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Drawer,
  Empty,
  List,
  Modal,
  Row,
  Space,
  Statistic,
  Steps,
  Table,
  Tag,
  Typography,
  Upload,
  message,
} from 'antd';
import {
  CheckCircleOutlined,
  DeleteOutlined,
  EyeOutlined,
  InboxOutlined,
  LockOutlined,
  SaveOutlined,
  SafetyCertificateOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import type { UploadFile, UploadProps } from 'antd';
import { api } from '../../api/client';
import type {
  ReportUploadCommitResult,
  ReportUploadPreviewItem,
  ReportUploadPreviewSession,
} from '../../types/reports';
import './ReportUploadReview.css';

const { Text, Title, Paragraph } = Typography;
const { Dragger } = Upload;

interface ReportUploadReviewProps {
  year: number;
  onCommitted?: (result: ReportUploadCommitResult) => void | Promise<void>;
}

const actionColor: Record<ReportUploadPreviewItem['action'], string> = {
  new: 'green',
  update: 'gold',
  unchanged: 'default',
};

const severityColor: Record<string, string> = {
  critical: 'red',
  high: 'volcano',
  medium: 'gold',
  low: 'blue',
  info: 'cyan',
  unknown: 'default',
};

const ReportUploadReview: React.FC<ReportUploadReviewProps> = ({ year, onCommitted }) => {
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [preview, setPreview] = useState<ReportUploadPreviewSession | null>(null);
  const [selectedIds, setSelectedIds] = useState<React.Key[]>([]);
  const [detailReport, setDetailReport] = useState<ReportUploadPreviewItem | null>(null);
  const [extracting, setExtracting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [lastCommit, setLastCommit] = useState<ReportUploadCommitResult | null>(null);

  const selectedCount = selectedIds.length;
  const files = useMemo<File[]>(() => {
    const selected: File[] = [];
    for (const item of fileList) {
      if (item.originFileObj) selected.push(item.originFileObj);
    }
    return selected;
  }, [fileList]);

  const uploadProps: UploadProps = {
    accept: '.docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    multiple: true,
    maxCount: 100,
    beforeUpload: () => false,
    fileList,
    disabled: Boolean(preview),
    onChange: ({ fileList: next }) => {
      setLastCommit(null);
      setFileList(next.slice(0, 100));
    },
  };

  const extractPreview = async () => {
    if (!files.length) {
      message.warning('Select at least one DOCX report first.');
      return;
    }
    setExtracting(true);
    setLastCommit(null);
    try {
      const result = await api.previewHistoricalReportUpload(year, files);
      setPreview(result);
      setSelectedIds(result.previews.filter((item) => item.action !== 'unchanged').map((item) => item.id));
      if (result.failed) {
        message.warning(`${result.ready} report(s) ready for review; ${result.failed} file(s) could not be extracted.`);
      } else {
        message.success(`${result.ready} report(s) extracted. Nothing has been saved yet.`);
      }
    } catch (error: any) {
      message.error(error?.response?.data?.detail || error?.message || 'Unable to extract reports for preview.');
    } finally {
      setExtracting(false);
    }
  };

  const cancelPreview = async () => {
    setDetailReport(null);
    if (!preview) {
      setFileList([]);
      return;
    }
    setCancelling(true);
    try {
      await api.cancelHistoricalReportUpload(preview.sessionToken);
    } catch (_) {
      // The session may already have expired; local UI can still be reset safely.
    } finally {
      setPreview(null);
      setSelectedIds([]);
      setFileList([]);
      setCancelling(false);
    }
  };

  const confirmSave = () => {
    if (!preview || !selectedCount) return;
    Modal.confirm({
      title: `Save ${selectedCount} reviewed report${selectedCount === 1 ? '' : 's'}?`,
      content: (
        <div>
          <Paragraph>
            Only the selected reports will be written to MongoDB. Their original DOCX files will also be retained under the local report year folder.
          </Paragraph>
          <Text type="secondary">This is the first point where the database is changed.</Text>
        </div>
      ),
      okText: 'Confirm & save',
      cancelText: 'Keep reviewing',
      okButtonProps: { icon: <SaveOutlined /> },
      onOk: async () => {
        setSaving(true);
        try {
          const result = await api.commitHistoricalReportUpload(
            preview.sessionToken,
            selectedIds.map(String),
          );
          setLastCommit(result);
          await onCommitted?.(result);

          if (result.failed === 0) {
            setDetailReport(null);
            setPreview(null);
            setSelectedIds([]);
            setFileList([]);
            message.success(`Saved: ${result.imported} new · ${result.updated} updated · ${result.skipped} unchanged`);
          } else {
            message.warning(`${result.failed} report(s) failed to save. The review session was kept for retry.`);
          }
        } catch (error: any) {
          message.error(error?.response?.data?.detail || error?.message || 'Unable to save reviewed reports.');
          throw error;
        } finally {
          setSaving(false);
        }
      },
    });
  };

  return (
    <div className="report-upload-workflow">
      <Card className="report-upload-hero">
        <div className="report-upload-hero-copy">
          <span className="report-upload-icon"><SafetyCertificateOutlined /></span>
          <div>
            <Text className="report-upload-eyebrow">REVIEW BEFORE SAVE</Text>
            <Title level={4}>Upload DOCX reports, inspect extraction, then confirm</Title>
            <Paragraph type="secondary">
              Files are staged only on this SOC server. Extraction runs locally. MongoDB is not changed until you explicitly confirm the preview.
            </Paragraph>
          </div>
        </div>
        <Tag icon={<LockOutlined />} color="blue">Local-only staging</Tag>
      </Card>

      <Steps
        size="small"
        current={preview ? 1 : lastCommit ? 2 : 0}
        items={[
          { title: 'Select files', description: 'DOCX only' },
          { title: 'Review extraction', description: 'No DB changes' },
          { title: 'Confirm & save', description: 'Selected reports only' },
        ]}
      />

      {!preview ? (
        <Card>
          <Dragger {...uploadProps} className="report-upload-dragger">
            <p className="ant-upload-drag-icon"><InboxOutlined /></p>
            <p className="ant-upload-text">Drop security report DOCX files here</p>
            <p className="ant-upload-hint">or click to select up to 100 files · current Jalali year: {year}</p>
          </Dragger>

          <div className="report-upload-actions">
            <Text type="secondary">{fileList.length ? `${fileList.length} file(s) selected` : 'No files selected'}</Text>
            <Space>
              {fileList.length ? <Button icon={<DeleteOutlined />} onClick={() => setFileList([])}>Clear</Button> : null}
              <Button
                type="primary"
                icon={<EyeOutlined />}
                loading={extracting}
                disabled={!files.length}
                onClick={extractPreview}
              >
                Extract & preview
              </Button>
            </Space>
          </div>
        </Card>
      ) : (
        <>
          <Alert
            type="info"
            showIcon
            icon={<LockOutlined />}
            message="Preview only — nothing below has been saved yet"
            description={`This review session expires at ${new Date(preview.expiresAt).toLocaleTimeString()}. Use View full extraction for each report before confirming.`}
          />

          <Row gutter={[12, 12]}>
            <Col xs={12} md={6}><Card size="small"><Statistic title="Uploaded" value={preview.discovered} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title="Ready" value={preview.ready} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title="Selected to save" value={selectedCount} /></Card></Col>
            <Col xs={12} md={6}><Card size="small"><Statistic title="Extraction issues" value={preview.failed} /></Card></Col>
          </Row>

          {preview.quality.unknownFindingCount > 0 ? (
            <Alert
              type="warning"
              showIcon
              icon={<WarningOutlined />}
              message={`${preview.quality.unknownFindingCount} report(s) have an unknown finding classification`}
              description="Review those rows carefully before saving."
            />
          ) : null}

          {preview.errors.length ? (
            <Alert
              type="warning"
              showIcon
              message="Some files could not be extracted"
              description={(
                <List
                  size="small"
                  dataSource={preview.errors}
                  renderItem={(item) => <List.Item><Text code>{item.file}</Text>&nbsp;—&nbsp;{item.error}</List.Item>}
                />
              )}
            />
          ) : null}

          <Card title="Extraction preview" className="report-upload-preview-card">
            {preview.previews.length ? (
              <Table<ReportUploadPreviewItem>
                rowKey="id"
                size="small"
                pagination={false}
                dataSource={preview.previews}
                rowSelection={{
                  selectedRowKeys: selectedIds,
                  onChange: setSelectedIds,
                  getCheckboxProps: (record) => ({ disabled: record.action === 'unchanged' }),
                }}
                scroll={{ x: 1320 }}
                expandable={{
                  expandedRowRender: (record) => <PreviewSummary report={record} />,
                  rowExpandable: () => true,
                  expandRowByClick: false,
                }}
                columns={[
                  {
                    title: 'Save action',
                    dataIndex: 'action',
                    width: 105,
                    render: (value: ReportUploadPreviewItem['action']) => <Tag color={actionColor[value]}>{value}</Tag>,
                  },
                  { title: 'File', dataIndex: 'file', width: 220, ellipsis: true },
                  { title: 'Report no.', dataIndex: 'reportNumber', width: 160, render: (value) => value || '—' },
                  { title: 'Date', dataIndex: 'date', width: 105, render: (value) => value || '—' },
                  { title: 'Type', dataIndex: 'reportType', width: 130 },
                  { title: 'Organization', dataIndex: 'organization', width: 250, ellipsis: true, render: (value) => value || '—' },
                  { title: 'IP', dataIndex: 'ip', width: 135, render: (value, row) => <Text code>{value || row.rawIp || '—'}</Text> },
                  { title: 'Finding', dataIndex: 'findingName', width: 210, ellipsis: true, render: (value, row) => value || row.finding },
                  {
                    title: 'Severity',
                    dataIndex: 'severityLevel',
                    width: 105,
                    render: (value, row) => <Tag color={severityColor[value] || 'default'}>{value} {row.severityScore ?? ''}</Tag>,
                  },
                  {
                    title: 'Review',
                    dataIndex: 'warnings',
                    width: 90,
                    align: 'center',
                    render: (warnings: string[]) => warnings?.length ? <Tag color="warning">{warnings.length}</Tag> : <CheckCircleOutlined className="report-upload-ok" />,
                  },
                  {
                    title: 'Details',
                    key: 'details',
                    width: 145,
                    fixed: 'right',
                    render: (_, row) => (
                      <Button size="small" icon={<EyeOutlined />} onClick={() => setDetailReport(row)}>
                        View full extraction
                      </Button>
                    ),
                  },
                ]}
              />
            ) : <Empty description="No report was extracted successfully" />}
          </Card>

          <div className="report-upload-confirm-bar">
            <div>
              <Text strong>{selectedCount} report(s) selected</Text>
              <div><Text type="secondary">Unchecked reports are not saved. Unchanged duplicates are disabled automatically.</Text></div>
            </div>
            <Space wrap>
              <Button danger icon={<DeleteOutlined />} loading={cancelling} onClick={cancelPreview}>Cancel preview</Button>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                loading={saving}
                disabled={!selectedCount}
                onClick={confirmSave}
              >
                Confirm & save selected
              </Button>
            </Space>
          </div>
        </>
      )}

      {lastCommit ? (
        <Alert
          type={lastCommit.failed ? 'warning' : 'success'}
          showIcon
          message="Reviewed import result"
          description={`Imported ${lastCommit.imported} · Updated ${lastCommit.updated} · Skipped ${lastCommit.skipped} · Failed ${lastCommit.failed}`}
        />
      ) : null}

      <Drawer
        width={1040}
        title={detailReport?.reportNumber || detailReport?.title || 'Complete extraction preview'}
        open={Boolean(detailReport)}
        onClose={() => setDetailReport(null)}
        extra={<Tag color="blue">Preview only · not saved</Tag>}
      >
        {detailReport ? <PreviewDetails report={detailReport} /> : null}
      </Drawer>
    </div>
  );
};

const PreviewSummary: React.FC<{ report: ReportUploadPreviewItem }> = ({ report }) => (
  <div className="report-upload-expanded">
    <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
      <Descriptions.Item label="Title" span={3}>{report.title || '—'}</Descriptions.Item>
      <Descriptions.Item label="Provider">{report.provider || '—'}</Descriptions.Item>
      <Descriptions.Item label="Urgency">{report.urgency || '—'}</Descriptions.Item>
      <Descriptions.Item label="Affected systems">{report.affectedSystems}</Descriptions.Item>
      <Descriptions.Item label="Finding type"><Text code>{report.finding}</Text></Descriptions.Item>
      <Descriptions.Item label="CVEs">{renderTags(report.cves)}</Descriptions.Item>
      <Descriptions.Item label="Recommendations">{report.recommendations}</Descriptions.Item>
      <Descriptions.Item label="Effect" span={3}>{report.effect || '—'}</Descriptions.Item>
    </Descriptions>
    <Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
      This is the compact view. Use <Text strong>View full extraction</Text> to inspect every normalized field, all affected-system rows, indicators, recommendations and the normalized JSON.
    </Paragraph>
  </div>
);

const PreviewDetails: React.FC<{ report: ReportUploadPreviewItem }> = ({ report }) => {
  const record = report.record;

  return (
    <div className="report-upload-expanded">
      <Alert
        type="info"
        showIcon
        message="Complete parser output"
        description="Everything below comes from the local deterministic DOCX extraction. The final source storage path can be assigned when you confirm the save."
      />

      <Divider>Report metadata</Divider>
      <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
        <Descriptions.Item label="Save action"><Tag color={actionColor[report.action]}>{report.action}</Tag></Descriptions.Item>
        <Descriptions.Item label="File"><Text code>{report.file}</Text></Descriptions.Item>
        <Descriptions.Item label="Report no.">{record.reportNumber || '—'}</Descriptions.Item>
        <Descriptions.Item label="Title" span={3}>{record.title || '—'}</Descriptions.Item>
        <Descriptions.Item label="Report date">{record.reportDateRaw || '—'}</Descriptions.Item>
        <Descriptions.Item label="Parsed Y/M/D">{[record.year, record.month, record.day].filter((value) => value != null).join('/') || '—'}</Descriptions.Item>
        <Descriptions.Item label="Report type"><Tag>{record.reportType}</Tag></Descriptions.Item>
        <Descriptions.Item label="Provider">{record.provider || '—'}</Descriptions.Item>
        <Descriptions.Item label="Contact">{record.contact || '—'}</Descriptions.Item>
        <Descriptions.Item label="Effect">{record.effect || '—'}</Descriptions.Item>
      </Descriptions>

      <Divider>Target, severity and urgency</Divider>
      <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
        <Descriptions.Item label="Organization">{record.target.organization || '—'}</Descriptions.Item>
        <Descriptions.Item label="Normalized IP"><Text code>{record.target.ip || '—'}</Text></Descriptions.Item>
        <Descriptions.Item label="Raw IP"><Text code>{record.target.rawIp || '—'}</Text></Descriptions.Item>
        <Descriptions.Item label="Severity raw">{record.severity.raw || '—'}</Descriptions.Item>
        <Descriptions.Item label="Severity score">{record.severity.score ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="Severity level"><Tag color={severityColor[record.severity.level] || 'default'}>{record.severity.level}</Tag></Descriptions.Item>
        <Descriptions.Item label="Urgency raw">{record.urgency.raw || '—'}</Descriptions.Item>
        <Descriptions.Item label="Urgency normalized"><Tag>{record.urgency.normalized}</Tag></Descriptions.Item>
      </Descriptions>

      <Divider>Finding classification</Divider>
      <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
        <Descriptions.Item label="Finding type"><Text code>{record.finding.type}</Text></Descriptions.Item>
        <Descriptions.Item label="Finding name">{record.finding.name || '—'}</Descriptions.Item>
        <Descriptions.Item label="Finding category">{record.finding.category || '—'}</Descriptions.Item>
        <Descriptions.Item label="CWE">{record.finding.cwe || '—'}</Descriptions.Item>
        <Descriptions.Item label="Vulnerability normalized">{record.vulnerability.normalizedName || '—'}</Descriptions.Item>
        <Descriptions.Item label="Vulnerability category">{record.vulnerability.category || '—'}</Descriptions.Item>
        <Descriptions.Item label="All report CVEs" span={2}>{renderTags(record.cves)}</Descriptions.Item>
        <Descriptions.Item label="Affected CVEs">{renderTags(record.affectedCves)}</Descriptions.Item>
      </Descriptions>

      <Divider>Description extracted</Divider>
      <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{record.description || 'No description extracted.'}</Paragraph>

      <Divider>Conclusion extracted</Divider>
      <Paragraph style={{ whiteSpace: 'pre-wrap' }}>{record.conclusion || 'No conclusion extracted.'}</Paragraph>

      <Divider>Affected systems / event rows ({record.affectedSystems.length})</Divider>
      {record.affectedSystems.length ? (
        <Table
          rowKey={(_, index) => String(index)}
          size="small"
          pagination={false}
          dataSource={record.affectedSystems}
          scroll={{ x: 1900 }}
          columns={[
            { title: 'Organization', dataIndex: 'organization', width: 220, ellipsis: true },
            { title: 'IP', dataIndex: 'ip', width: 130, render: (value, row) => <Text code>{value || row.rawIp || '—'}</Text> },
            { title: 'Domain', dataIndex: 'domain', width: 170, ellipsis: true },
            { title: 'Method', dataIndex: 'method', width: 85 },
            { title: 'Parameter', dataIndex: 'parameter', width: 120 },
            { title: 'Service', dataIndex: 'service', width: 160, ellipsis: true },
            { title: 'Port', dataIndex: 'port', width: 75 },
            { title: 'URL / path', dataIndex: 'url', width: 280, ellipsis: true },
            { title: 'Additional URLs', dataIndex: 'additionalUrls', width: 260, render: (value: string[]) => value?.length ? value.join(' · ') : '—' },
            { title: 'Packets', dataIndex: 'packetCount', width: 120 },
            { title: 'Participant IPs', dataIndex: 'participantIpCount', width: 120 },
            { title: 'Traffic', dataIndex: 'trafficVolumeRaw', width: 110 },
            { title: 'Event date', dataIndex: 'eventDateRaw', width: 110 },
            { title: 'Time range', dataIndex: 'timeRange', width: 130 },
            { title: 'Version', dataIndex: 'softwareVersion', width: 100 },
            { title: 'Reported finding', dataIndex: 'reportedFinding', width: 220, ellipsis: true },
            { title: 'CVEs', dataIndex: 'cves', width: 220, render: (value: string[]) => renderTags(value) },
          ]}
        />
      ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No affected-system rows extracted" />}

      <Divider>Phishing infrastructure ({record.phishingInfrastructure.length})</Divider>
      {record.phishingInfrastructure.length ? (
        <Table
          rowKey={(_, index) => String(index)}
          size="small"
          pagination={false}
          dataSource={record.phishingInfrastructure}
          columns={[
            { title: 'Domain', dataIndex: 'domain' },
            { title: 'IP', dataIndex: 'ip', render: (value, row) => <Text code>{value || row.rawIp || '—'}</Text> },
            { title: 'URL', dataIndex: 'url' },
            { title: 'Page title', dataIndex: 'pageTitle' },
          ]}
        />
      ) : <Text type="secondary">No phishing infrastructure extracted.</Text>}

      <Divider>Indicators / IOCs ({record.indicators.length})</Divider>
      {record.indicators.length ? (
        <Table
          rowKey={(_, index) => String(index)}
          size="small"
          pagination={false}
          dataSource={record.indicators}
          columns={[
            { title: 'Type', dataIndex: 'type', width: 140 },
            { title: 'Role', dataIndex: 'role', width: 160, render: (value) => value || '—' },
            { title: 'Value', dataIndex: 'value', render: (value) => <Text code>{value}</Text> },
          ]}
        />
      ) : <Text type="secondary">No standalone indicators extracted.</Text>}

      <Divider>Recommendations ({record.recommendations.length})</Divider>
      <List
        size="small"
        dataSource={record.recommendations}
        locale={{ emptyText: 'No recommendations extracted.' }}
        renderItem={(item, index) => <List.Item>{index + 1}. {item}</List.Item>}
      />

      <Divider>Extraction diagnostics</Divider>
      <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
        <Descriptions.Item label="Parser version"><Text code>{record.extraction.parserVersion || '—'}</Text></Descriptions.Item>
        <Descriptions.Item label="Paragraphs">{record.extraction.paragraphCount}</Descriptions.Item>
        <Descriptions.Item label="Tables">{record.extraction.tableCount}</Descriptions.Item>
        <Descriptions.Item label="Organization mismatch">{record.extraction.organizationMismatch ? <Tag color="warning">yes</Tag> : 'no'}</Descriptions.Item>
        <Descriptions.Item label="IP mismatch">{record.extraction.ipMismatch ? <Tag color="warning">yes</Tag> : 'no'}</Descriptions.Item>
        <Descriptions.Item label="Source size">{formatBytes(record.source.sizeBytes)}</Descriptions.Item>
        <Descriptions.Item label="SHA-256" span={3}><Text code>{record.source.sha256 || '—'}</Text></Descriptions.Item>
      </Descriptions>

      {record.extraction.warnings.length ? (
        <Alert
          className="report-upload-warning"
          type="warning"
          showIcon
          message="Extraction review flags"
          description={record.extraction.warnings.join(' · ')}
        />
      ) : (
        <Alert type="success" showIcon message="No extraction warnings for this report" />
      )}

      <Divider>Normalized JSON</Divider>
      <Paragraph type="secondary">
        This is the structured parser result used by the reviewed import flow. It is useful for checking exactly which fields were recognized before saving.
      </Paragraph>
      <details>
        <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Show normalized JSON</summary>
        <pre style={{ marginTop: 12, padding: 14, overflow: 'auto', maxHeight: 520, borderRadius: 8, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
          {JSON.stringify(record, null, 2)}
        </pre>
      </details>
    </div>
  );
};

function renderTags(values?: string[]) {
  if (!values?.length) return '—';
  return <Space size={[4, 4]} wrap>{values.map((value) => <Tag key={value}>{value}</Tag>)}</Space>;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export default ReportUploadReview;
