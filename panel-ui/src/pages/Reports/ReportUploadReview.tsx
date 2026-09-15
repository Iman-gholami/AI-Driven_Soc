import React, { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
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
            description={`This review session expires at ${new Date(preview.expiresAt).toLocaleTimeString()}. Select the reports you trust, inspect the expanded rows, then confirm.`}
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
                scroll={{ x: 1180 }}
                expandable={{
                  expandedRowRender: (record) => <PreviewDetails report={record} />,
                  rowExpandable: () => true,
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
    </div>
  );
};

const PreviewDetails: React.FC<{ report: ReportUploadPreviewItem }> = ({ report }) => (
  <div className="report-upload-expanded">
    <Descriptions bordered size="small" column={{ xs: 1, md: 2, xl: 3 }}>
      <Descriptions.Item label="Title" span={3}>{report.title || '—'}</Descriptions.Item>
      <Descriptions.Item label="Provider">{report.provider || '—'}</Descriptions.Item>
      <Descriptions.Item label="Urgency">{report.urgency || '—'}</Descriptions.Item>
      <Descriptions.Item label="Affected systems">{report.affectedSystems}</Descriptions.Item>
      <Descriptions.Item label="Finding type"><Text code>{report.finding}</Text></Descriptions.Item>
      <Descriptions.Item label="CVEs">{report.cves?.length ? report.cves.map((cve) => <Tag key={cve}>{cve}</Tag>) : '—'}</Descriptions.Item>
      <Descriptions.Item label="Recommendations">{report.recommendations}</Descriptions.Item>
      <Descriptions.Item label="Effect" span={3}>{report.effect || '—'}</Descriptions.Item>
    </Descriptions>

    {report.descriptionPreview ? (
      <div className="report-upload-text-block">
        <Text strong>Description extracted</Text>
        <Paragraph>{report.descriptionPreview}</Paragraph>
      </div>
    ) : null}

    {report.conclusionPreview ? (
      <div className="report-upload-text-block">
        <Text strong>Conclusion extracted</Text>
        <Paragraph>{report.conclusionPreview}</Paragraph>
      </div>
    ) : null}

    {report.affectedSystemPreview?.length ? (
      <>
        <Divider orientation="start">Affected system preview</Divider>
        <Table
          rowKey={(_, index) => String(index)}
          size="small"
          pagination={false}
          dataSource={report.affectedSystemPreview}
          scroll={{ x: 850 }}
          columns={[
            { title: 'Organization', dataIndex: 'organization', width: 220, ellipsis: true },
            { title: 'IP', dataIndex: 'ip', width: 130, render: (value) => value ? <Text code>{value}</Text> : '—' },
            { title: 'Domain', dataIndex: 'domain', width: 170, ellipsis: true },
            { title: 'Service', dataIndex: 'service', width: 140, ellipsis: true },
            { title: 'Port', dataIndex: 'port', width: 75 },
            { title: 'URL', dataIndex: 'url', width: 260, ellipsis: true },
            { title: 'Version', dataIndex: 'softwareVersion', width: 110 },
          ]}
        />
      </>
    ) : null}

    {report.phishingInfrastructure?.length ? (
      <>
        <Divider orientation="start">Phishing infrastructure / IOC preview</Divider>
        <List
          size="small"
          dataSource={report.phishingInfrastructure}
          renderItem={(item) => (
            <List.Item>
              <Space wrap>
                {item.domain ? <Tag>{item.domain}</Tag> : null}
                {item.ip ? <Text code>{item.ip}</Text> : null}
                {item.url ? <Text>{item.url}</Text> : null}
                {item.pageTitle ? <Text type="secondary">{item.pageTitle}</Text> : null}
              </Space>
            </List.Item>
          )}
        />
      </>
    ) : null}

    {report.recommendationPreview?.length ? (
      <>
        <Divider orientation="start">Recommendation preview</Divider>
        <List
          size="small"
          dataSource={report.recommendationPreview}
          renderItem={(item, index) => <List.Item>{index + 1}. {item}</List.Item>}
        />
      </>
    ) : null}

    {report.warnings?.length ? (
      <Alert
        className="report-upload-warning"
        type="warning"
        showIcon
        message="Extraction review flags"
        description={report.warnings.join(' · ')}
      />
    ) : null}
  </div>
);

export default ReportUploadReview;
