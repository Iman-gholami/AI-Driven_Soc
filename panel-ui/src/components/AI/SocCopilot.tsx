import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CloseOutlined,
  DeleteOutlined,
  RobotOutlined,
  SendOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { Button, Input, Spin, Tag, Typography } from 'antd';
import { api } from '../../api/client';
import type {
  CopilotBatchResult,
  CopilotChatHistoryItem,
  CopilotConversationState,
  CopilotCorrelationResult,
  CopilotEntityContextResult,
  CopilotMetricResult,
  CopilotQueryResult,
  CopilotResponse,
} from '../../types';

const { Text } = Typography;
const { TextArea } = Input;

type ChatMessage = {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  response?: CopilotResponse;
  error?: boolean;
};

const suggestions = [
  'در 24 ساعت گذشته چند Alert داشتیم؟',
  'بیشترین Signature در 7 روز گذشته چی بوده؟',
  'امروز چند Alert مربوط به SYN Flood داشتیم؟',
  'کدام سازمان بیشترین Alert دارای direct threat match را داشته؟',
];

const SocCopilot: React.FC = () => {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationState, setConversationState] = useState<CopilotConversationState>({});
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      text: 'از داده‌های SOC سؤال بپرس. پاسخ‌های آماری از Queryهای read-only و validate‌شده روی داده‌های واقعی تولید می‌شوند.',
    },
  ]);
  const sequence = useRef(0);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, loading, open]);

  const canSend = useMemo(() => input.trim().length > 0 && !loading, [input, loading]);

  const send = async (preset?: string) => {
    const question = String(preset ?? input).trim();
    if (!question || loading) return;

    const history: CopilotChatHistoryItem[] = messages
      .filter((message) => message.id !== 'welcome' && !message.error)
      .slice(-8)
      .map((message) => ({
        role: message.role,
        content: message.text,
      }));

    sequence.current += 1;
    const userId = `user-${sequence.current}`;
    setMessages((current) => [...current, { id: userId, role: 'user', text: question }]);
    setInput('');
    setLoading(true);

    try {
      const response = await api.queryCopilot(question, history, conversationState);
      setConversationState(response.state || conversationState);
      sequence.current += 1;
      setMessages((current) => [
        ...current,
        {
          id: `assistant-${sequence.current}`,
          role: 'assistant',
          text: response.answer,
          response,
        },
      ]);
    } catch (error: any) {
      sequence.current += 1;
      const detail = error?.response?.data?.detail || error?.message || 'Copilot query failed';
      setMessages((current) => [
        ...current,
        {
          id: `assistant-${sequence.current}`,
          role: 'assistant',
          text: String(detail),
          error: true,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {!open && (
        <button className="soc-copilot-launcher" type="button" onClick={() => setOpen(true)}>
          <RobotOutlined />
          <span>Ask SOC Copilot</span>
        </button>
      )}

      {open && (
        <section className="soc-copilot-panel" aria-label="SOC Copilot">
          <header className="soc-copilot-header">
            <div className="soc-copilot-heading">
              <span className="soc-copilot-icon"><RobotOutlined /></span>
              <div>
                <strong>AI SOC Copilot</strong>
                <span>Read-only analytics · MCP tools</span>
              </div>
            </div>
            <div className="soc-copilot-header-actions">
              <Button
                type="text"
                icon={<DeleteOutlined />}
                onClick={() => {
                  setMessages([
                    {
                      id: 'welcome',
                      role: 'assistant',
                      text: 'از داده‌های SOC سؤال بپرس. پاسخ‌های آماری از Queryهای read-only و validate‌شده روی داده‌های واقعی تولید می‌شوند.',
                    },
                  ]);
                  setInput('');
                  setConversationState({});
                }}
                aria-label="Clear SOC Copilot conversation"
              />
              <Button
                type="text"
                icon={<CloseOutlined />}
                onClick={() => setOpen(false)}
                aria-label="Close SOC Copilot"
              />
            </div>
          </header>

          <div className="soc-copilot-safety">
            <SafetyCertificateOutlined />
            <span>Queries are validated against the SOC schema catalog. No raw MongoDB execution.</span>
          </div>

          <div className="soc-copilot-messages">
            {messages.map((message) => (
              <div key={message.id} className={`soc-copilot-message is-${message.role}`}>
                <div
                  className={`soc-copilot-bubble ${message.error ? 'is-error' : ''}`}
                  dir="auto"
                  lang={/[\u0600-\u06FF]/.test(message.text) ? 'fa' : 'en'}
                >
                  {message.text}
                </div>

                {message.role === 'assistant' && message.response?.result && (
                  <>
                    <CopilotEvidence response={message.response} />
                    <CopilotStructuredResult response={message.response} />
                    {message.response.queryPlan && (
                      <details className="soc-copilot-plan">
                        <summary>Validated query plan</summary>
                        <pre>{JSON.stringify(message.response.queryPlan, null, 2)}</pre>
                      </details>
                    )}
                  </>
                )}
              </div>
            ))}

            {loading && (
              <div className="soc-copilot-thinking">
                <Spin size="small" />
                <span>Querying SOC data…</span>
              </div>
            )}
            <div ref={endRef} aria-hidden="true" />
          </div>

          {messages.length <= 1 && (
            <div className="soc-copilot-suggestions">
              <Text type="secondary">Suggested questions</Text>
              {suggestions.map((suggestion) => (
                <button key={suggestion} type="button" onClick={() => send(suggestion)} dir="auto">
                  {suggestion}
                </button>
              ))}
            </div>
          )}

          <footer className="soc-copilot-composer">
            <TextArea
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onPressEnter={(event) => {
                if (!event.shiftKey) {
                  event.preventDefault();
                  void send();
                }
              }}
              autoSize={{ minRows: 1, maxRows: 4 }}
              placeholder="Ask about alerts, rules, IPs, threat intel, MITRE…"
              disabled={loading}
              dir="auto"
            />
            <Button
              type="primary"
              icon={<SendOutlined />}
              disabled={!canSend}
              loading={loading}
              onClick={() => void send()}
              aria-label="Send SOC Copilot question"
            />
          </footer>
        </section>
      )}
    </>
  );
};

type CopilotRenderableResult =
  | CopilotQueryResult
  | CopilotBatchResult
  | CopilotEntityContextResult
  | CopilotMetricResult
  | CopilotCorrelationResult;

function isBatchResult(
  result: CopilotRenderableResult,
): result is CopilotBatchResult {
  return Array.isArray((result as CopilotBatchResult).results);
}

function isEntityContextResult(
  result: CopilotRenderableResult,
): result is CopilotEntityContextResult {
  return Boolean((result as CopilotEntityContextResult).entity?.type);
}

function isMetricResult(result: CopilotRenderableResult): result is CopilotMetricResult {
  return ['compare', 'percentage', 'trend'].includes(String((result as CopilotMetricResult).operation || ''));
}

function isCorrelationResult(result: CopilotRenderableResult): result is CopilotCorrelationResult {
  return (result as CopilotCorrelationResult).operation === 'correlate';
}

const CopilotEvidence: React.FC<{ response: CopilotResponse }> = ({ response }) => {
  if (!response.result) return null;

  if (isMetricResult(response.result)) {
    return (
      <div className="soc-copilot-evidence">
        <Tag>metric</Tag>
        <Tag>{response.result.operation}</Tag>
        {response.metadata?.mcp && <Tag>MCP</Tag>}
      </div>
    );
  }

  if (isCorrelationResult(response.result)) {
    return (
      <div className="soc-copilot-evidence">
        <Tag>correlation</Tag>
        <Tag>{response.result.relationship}</Tag>
        {response.result.timeRange?.label && <Tag>{response.result.timeRange.label}</Tag>}
        {response.metadata?.mcp && <Tag>MCP</Tag>}
      </div>
    );
  }

  if (isEntityContextResult(response.result)) {
    return (
      <div className="soc-copilot-evidence">
        <Tag>{response.result.entity.type}</Tag>
        <Tag>{response.result.entity.id}</Tag>
        <Tag>investigation context</Tag>
        {response.metadata?.mcp && <Tag>MCP</Tag>}
      </div>
    );
  }

  if (isBatchResult(response.result)) {
    return (
      <div className="soc-copilot-evidence">
        <Tag>{response.result.count} queries</Tag>
        {response.result.results.slice(0, 3).map((item, index) => (
          <Tag key={`${item.dataset}-${item.operation}-${index}`}>
            {item.dataset} · {item.operation}
          </Tag>
        ))}
        {response.metadata?.mcp && <Tag>MCP</Tag>}
      </div>
    );
  }

  return (
    <div className="soc-copilot-evidence">
      <Tag>{response.result.dataset}</Tag>
      <Tag>{response.result.operation}</Tag>
      {response.result.timeRange?.label && <Tag>{response.result.timeRange.label}</Tag>}
      {response.metadata?.mcp && <Tag>MCP</Tag>}
    </div>
  );
};

const CopilotStructuredResult: React.FC<{ response: CopilotResponse }> = ({ response }) => {
  if (!response.result) return null;

  if (isMetricResult(response.result)) {
    return <CopilotMetricBlock result={response.result} />;
  }

  if (isCorrelationResult(response.result)) {
    return <CopilotCorrelationBlock result={response.result} />;
  }

  if (isEntityContextResult(response.result)) {
    return <CopilotEntityContextBlock result={response.result} />;
  }

  if (isBatchResult(response.result)) {
    return (
      <div className="soc-copilot-result-stack">
        {response.result.results.slice(0, 5).map((result, index) => (
          <CopilotResultBlock key={`${result.dataset}-${result.operation}-${index}`} result={result} />
        ))}
      </div>
    );
  }

  return <CopilotResultBlock result={response.result} />;
};

const CopilotMetricBlock: React.FC<{ result: CopilotMetricResult }> = ({ result }) => {
  if (result.operation === 'compare') {
    return (
      <div className="soc-copilot-result-block">
        <div className="soc-copilot-result-title">
          <span>comparison</span>
          {result.changePercent !== null && result.changePercent !== undefined && (
            <strong>{result.changePercent.toLocaleString()}%</strong>
          )}
        </div>
        <div className="soc-copilot-result-rows">
          <div className="soc-copilot-result-row">
            <span><em>{result.left?.label || 'left'}</em><b>{Number(result.left?.count || 0).toLocaleString()}</b></span>
          </div>
          <div className="soc-copilot-result-row">
            <span><em>{result.right?.label || 'right'}</em><b>{Number(result.right?.count || 0).toLocaleString()}</b></span>
          </div>
          <div className="soc-copilot-result-row">
            <span><em>difference</em><b>{Number(result.difference || 0).toLocaleString()}</b></span>
          </div>
        </div>
      </div>
    );
  }

  if (result.operation === 'percentage') {
    const displayPercentage = result.percentage === null || result.percentage === undefined
      ? '—'
      : result.percentage.toLocaleString() + '%';
    return (
      <div className="soc-copilot-result-block">
        <div className="soc-copilot-result-title">
          <span>percentage</span>
          <strong>{displayPercentage}</strong>
        </div>
        <div className="soc-copilot-result-rows">
          <div className="soc-copilot-result-row">
            <span><em>{result.numerator?.label || 'numerator'}</em><b>{Number(result.numerator?.count || 0).toLocaleString()}</b></span>
          </div>
          <div className="soc-copilot-result-row">
            <span><em>{result.denominator?.label || 'denominator'}</em><b>{Number(result.denominator?.count || 0).toLocaleString()}</b></span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="soc-copilot-result-block">
      <div className="soc-copilot-result-title">
        <span>{result.bucket || 'trend'} trend</span>
        <strong>{result.points?.length || 0} pts</strong>
      </div>
      <div className="soc-copilot-result-rows">
        {(result.points || []).slice(-8).map((point) => (
          <div className="soc-copilot-result-row" key={point.from}>
            <span><em>{formatCopilotTime(point.from)}</em><b>{point.count.toLocaleString()}</b></span>
          </div>
        ))}
      </div>
    </div>
  );
};

const CopilotCorrelationBlock: React.FC<{ result: CopilotCorrelationResult }> = ({ result }) => (
  <div className="soc-copilot-result-block">
    <div className="soc-copilot-result-title">
      <span>{result.relationship}</span>
      <strong>{result.count.toLocaleString()}</strong>
    </div>
    <div className="soc-copilot-result-rows">
      {result.rows.slice(0, 5).map((row, index) => (
        <div className="soc-copilot-result-row" key={index}>
          {Object.entries(row).slice(0, 5).map(([key, value]) => (
            <span key={key}>
              <em>{key}</em>
              <b dir="auto">{formatCopilotValue(value)}</b>
            </span>
          ))}
        </div>
      ))}
    </div>
  </div>
);

function formatCopilotTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('fa-IR', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}
const CopilotEntityContextBlock: React.FC<{ result: CopilotEntityContextResult }> = ({ result }) => {
  const related = result.relatedEntities || {};
  return (
    <div className="soc-copilot-result-block">
      <div className="soc-copilot-result-title">
        <span>{result.entity.type}</span>
        <strong dir="auto">{result.entity.id}</strong>
      </div>
      <div className="soc-copilot-result-rows">
        {related.sourceIp && (
          <div className="soc-copilot-result-row">
            <span><em>source IP</em><b>{related.sourceIp}</b></span>
          </div>
        )}
        {related.destinationIp && (
          <div className="soc-copilot-result-row">
            <span><em>destination IP</em><b>{related.destinationIp}</b></span>
          </div>
        )}
        {related.organization && (
          <div className="soc-copilot-result-row">
            <span><em>organization</em><b dir="auto">{related.organization}</b></span>
          </div>
        )}
        {related.ruleId && (
          <div className="soc-copilot-result-row">
            <span><em>rule</em><b>{related.ruleId}</b></span>
          </div>
        )}
      </div>
    </div>
  );
};

const CopilotResultBlock: React.FC<{ result: CopilotQueryResult }> = ({ result }) => {
  const rows = Array.isArray(result.data?.rows) ? result.data.rows.slice(0, 5) : [];
  const isCountOnly = result.operation === 'count';

  return (
    <div className="soc-copilot-result-block">
      <div className="soc-copilot-result-title">
        <span>{result.dataset}</span>
        {isCountOnly && <strong>{Number(result.data?.count || 0).toLocaleString()}</strong>}
      </div>

      {rows.length > 0 && (
        <div className="soc-copilot-result-rows">
          {rows.map((row, index) => (
            <div className="soc-copilot-result-row" key={index}>
              {Object.entries(row).slice(0, 4).map(([key, value]) => (
                <span key={key}>
                  <em>{key}</em>
                  <b dir="auto">{formatCopilotValue(value)}</b>
                </span>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

function formatCopilotValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'number') return value.toLocaleString();
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

export default SocCopilot;
