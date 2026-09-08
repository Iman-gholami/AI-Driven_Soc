import React, { useMemo, useRef, useState } from 'react';
import {
  CloseOutlined,
  RobotOutlined,
  SendOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { Button, Input, Spin, Tag, Typography } from 'antd';
import { api } from '../../api/client';
import type { CopilotBatchResult, CopilotChatHistoryItem, CopilotQueryResult, CopilotResponse } from '../../types';

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
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      text: 'از داده‌های SOC سؤال بپرس. پاسخ‌های آماری از Queryهای read-only و validate‌شده روی داده‌های واقعی تولید می‌شوند.',
    },
  ]);
  const sequence = useRef(0);

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
      const response = await api.queryCopilot(question, history);
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
            <Button
              type="text"
              icon={<CloseOutlined />}
              onClick={() => setOpen(false)}
              aria-label="Close SOC Copilot"
            />
          </header>

          <div className="soc-copilot-safety">
            <SafetyCertificateOutlined />
            <span>Queries are validated against the SOC schema catalog. No raw MongoDB execution.</span>
          </div>

          <div className="soc-copilot-messages">
            {messages.map((message) => (
              <div key={message.id} className={`soc-copilot-message is-${message.role}`}>
                <div className={`soc-copilot-bubble ${message.error ? 'is-error' : ''}`} dir="auto">
                  {message.text}
                </div>

                {message.role === 'assistant' && message.response?.result && (
                  <CopilotEvidence response={message.response} />
                )}
              </div>
            ))}

            {loading && (
              <div className="soc-copilot-thinking">
                <Spin size="small" />
                <span>Querying SOC data…</span>
              </div>
            )}
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

function isBatchResult(
  result: CopilotQueryResult | CopilotBatchResult,
): result is CopilotBatchResult {
  return Array.isArray((result as CopilotBatchResult).results);
}

const CopilotEvidence: React.FC<{ response: CopilotResponse }> = ({ response }) => {
  if (!response.result) return null;

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

export default SocCopilot;
