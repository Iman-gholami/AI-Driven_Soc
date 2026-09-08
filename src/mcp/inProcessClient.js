const { SocMcpServer, PROTOCOL_VERSION } = require("./socMcpServer");

class InProcessMcpClient {
  constructor({ server = new SocMcpServer() } = {}) {
    this.server = server;
    this.nextId = 1;
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;
    const response = await this.request("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "ai-driven-soc-copilot", version: "1.0.0" },
    });
    if (!response?.protocolVersion) throw new Error("MCP initialization failed");
    await this.server.handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" });
    this.initialized = true;
  }

  async listTools() {
    await this.initialize();
    const result = await this.request("tools/list", {});
    return result?.tools || [];
  }

  async callTool(name, args = {}) {
    await this.initialize();
    const result = await this.request("tools/call", { name, arguments: args });
    if (result?.isError) {
      throw new Error(result.structuredContent?.error || result.content?.[0]?.text || "MCP tool failed");
    }
    return result?.structuredContent ?? parseToolText(result?.content);
  }

  async request(method, params) {
    const id = this.nextId++;
    const response = await this.server.handleMessage({ jsonrpc: "2.0", id, method, params });
    if (!response) throw new Error("MCP server returned no response");
    if (response.error) throw new Error(response.error.message || "MCP request failed");
    return response.result;
  }
}

function parseToolText(content) {
  const text = Array.isArray(content) ? content.find((item) => item?.type === "text")?.text : null;
  if (!text) return null;
  try { return JSON.parse(text); } catch (_) { return { text }; }
}

module.exports = { InProcessMcpClient };
