const { SocQueryService } = require("../services/socQueryService");
const { describeSocSchema } = require("../copilot/schemaCatalog");
const { SocEntityContextService } = require("../services/socEntityContextService");
const { SocMetricService } = require("../services/socMetricService");
const { SocCorrelationService } = require("../services/socCorrelationService");

const {
  QUERY_INPUT_SCHEMA,
  BATCH_INPUT_SCHEMA,
  ENTITY_CONTEXT_INPUT_SCHEMA,
  METRIC_ANALYSIS_INPUT_SCHEMA,
  CORRELATION_INPUT_SCHEMA,
  SOC_MCP_TOOLS,
} = require("./toolDefinitions");

const PROTOCOL_VERSION = "2025-11-25";

class SocMcpServer {
  constructor({
    queryService = new SocQueryService(),
    entityContextService = new SocEntityContextService(),
    metricService = new SocMetricService({ queryService }),
    correlationService = new SocCorrelationService(),
  } = {}) {
    this.queryService = queryService;
    this.entityContextService = entityContextService;
    this.metricService = metricService;
    this.correlationService = correlationService;
  }

  listTools() {
    return SOC_MCP_TOOLS;
  }

  async callTool(name, args = {}) {
    if (name === "describe_soc_schema") {
      const data = describeSocSchema(args.dataset);
      if (!data) throw new Error("Unknown dataset: " + String(args.dataset || ""));
      return toolSuccess(data);
    }

    if (name === "query_soc_data") {
      const data = await this.queryService.execute(args);
      return toolSuccess(data);
    }

    if (name === "correlate_soc_entities") {
      const data = await this.correlationService.correlate(args);
      return toolSuccess(data);
    }

    if (name === "analyze_soc_metric") {
      const data = await this.metricService.analyze(args);
      return toolSuccess(data);
    }

    if (name === "get_soc_entity_context") {
      const data = await this.entityContextService.getContext(args);
      return toolSuccess(data);
    }

    if (name === "query_soc_data_batch") {
      const queries = Array.isArray(args.queries) ? args.queries : [];
      if (queries.length < 2 || queries.length > 5) {
        throw new Error("query_soc_data_batch requires between 2 and 5 queries");
      }

      const results = [];
      for (const query of queries) {
        results.push(await this.queryService.execute(query));
      }

      return toolSuccess({
        count: results.length,
        results,
        metadata: { readOnly: true },
      });
    }

    throw new Error("Unknown MCP tool: " + name);
  }

  async handleMessage(message) {
    if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
      return message?.id === undefined ? null : rpcError(message?.id ?? null, -32600, "Invalid Request");
    }

    const id = message.id;
    const method = message.method;

    if (method === "notifications/initialized") return null;

    if (id === undefined) return null;

    try {
      if (method === "initialize") {
        return rpcResult(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "ai-driven-soc-mcp", version: "1.0.0" },
          instructions: "Read-only SOC data access. Use describe_soc_schema, query_soc_data, query_soc_data_batch, correlate_soc_entities, analyze_soc_metric, or get_soc_entity_context only.",
        });
      }

      if (method === "ping") return rpcResult(id, {});
      if (method === "tools/list") return rpcResult(id, { tools: this.listTools() });

      if (method === "tools/call") {
        const name = message.params?.name;
        const args = message.params?.arguments || {};
        try {
          return rpcResult(id, await this.callTool(name, args));
        } catch (error) {
          return rpcResult(id, toolFailure(error));
        }
      }

      return rpcError(id, -32601, "Method not found");
    } catch (error) {
      return rpcError(id, -32603, String(error?.message || error || "Internal error"));
    }
  }
}

function toolSuccess(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data,
    isError: false,
  };
}

function toolFailure(error) {
  const message = String(error?.message || error || "Tool execution failed");
  return {
    content: [{ type: "text", text: message }],
    structuredContent: { error: message },
    isError: true,
  };
}

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

module.exports = {
  PROTOCOL_VERSION,
  QUERY_INPUT_SCHEMA,
  BATCH_INPUT_SCHEMA,
  ENTITY_CONTEXT_INPUT_SCHEMA,
  METRIC_ANALYSIS_INPUT_SCHEMA,
  CORRELATION_INPUT_SCHEMA,
  SOC_MCP_TOOLS,
  SocMcpServer,
  toolSuccess,
  toolFailure,
};
