const { SocQueryService } = require("../services/socQueryService");
const { describeSocSchema } = require("../copilot/schemaCatalog");

const PROTOCOL_VERSION = "2025-11-25";

const QUERY_INPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["dataset", "operation"],
  properties: {
    dataset: {
      type: "string",
      enum: ["alerts", "detection_rules", "ip_assets", "threat_intelligence", "dataset_states", "mitre_coverage_snapshots", "mitre_techniques"],
    },
    operation: { type: "string", enum: ["count", "aggregate", "list", "distinct"] },
    timeRange: {
      type: "object",
      additionalProperties: false,
      properties: {
        type: {
          type: "string",
          enum: ["all", "today", "yesterday", "last_n_hours", "last_n_days", "this_week", "previous_week", "between"],
        },
        value: { type: "integer", minimum: 1, maximum: 3650 },
        from: { type: "string" },
        to: { type: "string" },
        field: { type: "string" },
      },
      required: ["type"],
    },
    filters: {
      type: "array",
      maxItems: 20,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["field", "operator"],
        properties: {
          field: { type: "string" },
          operator: { type: "string", enum: ["eq", "neq", "contains", "in", "exists", "gt", "gte", "lt", "lte"] },
          value: {},
        },
      },
    },
    groupBy: { type: "array", maxItems: 4, items: { type: "string" } },
    metrics: {
      type: "array",
      maxItems: 8,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["type"],
        properties: {
          type: { type: "string", enum: ["count", "sum", "avg", "min", "max"] },
          field: { type: "string" },
          alias: { type: "string", pattern: "^[A-Za-z_][A-Za-z0-9_]{0,63}$" },
        },
      },
    },
    select: { type: "array", maxItems: 20, items: { type: "string" } },
    sort: {
      type: "array",
      maxItems: 4,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["field", "direction"],
        properties: {
          field: { type: "string" },
          direction: { type: "string", enum: ["asc", "desc"] },
        },
      },
    },
    limit: { type: "integer", minimum: 1, maximum: 100 },
  },
};

const BATCH_INPUT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["queries"],
  properties: {
    queries: {
      type: "array",
      minItems: 2,
      maxItems: 5,
      items: QUERY_INPUT_SCHEMA,
    },
  },
};

const SOC_MCP_TOOLS = [
  {
    name: "describe_soc_schema",
    description: "Describe approved SOC datasets and fields. Use this before querying when field or dataset semantics are uncertain.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        dataset: {
          type: "string",
          enum: ["alerts", "detection_rules", "ip_assets", "threat_intelligence", "dataset_states", "mitre_coverage_snapshots", "mitre_techniques"],
        },
      },
    },
    annotations: {
      title: "Describe SOC schema",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "query_soc_data",
    description: "Run a validated read-only query against approved SOC datasets. Never accepts raw MongoDB or JavaScript.",
    inputSchema: QUERY_INPUT_SCHEMA,
    annotations: {
      title: "Query SOC data",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "query_soc_data_batch",
    description: "Run 2 to 5 independent validated read-only SOC queries when one analyst question requires multiple datasets or comparisons.",
    inputSchema: BATCH_INPUT_SCHEMA,
    annotations: {
      title: "Batch query SOC data",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
];

class SocMcpServer {
  constructor({ queryService = new SocQueryService() } = {}) {
    this.queryService = queryService;
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
          instructions: "Read-only SOC data access. Use describe_soc_schema, query_soc_data, or query_soc_data_batch only.",
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
  SOC_MCP_TOOLS,
  SocMcpServer,
  toolSuccess,
  toolFailure,
};
