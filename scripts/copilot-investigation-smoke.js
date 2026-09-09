require("dotenv").config();

const { settings } = require("../src/core/config");
const { createLogger } = require("../src/core/logging");
const { connectMongo, disconnectMongo } = require("../src/database/mongo");
const { CopilotService } = require("../src/services/copilotService");

const logger = createLogger(settings.logLevel);

async function main() {
  const connected = await connectMongo(logger);
  if (!connected) {
    throw new Error("MongoDB is required for the Copilot investigation smoke test");
  }

  const service = new CopilotService();
  const firstQuestion = "آخرین Alert امروز چی بود؟";
  const first = await service.query(firstQuestion);

  if (!first?.state?.focus || first.state.focus.entityType !== "alert") {
    throw new Error("Latest-alert query did not establish an alert focus in conversation state");
  }

  const secondQuestion = "یه تحلیل خلاصه ازش بده؛ بگو از چه IP به چه مقصد و سازمانی بوده، چرا مهمه و چه اقداماتی باید انجام بشه.";
  const second = await service.query(secondQuestion, {
    state: first.state,
    history: [
      { role: "user", content: firstQuestion },
      { role: "assistant", content: first.answer },
    ],
  });

  if (second.tool !== "get_soc_entity_context") {
    throw new Error(`Expected get_soc_entity_context, got ${second.tool || "none"}`);
  }

  if (second.result?.entity?.type !== "alert") {
    throw new Error("Focused follow-up did not return alert investigation context");
  }

  const result = second.result;
  const output = {
    success: true,
    firstTurn: {
      question: firstQuestion,
      answer: first.answer,
      focus: first.state.focus,
    },
    followUp: {
      question: secondQuestion,
      answer: second.answer,
      tool: second.tool,
      alertId: result.entity?.id || null,
      traffic: result.traffic || null,
      organization: result.relatedEntities?.organization
        || result.destination?.asset?.organization
        || null,
      verdict: result.analysis?.verdict || null,
      riskAssessment: result.analysis?.riskAssessment || null,
      mitre: result.mitre || [],
      threatEvidence: {
        source: result.source?.threat || null,
        destination: result.destination?.threat || null,
      },
      relationshipAnalysis: result.relationshipAnalysis || null,
      recommendedActions: result.recommendedActions || [],
      evidencePolicy: result.evidencePolicy || null,
    },
    state: second.state,
    metadata: second.metadata,
  };

  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
}

main()
  .catch((error) => {
    process.stderr.write(JSON.stringify({
      success: false,
      error: String(error?.message || error),
      cause: error?.cause ? String(error.cause?.message || error.cause) : undefined,
    }, null, 2) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectMongo(logger);
  });
