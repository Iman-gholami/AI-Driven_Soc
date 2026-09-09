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

  const primaryQuestion = "آخرین Alert امروز چی بود؟";
  let selectedQuestion = primaryQuestion;
  let selected = await service.query(primaryQuestion);
  const firstTodayResult = selected;
  let selectionScope = "today";

  if (!hasAlertFocus(selected)) {
    const primaryRows = selected?.result?.data?.rows;
    const primaryIsEmptyAlertList = selected?.tool === "query_soc_data"
      && selected?.result?.dataset === "alerts"
      && selected?.result?.operation === "list"
      && Array.isArray(primaryRows)
      && primaryRows.length === 0;

    if (!primaryIsEmptyAlertList) {
      throw new Error(
        "Latest-alert query failed before focus resolution: "
        + JSON.stringify(buildDiagnostic(selected)),
      );
    }

    selectedQuestion = "آخرین Alert تحلیل‌شده موجود چی بود؟";
    selectionScope = "all_time_analyzed_fallback";
    selected = await service.query(selectedQuestion);

    if (!hasAlertFocus(selected)) {
      throw new Error(
        "No alert could be selected for investigation. The today query was empty and the all-time fallback also produced no alert focus: "
        + JSON.stringify({
          today: buildDiagnostic(firstTodayResult),
          fallback: buildDiagnostic(selected),
        }),
      );
    }
  }

  const secondQuestion = "یه تحلیل خلاصه ازش بده؛ بگو از چه IP به چه مقصد و سازمانی بوده، چرا مهمه و چه اقداماتی باید انجام بشه.";
  let second = await runFocusedFollowUp(service, {
    selected,
    selectedQuestion,
    secondQuestion,
  });

  if (second.result?.analysisAvailable === false && selectionScope === "today") {
    selectedQuestion = "آخرین Alert تحلیل‌شده موجود چی بود؟";
    selectionScope = "all_time_analyzed_fallback";
    selected = await service.query(selectedQuestion);

    if (!hasAlertFocus(selected)) {
      throw new Error(
        "The latest alert today has no persisted analysis and no analyzed alert could be selected for the investigation fallback: "
        + JSON.stringify(buildDiagnostic(selected)),
      );
    }

    second = await runFocusedFollowUp(service, {
      selected,
      selectedQuestion,
      secondQuestion,
    });
  }

  if (second.tool !== "get_soc_entity_context") {
    throw new Error(`Expected get_soc_entity_context, got ${second.tool || "none"}`);
  }

  if (second.result?.entity?.type !== "alert") {
    throw new Error("Focused follow-up did not return alert investigation context");
  }

  const result = second.result;
  const output = {
    success: true,
    selection: {
      requestedScope: "today",
      usedScope: selectionScope,
      fellBack: selectionScope !== "today",
    },
    firstTurn: {
      question: selectedQuestion,
      answer: selected.answer,
      focus: selected.state.focus,
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

async function runFocusedFollowUp(service, {
  selected,
  selectedQuestion,
  secondQuestion,
}) {
  return service.query(secondQuestion, {
    state: selected.state,
    history: [
      { role: "user", content: selectedQuestion },
      { role: "assistant", content: selected.answer },
    ],
  });
}

function hasAlertFocus(response) {
  return Boolean(
    response?.state?.focus
    && response.state.focus.entityType === "alert"
    && response.state.focus.id,
  );
}

function buildDiagnostic(response) {
  return {
    tool: response?.tool || null,
    queryPlan: response?.queryPlan || null,
    result: response?.result || null,
    state: response?.state || null,
    answer: response?.answer || null,
  };
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
