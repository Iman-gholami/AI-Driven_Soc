const express = require('express');
const multer = require('multer');
const os = require('node:os');
const path = require('node:path');
const { IncidentAnalyzer } = require('../services/analyzer');
const { AlertRepository } = require('../repositories/AlertRepository');
const { UnifiedCopilotService } = require('../services/unifiedCopilotService');
const { InvestigationService } = require('../services/investigationService');
const { AnalystFeedbackService } = require('../services/analystFeedbackService');
const { createAnalyticsController } = require('./controllers/analytics.controller');
const { AlertController, getRequestedSocFields } = require('./controllers/alerts.controller');
const { CopilotController } = require('./controllers/copilot.controller');
const { createInvestigationController } = require('./controllers/investigation.controller');
const { RuleController } = require('./controllers/rules.controller');
const { MitreController } = require('./controllers/mitre.controller');
const { normalizeAlertPayload } = require('../services/alertIngest');
const { asyncHandler } = require('./middleware/asyncHandler');

// Rule files are read once and deleted by the controller, so they never need a persistent folder.
const ruleUpload = multer({ dest: path.join(os.tmpdir(), 'ai-driven-soc-rule-uploads') });

function createRouter({
  analyzer = new IncidentAnalyzer(),
  alertRepository = new AlertRepository(),
  copilot = new UnifiedCopilotService(),
  ruleController = new RuleController(),
  mitreController = new MitreController(),
  investigationService = new InvestigationService(),
  analystFeedbackService = new AnalystFeedbackService(),
} = {}) {
  const router = express.Router();
  const alerts = new AlertController({ alertRepository, analyzer });
  const copilotController = new CopilotController({ copilot });
  const investigation = createInvestigationController({ investigationService });
  const analytics = createAnalyticsController({ analystFeedbackService });

  router.get('/copilot/schema', asyncHandler(copilotController.describeSchema));
  router.get('/copilot/tools', asyncHandler(copilotController.listTools));
  router.post('/copilot/query', asyncHandler(copilotController.query));

  router.post('/analyze-incident', asyncHandler(alerts.analyzeIncident));
  router.post('/webhook-alert', asyncHandler(alerts.ingestWebhook));

  router.get('/alerts', asyncHandler(alerts.list));
  router.get('/alerts/:id', asyncHandler(alerts.get));
  router.post('/alerts/:id/analyze', asyncHandler(alerts.analyze));
  router.get('/dashboard/stats', asyncHandler(alerts.dashboardStats));
  router.get('/intelligence/ip/:ip', asyncHandler(alerts.ipIntelligence));

  // Analyst investigation: human actions only. These endpoints never call the LLM.
  router.get('/investigation/reasons', asyncHandler(investigation.listReasons));
  router.get('/alerts/:id/investigation', asyncHandler(investigation.getInvestigation));
  router.post('/alerts/:id/investigation/review', asyncHandler(investigation.recordReview));
  router.post('/alerts/:id/investigation/disposition', asyncHandler(investigation.recordDisposition));
  router.post('/alerts/:id/investigation/notes', asyncHandler(investigation.recordNote));
  router.post('/alerts/:id/investigation/reopen', asyncHandler(investigation.reopen));

  // Analyst Feedback metrics over human investigation events (kept at the ai-accuracy URL).
  router.get('/analytics/ai-accuracy', asyncHandler(analytics.aiAccuracy));

  // Rule-level MITRE ATT&CK coverage.
  router.get('/mitre/coverage', mitreController.getCoverage);
  router.post('/mitre/coverage/rebuild', mitreController.rebuildCoverage);
  router.get('/mitre/techniques/:techniqueId', mitreController.getTechnique);
  router.get('/mitre/techniques/:techniqueId/rules', mitreController.getTechniqueRules);

  // Detection rules use the same DetectionRule model/repository/parser as the AI resolver.
  router.post('/rules/import', ruleUpload.single('rulesFile'), ruleController.importRules);
  router.get('/rules', ruleController.getRules);
  router.get('/rules/:ruleId', ruleController.getRuleById);
  router.delete('/rules/:ruleId', ruleController.deleteRule);

  // Backward-compatible import alias.
  router.post('/import', ruleUpload.single('rulesFile'), ruleController.importRules);

  return router;
}

module.exports = {
  createRouter,
  normalizeAlertPayload,
  getRequestedSocFields,
};
