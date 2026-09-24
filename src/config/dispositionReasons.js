// Stable vocabulary for analyst dispositions. IDs are persisted in investigation events and must never be
// renamed or reused; labels and allowed outcomes may evolve. Retired reasons stay in this list with
// `retired: true` so historical events keep resolving to a label.

const DISPOSITION_OUTCOMES = Object.freeze([
  {
    id: 'true_positive',
    label: 'True positive',
    description: 'The detected security concern was confirmed.',
  },
  {
    id: 'benign_true_positive',
    label: 'Benign true positive',
    description:
      'The rule correctly detected the behavior, but investigation established that it was authorized or benign.',
  },
  {
    id: 'false_positive',
    label: 'False positive',
    description: 'Investigation established that the detection incorrectly indicated the claimed condition.',
  },
  {
    id: 'inconclusive',
    label: 'Inconclusive',
    description: 'The evidence is insufficient to determine the outcome.',
  },
]);

const DISPOSITION_ACTIONS = Object.freeze([
  {
    id: 'ticket_created',
    label: 'Ticket created',
    description: 'Handed off through an external ticket. Closes local triage.',
    closesTriage: true,
  },
  {
    id: 'escalated',
    label: 'Escalated',
    description: 'Escalated to another team or tier. Closes local triage.',
    closesTriage: true,
  },
  {
    id: 'closed_no_action',
    label: 'Closed, no action',
    description: 'No further action required. Closes local triage.',
    closesTriage: true,
  },
  {
    id: 'monitoring',
    label: 'Monitoring',
    description: 'Keep watching; local triage stays open.',
    closesTriage: false,
  },
]);

const ALL_OUTCOMES = DISPOSITION_OUTCOMES.map((outcome) => outcome.id);

const DISPOSITION_REASONS = Object.freeze([
  {
    id: 'confirmed_malicious_activity',
    labelEn: 'Confirmed malicious activity',
    labelFa: 'فعالیت مخرب تأییدشده',
    outcomes: ['true_positive'],
  },
  {
    id: 'authorized_internal_scanner',
    labelEn: 'Authorized internal scanner',
    labelFa: 'اسکنر داخلی مجاز',
    outcomes: ['benign_true_positive', 'false_positive'],
  },
  {
    id: 'authorized_test_or_simulation',
    labelEn: 'Authorized test or simulation',
    labelFa: 'آزمون یا شبیه‌سازی مجاز',
    outcomes: ['benign_true_positive'],
  },
  {
    id: 'known_benign_service',
    labelEn: 'Known benign service',
    labelFa: 'سرویس شناخته‌شده و بی‌خطر',
    outcomes: ['benign_true_positive', 'false_positive'],
  },
  {
    id: 'rule_too_broad',
    labelEn: 'Detection rule too broad',
    labelFa: 'قاعده تشخیص بیش از حد کلی است',
    outcomes: ['false_positive', 'benign_true_positive'],
  },
  {
    id: 'duplicate_existing_ticket',
    labelEn: 'Duplicate of an existing ticket',
    labelFa: 'تکراری؛ تیکت موجود',
    outcomes: ALL_OUTCOMES,
  },
  {
    id: 'remediated_previous_report',
    labelEn: 'Remediated per a previous report',
    labelFa: 'طبق گزارش قبلی رفع شده است',
    outcomes: ['true_positive', 'benign_true_positive', 'inconclusive'],
  },
  {
    id: 'insufficient_evidence',
    labelEn: 'Insufficient evidence',
    labelFa: 'شواهد ناکافی',
    outcomes: ['inconclusive'],
  },
  {
    id: 'other',
    labelEn: 'Other',
    labelFa: 'سایر',
    outcomes: ALL_OUTCOMES,
    requiresText: true,
  },
]);

const REASONS_BY_ID = new Map(DISPOSITION_REASONS.map((reason) => [reason.id, reason]));

function getDispositionReason(id) {
  return REASONS_BY_ID.get(id) || null;
}

// A retired reason stays readable for history but can no longer be selected.
function isReasonAllowedForOutcome(reasonId, outcome) {
  const reason = REASONS_BY_ID.get(reasonId);
  return Boolean(reason && !reason.retired && reason.outcomes.includes(outcome));
}

function listDispositionVocabulary() {
  return {
    outcomes: DISPOSITION_OUTCOMES.map((outcome) => ({ ...outcome })),
    actions: DISPOSITION_ACTIONS.map((action) => ({ ...action })),
    reasons: DISPOSITION_REASONS.map((reason) => ({
      id: reason.id,
      labelEn: reason.labelEn,
      labelFa: reason.labelFa,
      outcomes: [...reason.outcomes],
      requiresText: Boolean(reason.requiresText),
      retired: Boolean(reason.retired),
    })),
  };
}

module.exports = {
  DISPOSITION_OUTCOMES,
  DISPOSITION_ACTIONS,
  DISPOSITION_REASONS,
  OUTCOME_IDS: ALL_OUTCOMES,
  ACTION_IDS: DISPOSITION_ACTIONS.map((action) => action.id),
  CLOSING_ACTION_IDS: DISPOSITION_ACTIONS.filter((action) => action.closesTriage).map((action) => action.id),
  getDispositionReason,
  isReasonAllowedForOutcome,
  listDispositionVocabulary,
};
