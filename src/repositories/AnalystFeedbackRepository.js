const Alert = require('../models/Alert');
const InvestigationEvent = require('../models/InvestigationEvent');

// Aggregations that reduce the event log to one row per alert inside MongoDB. Each method returns a
// cursor so rows are streamed into the pure accumulator in src/investigation/feedbackMetrics.js.
// The selection rules mirror selectLatestHumanReview / selectEffectiveHumanDisposition.
class AnalystFeedbackRepository {
  constructor({ alertModel = Alert, eventModel = InvestigationEvent } = {}) {
    this.alertModel = alertModel;
    this.eventModel = eventModel;
  }

  reviewRows({ from, to }) {
    return this.eventModel
      .aggregate([
        { $match: { type: 'ai_review', 'actor.kind': 'human', createdAt: { $lt: to } } },
        { $sort: { alertRef: 1, sequence: -1 } },
        { $group: { _id: '$alertRef', latest: { $first: '$$ROOT' } } },
        { $match: { 'latest.createdAt': { $gte: from } } },
        {
          $project: {
            _id: 0,
            alertRef: '$_id',
            actorKind: '$latest.actor.kind',
            createdAt: '$latest.createdAt',
            sections: '$latest.payload.sections',
            snapshot: '$latest.context.analysisSnapshot',
          },
        },
      ])
      .allowDiskUse(true)
      .cursor();
  }

  dispositionRows({ from, to }) {
    return this.eventModel
      .aggregate([
        // Every actor's dispositions and reopens are replayed; only a human effective disposition counts.
        { $match: { type: { $in: ['disposition', 'reopened'] }, createdAt: { $lt: to } } },
        { $sort: { alertRef: 1, sequence: -1 } },
        { $group: { _id: '$alertRef', latest: { $first: '$$ROOT' } } },
        {
          $match: {
            'latest.type': 'disposition',
            'latest.actor.kind': 'human',
            'latest.createdAt': { $gte: from },
          },
        },
        {
          $project: {
            _id: 0,
            alertRef: '$_id',
            actorKind: '$latest.actor.kind',
            createdAt: '$latest.createdAt',
            outcome: '$latest.payload.outcome',
            rule: '$latest.context.rule',
            snapshot: '$latest.context.analysisSnapshot',
            analysisRef: '$latest.context.analysisRef',
          },
        },
      ])
      .allowDiskUse(true)
      .cursor();
  }

  coverageRows({ from, to }) {
    return this.alertModel
      .aggregate([
        { $match: { analysis: { $elemMatch: { analyzedAt: { $gte: from, $lt: to } } } } },
        {
          $project: {
            // $map keeps positions aligned with analysis indexes even when an entry lacks analyzedAt.
            analyzedAts: {
              $map: { input: { $ifNull: ['$analysis', []] }, as: 'entry', in: '$$entry.analyzedAt' },
            },
          },
        },
        {
          $lookup: {
            from: this.eventModel.collection.collectionName,
            let: { alertRef: '$_id' },
            pipeline: [
              {
                $match: {
                  $expr: { $eq: ['$alertRef', '$$alertRef'] },
                  type: 'ai_review',
                  'actor.kind': 'human',
                  createdAt: { $lt: to },
                },
              },
              { $project: { _id: 0, analysisRef: '$context.analysisRef', createdAt: 1 } },
            ],
            as: 'reviews',
          },
        },
        { $project: { _id: 0, alertRef: '$_id', analyzedAts: 1, reviews: 1 } },
      ])
      .allowDiskUse(true)
      .cursor();
  }
}

module.exports = { AnalystFeedbackRepository };
