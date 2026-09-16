const v6 = require("./reportDocxParserV6");

module.exports = {
  PARSER_VERSION: v6.PARSER_VERSION,
  parseDocxReport: v6.parseDocxReport,
  enhanceReportRecordV5: v6.enhanceReportRecordV6,
  classifyFindingV5: v6.classifyFindingV6,
  vulnerabilityFromFindingV5: v6.vulnerabilityFromFindingV6,
};
