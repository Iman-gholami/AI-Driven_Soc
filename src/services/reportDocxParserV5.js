const v6 = require("./reportDocxParserV6");
const v10 = require("./reportDocxParserV10");

// Compatibility shim: existing callers still import V5, while the active
// parse path advances to the latest parser. Legacy classifier exports remain
// mapped to V6 so older regression tests keep their original contract.
module.exports = {
  PARSER_VERSION: v10.PARSER_VERSION,
  parseDocxReport: v10.parseDocxReport,
  enhanceReportRecordV5: v6.enhanceReportRecordV6,
  classifyFindingV5: v6.classifyFindingV6,
  vulnerabilityFromFindingV5: v6.vulnerabilityFromFindingV6,
};
