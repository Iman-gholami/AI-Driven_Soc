// Runs Prettier on the files that follow the repository formatting standard.
// Existing files are not reformatted wholesale; add a path here when a file is brought under Prettier.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const FORMATTED_PATHS = [
  '.prettierrc.json',
  'scripts/format.js',
  'src/config/dispositionReasons.js',
  'src/investigation',
  'src/models/InvestigationEvent.js',
  'src/mcp/toolDefinitions.js',
  'src/repositories/InvestigationRepository.js',
  'src/services/investigationService.js',
  'integration',
  'test/support',
  'test/investigationSchemas.test.js',
  'test/investigationReducer.test.js',
  'test/investigationAnalysisReference.test.js',
  'test/investigationService.test.js',
];

const mode = process.argv[2] === '--write' ? '--write' : '--check';
const root = path.join(__dirname, '..');
const missing = FORMATTED_PATHS.filter((entry) => !fs.existsSync(path.join(root, entry)));
if (missing.length > 0) {
  console.error(`Formatted paths do not exist: ${missing.join(', ')}`);
  process.exit(1);
}

const prettier = require.resolve('prettier/bin/prettier.cjs');
const result = spawnSync(process.execPath, [prettier, mode, ...FORMATTED_PATHS], {
  cwd: root,
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
