'use strict';
// Ship: run the full test suite, then commit and push main. The host
// (Render/Railway/Fly) auto-deploys from the push. Usage:
//   npm run ship -- "commit message"
const { execSync } = require('child_process');
const root = require('path').join(__dirname, '..');
const run = (c) => execSync(c, { cwd: root, stdio: 'inherit' });
const cap = (c) => execSync(c, { cwd: root }).toString().trim();

const msg = process.argv.slice(2).join(' ') || 'ship: update';

try {
  console.log('\n== running tests ==');
  run('npm test');

  console.log('\n== git status ==');
  const dirty = cap('git status --porcelain');
  if (!dirty) { console.log('nothing to commit; pushing existing commits.'); }
  else { run('git add -A'); run(`git commit -m ${JSON.stringify(msg)}`); }

  console.log('\n== pushing main (host auto-deploys) ==');
  run('git push origin main');
  console.log('\n✓ shipped. Your host will build & deploy from this push.');
} catch (e) {
  console.error('\n✗ ship aborted:', e.message);
  process.exit(1);
}
