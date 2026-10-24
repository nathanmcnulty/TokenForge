import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
test('template remains unregistered, manually triggered, literal-false, bounded and bound to reviewed dormant implementation',()=>{
 const source=fs.readFileSync(new URL('../publication/canary/workflow.yml',import.meta.url),'utf8');
 assert.match(source,/^on:\n  workflow_dispatch:\n/m);assert.doesNotMatch(source,/^  (?:push|pull_request|schedule|workflow_run|workflow_call):/m);
 assert.match(source,/^    if: \$\{\{ false \}\}$/m);assert.match(source,/^    runs-on: ubuntu-24\.04$/m);assert.match(source,/^    timeout-minutes: 5$/m);
 assert.match(source,/^permissions: \{\}$/m);assert.doesNotMatch(source,/id-token:|write|secrets:|env:|run:|continue-on-error:/);
 assert.equal((source.match(/^  canary:$/gm)||[]).length,1);assert.equal((source.match(/uses:/g)||[]).length,2);
 assert.match(source,/uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/);assert.match(source,/ref: 026ec9d0380eeacae9ecd7787c84996a0307814c/);assert.match(source,/persist-credentials: false/);assert.match(source,/uses: \.\/\.github\/actions\/tokenforge-canary/);
 for(const name of ['action.yml','index.mjs']) {const bytes=fs.readFileSync(new URL('../.github/actions/tokenforge-canary/'+name,import.meta.url));assert.equal(createHash('sha256').update(bytes).digest('hex'),name==='action.yml'?'385dedf45df0e302ed1433f459059402c91916933b36980f5c0062672214e65c':'2550a8961b79b1ffc0835ed863248d4f2f40daae037ef7f2090a3695581e6e84');}
});
