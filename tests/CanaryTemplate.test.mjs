import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
test('unregistered template binds complete inert bootstrap and local action with only Actions read',()=>{
 const source=fs.readFileSync(new URL('../publication/canary/workflow.yml',import.meta.url),'utf8');
 assert.match(source,/^on:\n  workflow_dispatch:\n/m);assert.doesNotMatch(source,/^  (?:push|pull_request|schedule|workflow_run|workflow_call):/m);
 assert.match(source,/^    if: \$\{\{ false \}\}$/m);assert.match(source,/^    runs-on: ubuntu-24\.04$/m);assert.match(source,/^    timeout-minutes: 5$/m);assert.match(source,/^permissions: \{\}$/m);
 assert.doesNotMatch(source,/actions\/checkout|contents:|id-token:|secrets:|continue-on-error:/);assert.match(source,/^      actions: read$/m);
 assert.equal((source.match(/^  canary:$/gm)||[]).length,1);assert.equal((source.match(/^        uses:/gm)||[]).length,1);assert.match(source,/uses: \.\/candidate\/\.github\/actions\/tokenforge-canary/);
 assert.match(source,/python3 -I -S -B - 441bf8020b11c9770115e896d73134c298dd9c1d/);
 const embedded=source.split("<<'TOKENFORGE_BOOTSTRAP'\n")[1].split('          TOKENFORGE_BOOTSTRAP\n')[0].split('\n').slice(0,-1).map(line=>{if(line==='')return '';assert.ok(line.startsWith('          '));return line.slice(10);}).join('\n')+'\n';assert.equal(embedded,fs.readFileSync(new URL('../scripts/TokenForgeCanaryBootstrap.py',import.meta.url),'utf8'));
 for(const name of ['BASH_ENV','ENV','NODE_OPTIONS','NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','NODE_DEBUG','NODE_DEBUG_NATIVE','NODE_USE_ENV_PROXY','NODE_USE_SYSTEM_CA','OPENSSL_CONF','OPENSSL_MODULES','LD_PRELOAD','LD_LIBRARY_PATH','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'])assert.match(source,new RegExp('^      '+name+": ''$",'m'));
 for(const name of ['action.yml','index.mjs']) {const bytes=fs.readFileSync(new URL('../.github/actions/tokenforge-canary/'+name,import.meta.url));assert.equal(createHash('sha256').update(bytes).digest('hex'),name==='action.yml'?'385dedf45df0e302ed1433f459059402c91916933b36980f5c0062672214e65c':'61f3046ff17f8d6c01a0819baec3ab8ff4bde0eedc765b8743428323dd0eba51');}
});
