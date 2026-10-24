// Synthetic Linux-only model tests; no socket server, HTTP, runner or credentials.
import {test, before, after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {OfflineArtifactTransaction as Tx, createFakeTransport, createFakeClock, assertCanonicalOriginal, LIMITS} from '../scripts/offline/TokenForgeArtifactTransaction.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const encoder=path.join(here,'fixtures/publication/MutateSealerZip.py');
const identity={repository:'synthetic/tokenforge',repositoryId:'1',workflowId:'2',runId:'3',attempt:'1',source:'a'.repeat(40)};
const digest=b=>createHash('sha256').update(b).digest('hex');
let root,original;
before(()=>{
  root=fs.mkdtempSync(path.join(os.tmpdir(),'tf-core-tests-'));fs.chmodSync(root,0o755);
  const files=path.join(root,'files');fs.mkdirSync(files,{mode:0o700});
  for(const name of ['coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json']) fs.writeFileSync(path.join(files,name),name.endsWith('.json')?'{}':'Synthetic public review\n');
  const zip=path.join(root,'independent.zip');execFileSync('/usr/bin/python3',['-I',encoder,files,zip,'canonical-from-directory']);original=fs.readFileSync(zip);
});
after(()=>fs.rmSync(root,{recursive:true,force:true}));
function fixture(t,options={}) {
  const clock=createFakeClock(), transport=createFakeTransport(options,clock);
  const tx=Tx.prepare({parent:root,original,context:identity,transport,clock});t.after(()=>tx.close());return {tx,transport,clock};
}
function upload(tx) {for(let i=0;i<4;i++) tx.advance();return tx.snapshot();}
function reopen(t,f,changes={}) {const directory=f.tx.directory;f.tx.close();const tx=Tx.open({directory,context:identity,transport:f.transport,clock:f.clock,...changes});t.after(()=>tx.close());return tx;}
function patchJournal(tx,edit) {const file=path.join(tx.directory,'journal.json');const j=JSON.parse(fs.readFileSync(file));edit(j);fs.writeFileSync(file,JSON.stringify(j));}

test('original bytes survive caller mutation, four mutations and independent seven-read observation',t=>{
  const input=Buffer.from(original),f=fixture(t); // additional preparation tests input isolation
  const tx=Tx.prepare({parent:root,original:input,context:identity,transport:f.transport,clock:f.clock});t.after(()=>tx.close());input.fill(0);
  assert.equal(upload(tx).state,'Finalized');const result=tx.observe();assert.equal(result.state,'Observed');
  assert.deepEqual(f.transport.archivedBytes(),original);assert.deepEqual(fs.readFileSync(path.join(tx.directory,'original.zip')),original);
  const log=f.transport.transcript();assert.equal(log.length,11);assert.equal(log.find(x=>x.op==='Block').requestSha256,digest(original));
  assert.deepEqual(log.map(x=>[x.op,x.credentialRole]),[['Create','Runtime'],['Block','Blob'],['Commit','Blob'],['Finalize','Runtime'],['Repository','Read'],['Run','Read'],['Artifact','Read'],['Redirect','Read'],['Download','Download'],['Artifact','Read'],['Run','Read']]);
  assert.equal(result.artifactId,'18446744073709551614');assert.equal(result.kind,'OfflineFakeTransactionObservation');
  for(const key of ['networkEnabled','serviceInteroperabilityProven','operationalPolicyEmissionAllowed','contentPrivacyApproval']) assert.equal(result[key],false);
  tx.observe();tx.advance();assert.equal(log.length,f.transport.transcript().length);
});
test('0755 temporary root produces dedicated 0700 child before private files',t=>{
  const {tx}=fixture(t);assert.equal(fs.statSync(root).mode&0o777,0o755);assert.equal(fs.statSync(tx.directory).mode&0o777,0o700);
  assert.equal(fs.statSync(path.join(tx.directory,'original.zip')).mode&0o777,0o400);assert.equal(fs.statSync(path.join(tx.directory,'journal.json')).mode&0o777,0o600);
});
for(const mutation of ['archive-comment','entry-comment','local-and-central-extra','deflate','zip64-extra','reordered','duplicate-record','local-crc','central-crc','local-size','central-size','local-name','central-name','offset','timestamp','attributes','encryption','descriptor','unsupported-method','appended-bytes','prepended-adjusted','gap-before-central-directory','gap-before-end-record']) {
  test(`refuses original ${mutation} without normalization or transport`,()=>{
    const out=path.join(root,`${mutation}.zip`);execFileSync('/usr/bin/python3',['-I',encoder,path.join(root,'independent.zip'),out,mutation]);
    const transport=createFakeTransport();assert.throws(()=>Tx.prepare({parent:root,original:fs.readFileSync(out),context:identity,transport}),/ArchiveRefused/);assert.equal(transport.transcript().length,0);
  });
}
for(const transform of ['header','trailer','wrapper']) test(`service digest echo with ${transform} transformation cannot pass`,t=>{
  const f=fixture(t,{transform});upload(f.tx);assert.equal(f.tx.observe().state,'ObservationUnknown');assert.notDeepEqual(f.transport.archivedBytes(),original);
  assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
});
for(const op of ['Create','Block','Commit','Finalize']) for(const fault of ['before','after','interruptBefore','interruptAfter','cancelBefore','cancelAfter']) {
  test(`${op} ${fault}: durable unknown, no mutation replay`,t=>{
    const f=fixture(t,{faults:{[op]:fault}});const target=['Create','Block','Commit','Finalize'].indexOf(op);
    for(let i=0;i<=target;i++) f.tx.advance();
    const saved=f.tx.snapshot();assert.equal(saved.ledger.length,target+1);
    if(fault.startsWith('interrupt')) assert.equal(saved.state,`${op}Intent`);
    const resumed=reopen(t,f);const unknown=op==='Create'?'CreateUnknown':op==='Finalize'?'FinalizeUnknown':'UploadUnknown';assert.equal(resumed.snapshot().state,unknown);
    resumed.advance();const r=resumed.observe();
    if(op==='Finalize'&&(fault==='after'||fault==='interruptAfter'||fault==='cancelAfter')) {assert.equal(r.state,'Observed');assert.equal(r.attempts,12);assert.equal(r.priorUnknown,'FinalizeUnknown');}
    else assert.equal(r.state,unknown);
    assert.equal(f.transport.transcript().filter(x=>x.op===op).length,1);
    assert.deepEqual(fs.readFileSync(path.join(resumed.directory,'original.zip')),original);
    const count=f.transport.transcript().length;resumed.observe();resumed.advance();assert.equal(f.transport.transcript().length,count);
  });
}
for(const count of [0,1,2,3,4]) test(`restart after ${count} definitive mutations preserves evidence and never restarts upload`,t=>{
  const f=fixture(t);for(let i=0;i<count;i++) f.tx.advance();const before=f.tx.snapshot();const tx=reopen(t,f);
  assert.equal(tx.snapshot().deadline,before.deadline);assert.deepEqual(tx.snapshot().ledger,before.ledger);
  if(count===0){assert.equal(tx.advance().state,'Created');}
  else if(count===4){assert.equal(tx.observe().state,'Observed');}
  else {assert.equal(tx.advance().state,'UploadUnknown');assert.equal(f.transport.transcript().length,count);}
});
for(const listMode of ['zero','multiple','paginated']) test(`ambiguous finalize ${listMode} reconciliation remains unknown and only once`,t=>{
  const f=fixture(t,{faults:{Finalize:'after'},listMode});upload(f.tx);
  assert.equal(f.tx.observe().state,'FinalizeUnknown');f.tx.observe();assert.equal(f.transport.transcript().filter(x=>x.op==='List').length,1);
});
for(const metadataChange of [{digest:'sha256:'+'0'.repeat(64)},{size:0},{expired:true},{id:30},{id:'42'},{context:{...identity,attempt:'2'}}]) test(`metadata change ${JSON.stringify(metadataChange)} refuses observation`,t=>{
  const f=fixture(t,{metadataChange});upload(f.tx);assert.equal(f.tx.observe().state,'ObservationUnknown');
});
for(const op of ['Repository','Run','Artifact','Redirect','Download']) test(`interrupted observer ${op} preserves charged reads and forbids a second observation`,t=>{
  const f=fixture(t,{faults:{[op]:'interruptAfter'}});upload(f.tx);f.tx.observe();const count=f.transport.transcript().length;const tx=reopen(t,f);
  assert.equal(tx.snapshot().state,'ObservationUnknown');tx.observe();assert.equal(f.transport.transcript().length,count);
});
test('fixed deadline survives restart; expiry performs no dispatch',t=>{
  const f=fixture(t);f.clock.advance(179999);const tx=reopen(t,f);assert.equal(tx.snapshot().deadline,1180000);f.clock.advance(1);
  assert.equal(tx.advance().state,'Refused');assert.equal(f.transport.transcript().length,0);
});
test('deadline applies across upload and observer',t=>{
  const f=fixture(t);for(let i=0;i<4;i++){f.clock.advance(40000);f.tx.advance();}f.clock.advance(20000);
  assert.equal(f.tx.observe().state,'ObservationUnknown');assert.equal(f.transport.transcript().length,4);
});
test('clock rollback refuses resume rather than replenishing time',t=>{
  const f=fixture(t);f.clock.advance(100);f.tx.advance();f.clock.advance(-1);f.tx.close();assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);
});
test('one request exceeding ten seconds is charged once and unknown',t=>{
  const f=fixture(t,{delayMs:10000});assert.equal(f.tx.advance().state,'CreateUnknown');assert.equal(f.tx.snapshot().ledger.length,1);
  assert.equal(f.tx.snapshot().ledger[0].charge>LIMITS.controlResponse,true);f.tx.advance();assert.equal(f.transport.transcript().length,1);
});
for(const op of ['Create','Block','Commit','Finalize','Repository','Download']) test(`wrong credential role on ${op} is denied and never leaks synthetic error`,t=>{
  const f=fixture(t,{credentialFault:op});let r;for(let i=0;i<4;i++) r=f.tx.advance();if(!['Create','Block','Commit','Finalize'].includes(op)) r=f.tx.observe();
  assert.notEqual(r.state,'Observed');assert.doesNotMatch(JSON.stringify(r)+fs.readFileSync(path.join(f.tx.directory,'journal.json'),'utf8'),/SYNTHETIC_SECRET_ERROR|FixtureBlobCapability|FixtureDownloadCapability/);
});
for(const op of ['Create','Artifact','Download']) test(`bounded ${op} response never becomes a successful observation`,t=>{
  const f=fixture(t,{responseOversize:op});upload(f.tx);assert.notEqual(f.tx.observe().state,'Observed');
});
test('body reservations and mutation/read attempts remain within fixed limits including recovery',t=>{
  const f=fixture(t,{faults:{Finalize:'after'}});upload(f.tx);const r=f.tx.observe(),j=f.tx.snapshot();
  assert.equal(r.state,'Observed');assert.equal(j.ledger.length,LIMITS.attempts);
  assert.equal(j.ledger.filter(x=>['Create','Block','Commit','Finalize'].includes(x.op)).length,LIMITS.mutations);
  assert.equal(j.ledger.filter(x=>!['Create','Block','Commit','Finalize'].includes(x.op)).length,LIMITS.reads);
  assert.ok(j.ledger.reduce((n,x)=>n+x.charge,0)<=LIMITS.totalBytes);
  assert.ok(j.ledger.find(x=>x.op==='Download').charge===LIMITS.archive);
  assert.throws(()=>{LIMITS.attempts=100;},TypeError);
});
test('changed frozen file refuses before next dispatch without substitution',t=>{
  const f=fixture(t);f.tx.advance();const file=path.join(f.tx.directory,'original.zip');fs.chmodSync(file,0o600);const changed=Buffer.from(original);changed[10]^=1;fs.writeFileSync(file,changed);
  assert.equal(f.tx.advance().state,'Refused');assert.equal(f.transport.transcript().length,1);assert.deepEqual(fs.readFileSync(file),changed);
});
for(const change of ['missing','symlink','hardlink','broad-mode']) test(`resume refuses ${change} original evidence`,t=>{
  const f=fixture(t);f.tx.close();const file=path.join(f.tx.directory,'original.zip');
  if(change==='missing') fs.unlinkSync(file);
  if(change==='symlink'){fs.unlinkSync(file);fs.symlinkSync(path.join(root,'independent.zip'),file);}
  if(change==='hardlink') fs.linkSync(file,path.join(f.tx.directory,'copy'));
  if(change==='broad-mode') fs.chmodSync(file,0o644);
  assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);assert.equal(f.transport.transcript().length,0);
});
for(const edit of [j=>j.version=2,j=>j.extra=true,j=>j.deadline++,j=>j.context.attempt='2',j=>j.ledger=Array(13).fill({op:'Run',charge:131072,at:j.created}),j=>j.ledger=[{op:'Run',charge:2097153,at:j.created}],j=>j.ledger=[{op:'Finalize',charge:131072,at:j.created}],j=>j.state='Finalized']) test(`corrupt journal refuses: ${edit}`,t=>{
  const f=fixture(t);patchJournal(f.tx,edit);f.tx.close();assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);assert.equal(f.transport.transcript().length,0);
});
test('exclusive open prevents concurrent writers',t=>{
  const f=fixture(t);assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}));assert.equal(f.tx.advance().state,'Created');
});
test('no arbitrary transport, credentials, limits, HTTPS route or observer callback accepted',t=>{
  const f=fixture(t);for(const extra of [{runtimeToken:'DO_NOT_USE'},{https:true},{operational:true},{limits:{attempts:100}},{observer:()=>true}]) assert.throws(()=>Tx.prepare({parent:root,original,context:identity,transport:f.transport,...extra}),/SchemaRefused/);
  for(const transport of [{kind:'NetworkDisabledFakeTransport'},()=>{},'https://example.invalid']) assert.throws(()=>Tx.prepare({parent:root,original,context:identity,transport}),/FakeTransportRequired/);
  assert.throws(()=>createFakeTransport({fetch:()=>{}}));assert.throws(()=>new Tx(),/UseOfflineFactory/);
});
test('canonical checker rejects nonbytes, oversize and damaged payload even with correct metadata length',()=>{
  for(const value of ['zip',Buffer.alloc(65537),Buffer.alloc(22)]) assert.throws(()=>assertCanonicalOriginal(value),/ArchiveRefused/);
});

test('latest response timing is persisted; delayed response followed by rollback refuses reopen',t=>{
  const f=fixture(t,{delayMs:9000});assert.equal(f.tx.advance().state,'Created');assert.equal(f.tx.snapshot().lastWall,1009000);
  f.tx.close();f.clock.advance(-8000);assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);
});
test('different clock instance cannot manufacture restart time proof',t=>{
  const f=fixture(t);f.tx.close();assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:createFakeClock()}),/OfflineResumeRefused/);
});
test('reused fake service retains first artifact identity; second transaction cannot borrow it',t=>{
  const f=fixture(t);upload(f.tx);const second=Tx.prepare({parent:root,original,context:{...identity,runId:'9'},transport:f.transport,clock:f.clock});t.after(()=>second.close());
  assert.equal(second.advance().state,'CreateUnknown');assert.equal(second.observe().state,'ObservationUnknown');
  assert.deepEqual(f.transport.archivedBytes(),original);assert.equal(second.snapshot().priorUnknown,'CreateUnknown');
});
test('same-context second transaction cannot borrow a previous artifact name',t=>{
  const f=fixture(t);upload(f.tx);const second=Tx.prepare({parent:root,original,context:identity,transport:f.transport,clock:f.clock});t.after(()=>second.close());
  second.advance();assert.equal(second.observe().state,'ObservationUnknown');assert.notEqual(second.snapshot().name,f.tx.snapshot().name);
});
for(const value of [['a'.repeat(40)],{toString:'a'.repeat(40)},0,null]) test(`non-string source rejected: ${JSON.stringify(value)}`,()=>{
  const transport=createFakeTransport();assert.throws(()=>Tx.prepare({parent:root,original,context:{...identity,source:value},transport}),/IdentityRefused/);assert.equal(transport.transcript().length,0);
});
for(const field of ['name','hash']) test(`non-string journal ${field} rejected`,t=>{
  const f=fixture(t);patchJournal(f.tx,j=>j[field]=[j[field]]);f.tx.close();assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);
});
for(const kind of ['duplicate','escaped-duplicate','charge-refund','state-shortcut','read-order']) test(`journal rejects ${kind}`,t=>{
  const f=fixture(t);upload(f.tx);f.tx.observe();f.tx.close();const file=path.join(f.tx.directory,'journal.json');let raw=fs.readFileSync(file,'utf8');
  if(kind==='duplicate') raw=raw.replace('"version":1','"version":2,"version":1');
  if(kind==='escaped-duplicate') raw=raw.replace('"version":1','"vers\\u0069on":2,"version":1');
  if(kind==='charge-refund') {const j=JSON.parse(raw);j.ledger[0].charge=1;raw=JSON.stringify(j);}
  if(kind==='state-shortcut') {const j=JSON.parse(raw);j.ledger=j.ledger.slice(0,4);raw=JSON.stringify(j);}
  if(kind==='read-order') {const j=JSON.parse(raw);[j.ledger[4],j.ledger[5]]=[j.ledger[5],j.ledger[4]];raw=JSON.stringify(j);}
  fs.writeFileSync(file,raw);assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);
});
test('actual process exit without close preserves intent and stale lock; reopening refuses instead of replaying',()=>{
  const dir=fs.mkdtempSync(path.join(root,'killed-'));const setup=path.join(dir,'setup.mjs');
  const moduleUrl=new URL('../scripts/offline/TokenForgeArtifactTransaction.mjs',import.meta.url).href;
  fs.writeFileSync(setup,`import fs from 'node:fs';import {OfflineArtifactTransaction as Tx,createFakeTransport} from ${JSON.stringify(moduleUrl)};const tx=Tx.prepare({parent:${JSON.stringify(dir)},original:fs.readFileSync(${JSON.stringify(path.join(root,'independent.zip'))}),context:${JSON.stringify(identity)},transport:createFakeTransport({faults:{Create:'interruptAfter'}})});tx.advance();fs.writeFileSync(${JSON.stringify(path.join(dir,'directory'))},tx.directory);process.exit(0);`);
  execFileSync(process.execPath,[setup]);const directory=fs.readFileSync(path.join(dir,'directory'),'utf8');const before=fs.readFileSync(path.join(directory,'journal.json'));
  assert.equal(JSON.parse(before).state,'CreateIntent');const transport=createFakeTransport();assert.throws(()=>Tx.open({directory,context:identity,transport}));
  assert.equal(transport.transcript().length,0);assert.deepEqual(fs.readFileSync(path.join(directory,'journal.json')),before);assert.deepEqual(fs.readFileSync(path.join(directory,'original.zip')),original);
});

test('expiration while persisting charge prevents dispatch and preserves consumed budget',t=>{
  const f=fixture(t),originalSync=fs.fsyncSync;let calls=0;
  fs.fsyncSync=function(fd){const r=originalSync(fd);if(++calls===4) f.clock.advance(LIMITS.deadlineMs);return r;};
  let result;try {result=f.tx.advance();} finally {fs.fsyncSync=originalSync;}
  assert.equal(result.state,'CreateUnknown');assert.equal(f.transport.transcript().length,0);assert.equal(f.tx.snapshot().ledger.length,1);
  assert.ok(f.tx.snapshot().ledger[0].charge>LIMITS.controlResponse);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
});
test('normal observed transaction can reopen read-only without sending requests or resetting counters',t=>{
  const f=fixture(t);upload(f.tx);f.tx.observe();const before=f.tx.snapshot();const tx=reopen(t,f);assert.equal(tx.observe().state,'Observed');assert.deepEqual(tx.snapshot().ledger,before.ledger);assert.equal(f.transport.transcript().length,11);
});

for(const repository of ['a'.repeat(40)+'/repo','owner/'+'b'.repeat(101)]) test('oversize repository identity refuses before any store creation',()=>{
  const before=fs.readdirSync(root),transport=createFakeTransport();assert.throws(()=>Tx.prepare({parent:root,original,context:{...identity,repository},transport}),/IdentityRefused/);assert.deepEqual(fs.readdirSync(root),before);assert.equal(transport.transcript().length,0);
});
for(const state of ['Finalized','ObserveIntent','Observed']) test(`${state} cannot bypass an upload-unknown barrier in a saved journal`,t=>{
  const f=fixture(t);upload(f.tx);if(state!=='Finalized') f.tx.observe();patchJournal(f.tx,j=>{j.state=state;j.priorUnknown='UploadUnknown';});f.tx.close();
  assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);
});
for(const content of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}','{} trailing',Buffer.from([0xff])]) test(`invalid canonical JSON payload refuses without replacement: ${content}`,()=>{
  const dir=fs.mkdtempSync(path.join(root,'json-'));fs.cpSync(path.join(root,'files'),dir,{recursive:true});fs.writeFileSync(path.join(dir,'manifest.json'),content);
  const target=path.join(dir,'encoded.zip');execFileSync('/usr/bin/python3',['-I',encoder,dir,target,'canonical-from-directory']);assert.throws(()=>assertCanonicalOriginal(fs.readFileSync(target)),/ArchiveRefused/);
});
test('core source has only fixed filesystem/path/crypto imports and no real transport or environment hook',()=>{
  const source=fs.readFileSync(new URL('../scripts/offline/TokenForgeArtifactTransaction.mjs',import.meta.url),'utf8');
  assert.deepEqual([...source.matchAll(/from '(.*?)'/g)].map(m=>m[1]),['node:fs','node:path','node:crypto']);
  assert.doesNotMatch(source,/\b(?:fetch|eval)\s*\(|\bimport\s*\(|process\s*\.\s*env|https:\/\/|node:(?:http|https|net|tls|child_process)|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN/);
});
