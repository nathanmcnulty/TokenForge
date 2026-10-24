// Pure wire-profile + integrated fake tests. No network-capable dispatcher.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {OfflineArtifactTransaction as Tx,createFakeClock,createFakeTransport,LIMITS} from '../scripts/offline/TokenForgeArtifactTransaction.mjs';
import {PROTOCOL,ROLES,requestBody,buildRequest,validateRequest,parseResponse,signedCapability,fixtureCapability} from '../scripts/offline/TokenForgeArtifactProtocol.mjs';
import {strictJson} from '../scripts/offline/TokenForgeOfflineSchema.mjs';
let root,original,t;
const identity={repository:'synthetic/tokenforge',repositoryId:'1',workflowId:'2',runId:'3',attempt:'1',source:'a'.repeat(40)};
before(()=>{
  root=fs.mkdtempSync(path.join(os.tmpdir(),'tf-protocol-'));const files=path.join(root,'files');fs.mkdirSync(files);
  for(const n of ['coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json']) fs.writeFileSync(path.join(files,n),n.endsWith('.json')?'{}':'Synthetic');
  const out=path.join(root,'original.zip');execFileSync('/usr/bin/python3',['-I',path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures/publication/MutateSealerZip.py'),files,out,'canonical-from-directory']);original=fs.readFileSync(out);
  t={context:identity,name:'tf-offline-'+'1'.repeat(32),hash:createHash('sha256').update(original).digest('hex'),size:original.length,artifactId:PROTOCOL.artifactId};
});
after(()=>fs.rmSync(root,{recursive:true,force:true}));
const caps=()=>({original,uploadUrl:fixtureCapability('Blob'),downloadUrl:fixtureCapability('Download')});
const envelope=(body,status=200,extra={})=>{const b=Buffer.isBuffer(body)?body:Buffer.from(typeof body==='string'?body:JSON.stringify(body));return {status,headers:{'content-type':'application/json','content-length':String(b.length),...extra},body:b};};
function setup(testCase,options={}) {const clock=createFakeClock(),transport=createFakeTransport(options,clock),tx=Tx.prepare({parent:root,original,context:identity,transport,clock});testCase.after(()=>tx.close());return {clock,transport,tx};}
const upload=tx=>{for(let i=0;i<4;i++)tx.advance();};

for(const pairing of ['fake/fake','fake/default','default/fake']) test(`M1 rejects ${pairing} timing domains before creating any store`,()=>{
  const a=createFakeClock(),b=createFakeClock();const transport=createFakeTransport(pairing==='default/fake'?{}:{delayMs:10000},pairing==='default/fake'?undefined:a);
  const clock=pairing==='fake/default'?undefined:b,before=fs.readdirSync(root);
  assert.throws(()=>Tx.prepare({parent:root,original,context:identity,transport,clock}),/ClockBindingRefused/);assert.deepEqual(fs.readdirSync(root),before);assert.equal(transport.transcript().length,0);
});
for(const pairing of ['fake/fake','fake/default','default/fake']) test(`M1 ${pairing} reopen refuses before lock creation or journal changes`,testCase=>{
  const clock=pairing==='default/fake'?undefined:createFakeClock(),transport=createFakeTransport({},clock);
  const tx=Tx.prepare({parent:root,original,context:identity,transport,clock});tx.close();const dir=tx.directory,journal=fs.readFileSync(path.join(dir,'journal.json')),entries=fs.readdirSync(dir);
  const wrong=pairing==='fake/default'?undefined:createFakeClock();
  assert.throws(()=>Tx.open({directory:dir,context:identity,transport,clock:wrong}),/ClockBindingRefused/);assert.deepEqual(fs.readdirSync(dir),entries);assert.deepEqual(fs.readFileSync(path.join(dir,'journal.json')),journal);assert.deepEqual(fs.readFileSync(path.join(dir,'original.zip')),original);
  const correct=Tx.open({directory:dir,context:identity,transport,clock});testCase.after(()=>correct.close());assert.equal(correct.snapshot().ledger.length,0);
});
test('M1 explicit default/default uses local timing; default service cannot simulate delay',testCase=>{
  assert.throws(()=>createFakeTransport({delayMs:10000}),/FakeConfigurationRefused/);
  const transport=createFakeTransport(),tx=Tx.prepare({parent:root,original,context:identity,transport});testCase.after(()=>tx.close());upload(tx);assert.equal(tx.observe().state,'Observed');
});
test('M1 identical shared domain charges ten-second boundary, refuses timely success, never replays',testCase=>{
  const f=setup(testCase,{delayMs:10000});assert.equal(f.tx.advance().state,'CreateUnknown');assert.equal(f.tx.snapshot().ledger.length,1);assert.equal(f.transport.transcript().length,1);f.tx.advance();assert.equal(f.transport.transcript().length,1);
});
test('M1 shared total deadline includes prior simulated delays and survives clean-close reopen',testCase=>{
  const f=setup(testCase,{delayMs:9000});upload(f.tx);assert.equal(f.tx.snapshot().lastWall,1036000);const dir=f.tx.directory;f.tx.close();f.clock.advance(144000);
  const before=fs.readFileSync(path.join(dir,'journal.json'));assert.throws(()=>Tx.open({directory:dir,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);assert.deepEqual(fs.readFileSync(path.join(dir,'journal.json')),before);assert.equal(f.transport.transcript().length,4);
});

test('Twirp request bytes follow pinned snake_case JSON, GUID routing and scalar hash',()=>{
  const c=buildRequest('Create',t,caps()),f=buildRequest('Finalize',t,caps());
  assert.equal(c.method,'POST');assert.equal(c.url,PROTOCOL.results+'/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact');
  assert.deepEqual(JSON.parse(c.body),{workflow_run_backend_id:PROTOCOL.runBackend,workflow_job_run_backend_id:PROTOCOL.jobBackend,name:t.name,version:4});
  assert.deepEqual(JSON.parse(f.body),{workflow_run_backend_id:PROTOCOL.runBackend,workflow_job_run_backend_id:PROTOCOL.jobBackend,name:t.name,size:String(original.length),hash:'sha256:'+t.hash});
  assert.notEqual(JSON.parse(c.body).workflow_run_backend_id,identity.runId);assert.equal(c.credentialRole,'Runtime');assert.equal(c.credentialPlacement,'AuthorizationBearer');assert.equal(c.headers.authorization,undefined);
});
test('Block body is original and SAS query octets survive both storage operations',()=>{
  const input=caps(),b=buildRequest('Block',t,input),c=buildRequest('Commit',t,input);assert.deepEqual(b.body,original);
  assert.ok(b.url.startsWith(input.uploadUrl+'&comp=block&blockid='));assert.equal(c.url,input.uploadUrl+'&comp=blocklist');
  assert.match(c.body.toString(),/^<\?xml version="1.0" encoding="utf-8"\?><BlockList><Uncommitted>[A-Za-z0-9+/=]+<\/Uncommitted><\/BlockList>$/);assert.doesNotMatch(c.body.toString(),/Latest|Committed>/);
  assert.equal(b.headers['x-ms-version'],PROTOCOL.storageVersion);assert.equal(b.headers['content-length'],String(original.length));assert.equal(c.headers['content-length'],String(c.body.length));
  assert.ok(b.url.includes('sig=fixture%2Bonly%2f%3D%3D'));assert.equal(new URL(b.url).searchParams.get('blockid'),Buffer.from(t.name).toString('base64'));
  assert.equal(b.credentialRole,'Blob');assert.equal(b.credentialPlacement,'UrlCapability');assert.equal(b.headers.authorization,undefined);
});
for(const op of Object.keys(ROLES)) test(`fixed ${op} method/path/origin/body/credential envelope validates and has no secret input`,()=>{
  const r=buildRequest(op,t,caps());assert.equal(validateRequest(r,t,caps()),r);assert.equal(r.credentialRole,ROLES[op]);assert.ok(new URL(r.url).hostname.endsWith('.fixture.invalid'));assert.ok(r.body.length<=(op==='Block'?65536:8192));
  assert.throws(()=>buildRequest(op,t,{...caps(),token:'DO_NOT_ACCEPT'}),/ProtocolOptionsRefused/);
});
for(const edit of [r=>r.method='DELETE',r=>r.url='https://api.github.com/repos/x/y',r=>r.url+='/extra',r=>r.headers.authorization='fixture',r=>r.headers['content-length']='0',r=>r.credentialRole='Read',r=>r.credentialPlacement='UrlCapability',r=>r.body=Buffer.from('{}')]) test(`request refusal ${edit}`,()=>{
  const r=buildRequest('Create',t,caps());edit(r);assert.throws(()=>validateRequest(r,t,caps()),/Refused/);
});
for(const suffix of ['&sig=other','&%73ig=other','&SIG=other','&comp=block','&blockid=abc','&Comp=block','&%63omp=block','&unknown=x','#fragment']) test(`signed query refuses appended ${suffix}`,()=>assert.throws(()=>signedCapability(fixtureCapability('Blob')+suffix,'Blob'),/Refused/));
for(const replace of [s=>s.replace('https:','http:'),s=>s.replace('blob.fixture.invalid','blob.fixture.invalid.evil.invalid'),s=>s.replace('blob.fixture.invalid','user@blob.fixture.invalid'),s=>s.replace('blob.fixture.invalid','blob.fixture.invalid:443'),s=>s.replace('/container/','/a/../container/'),s=>s.replace('sig=','s%69g='),s=>s.replace('sig=fixture','sig=%xy'),s=>s.replace('spr=https','spr=http'),s=>s.replace('sp=cw','sp=r')]) test(`signed URL refuses normalization/policy variant ${replace}`,()=>assert.throws(()=>signedCapability(replace(fixtureCapability('Blob')),'Blob'),/Refused/));
test('dummy query encoding stays byte-exact even for equivalent slash encoding',()=>{
  const raw=fixtureCapability('Blob').replace('%2f','%2F');assert.equal(signedCapability(raw,'Blob'),raw);assert.ok(buildRequest('Block',t,{...caps(),uploadUrl:raw}).url.startsWith(raw+'&'));
});
test('existing Block archive cannot be omitted, changed or substituted',()=>{
  assert.throws(()=>buildRequest('Block',t,{uploadUrl:fixtureCapability('Blob')}),/ProtocolOriginalRefused/);const changed=Buffer.from(original);changed[0]^=1;assert.throws(()=>buildRequest('Block',t,{...caps(),original:changed}),/ProtocolOriginalRefused/);
});
for(const field of ['signed_upload_url','signedUploadUrl']) test(`Create response accepts exactly one pinned ${field} alias`,()=>assert.deepEqual(parseResponse('Create',envelope({ok:true,[field]:fixtureCapability('Blob')}),t),{reservation:fixtureCapability('Blob')}));
for(const field of ['artifact_id','artifactId']) test(`Finalize response ${field} remains exact above Number.MAX_SAFE_INTEGER`,()=>assert.equal(parseResponse('Finalize',envelope({ok:true,[field]:PROTOCOL.artifactId}),t).id,PROTOCOL.artifactId));
for(const value of ['0','-1','01','9223372036854775808',9007199254740992,null,{},'1e3']) test(`signed int64 identity refuses ${JSON.stringify(value)}`,()=>assert.throws(()=>parseResponse('Finalize',envelope({ok:true,artifact_id:value}),t),/Refused/));
for(const raw of ['{"ok":true,"artifact_id":"1","artifactId":"1"}','{"ok":true,"artifact_id":"1","artifact_id":"2"}','{"ok":true,"artifact_id":"1","artifact_\\u0069d":"2"}','{"ok":false,"artifact_id":"1"}','{"ok":true,"artifact_id":"1","extra":"not logged"}','{} trailing']) test(`strict response schema refuses ${raw}`,()=>assert.throws(()=>parseResponse('Finalize',envelope(raw),t),/Refused/));
test('REST JSON number IDs preserve integer lexemes; strings/decimal/exponent/coercion cannot masquerade',()=>{
  const large=PROTOCOL.artifactId;
  assert.equal(parseResponse('Repository',envelope(`{"id":${large},"full_name":"synthetic/tokenforge"}`),t).id,large);
  for(const bad of [`"${large}"`,'1.0','1e0','-0','-1','null','{}']) assert.throws(()=>parseResponse('Repository',envelope(`{"id":${bad},"full_name":"synthetic/tokenforge"}`),t),/Refused/);
  assert.equal(strictJson(Buffer.from('9007199254740993'),true),9007199254740993n);
});
test('one-hop download planning strips Read bearer role; a second redirect never succeeds',()=>{
  const redirect=parseResponse('Redirect',{status:302,headers:{location:fixtureCapability('Download'),'content-length':'0'},body:Buffer.alloc(0)},t);const r=buildRequest('Download',t,{downloadUrl:redirect.capability});
  assert.equal(r.credentialRole,'Download');assert.equal(r.credentialPlacement,'UrlCapability');assert.equal(r.headers.authorization,undefined);
  assert.throws(()=>parseResponse('Download',{status:302,headers:{location:fixtureCapability('Download'),'content-length':'0'},body:Buffer.alloc(0)},t),/ProtocolStatusRefused/);
});
for(const edit of [r=>r.status=500,r=>r.headers['content-encoding']='gzip',r=>r.headers['content-length']='999',r=>r.headers['content-type']='text/html',r=>r.body=Buffer.alloc(131073),r=>r.headers.location='https://unapproved.invalid/no']) test(`response envelope/body policy ${edit}`,()=>{
  const r=envelope({ok:true,artifact_id:'1'});edit(r);assert.throws(()=>parseResponse('Finalize',r,t),/Refused/);
});
for(const [op,kind] of [['Create','method'],['Create','origin'],['Create','path'],['Create','json'],['Block','original'],['Block','credential'],['Block','query'],['Commit','json'],['Finalize','json'],['Repository','credential'],['Redirect','origin'],['Download','path']]) test(`integrated serializer ${op}/${kind} consumes fixed charge, preserves C and cannot replay or approve`,testCase=>{
  const f=setup(testCase,{serializationFault:{op,kind}});upload(f.tx);let r=f.tx.observe();assert.notEqual(r.state,'Observed');
  const ledger=f.tx.snapshot().ledger,entry=ledger.find(x=>x.op===op);assert.ok(entry);assert.equal(entry.charge,requestBody(op,f.tx.snapshot()).length+(op==='Download'?65536:131072));
  assert.equal(f.transport.transcript().filter(x=>x.op===op).length,0);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
  const count=f.transport.transcript().length,budget=JSON.stringify(f.tx.snapshot().ledger);f.tx.advance();f.tx.observe();assert.equal(f.transport.transcript().length,count);assert.equal(JSON.stringify(f.tx.snapshot().ledger),budget);
  for(const flag of ['networkEnabled','serviceInteroperabilityProven','operationalPolicyEmissionAllowed','contentPrivacyApproval']) assert.equal(r[flag],false);
});
for(const [op,kind] of [['Create','badJson'],['Create','encoding'],['Finalize','duplicate'],['Finalize','unsafeInteger'],['Finalize','aliasConflict'],['Redirect','redirectOrigin'],['Download','status'],['Artifact','encoding']]) test(`integrated response ${op}/${kind} preserves uncertainty and sanitized results`,testCase=>{
  const f=setup(testCase,{responseFault:{op,kind}});upload(f.tx);const r=f.tx.observe();assert.equal(r.serviceInteroperabilityProven,false);assert.equal(r.operationalPolicyEmissionAllowed,false);assert.doesNotMatch(JSON.stringify(r)+JSON.stringify(f.tx.snapshot()),/SYNTHETIC_ERROR|fixture%2B|signed_upload_url|Authorization/);
});
test('serialized successful path is four mutations/seven reads with no budgets or archive substitution',testCase=>{
  const f=setup(testCase);upload(f.tx);assert.equal(f.tx.observe().state,'Observed');assert.equal(f.transport.transcript().length,11);assert.deepEqual(f.transport.archivedBytes(),original);
  const ledger=f.tx.snapshot().ledger;assert.ok(ledger.reduce((n,e)=>n+e.charge,0)<=LIMITS.totalBytes);for(const e of ledger) assert.equal(e.charge,requestBody(e.op,f.tx.snapshot()).length+(e.op==='Download'?65536:131072));
});
test('offline source closure contains no network, subprocess, environment, executable action or dispatcher capability',()=>{
  for(const name of ['TokenForgeArtifactProtocol.mjs','TokenForgeOfflineSchema.mjs']) {
    const text=fs.readFileSync(new URL('../scripts/offline/'+name,import.meta.url),'utf8');assert.doesNotMatch(text,/\b(?:fetch|eval)\s*\(|\bimport\s*\(|process\s*\.\s*env|node:(?:http|https|net|tls|child_process|fs)/);
  }
  const r=buildRequest('Create',t);assert.ok(new URL(r.url).hostname.endsWith('.invalid'));assert.equal('dispatch' in r,false);
});

for(const at of [2,4]) test(`expiry during serialization phase ${at} retains charge and records zero exchanges`,testCase=>{
  const f=setup(testCase),stringify=JSON.stringify;let calls=0;
  JSON.stringify=function(value,...args){const result=stringify.call(JSON,value,...args);if(value?.workflow_run_backend_id&&++calls===at) f.clock.advance(180000);return result;};
  let r;try{r=f.tx.advance();}finally{JSON.stringify=stringify;}
  assert.equal(r.state,'CreateUnknown');assert.equal(f.transport.transcript().length,0);assert.equal(f.tx.snapshot().ledger.length,1);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
});
for(const raw of ['{"ok":true,"artifact_id":"SYNTHETIC_SECRET\\q"}','{"ok":true,"artifact_id":"SYNTHETIC_SECRET\n"}']) test('pure response exception is sanitized even for invalid JSON string escapes/control bytes',()=>{
  assert.throws(()=>parseResponse('Finalize',envelope(raw),t),e=>{assert.equal(e.message,'JsonRefused');assert.doesNotMatch(e.stack,/SYNTHETIC_SECRET|artifact_id/);return true;});
});
test('artifact wire normalization exposes only observed provenance, without invented attempt/workflow/repository-name fields',()=>{
  const r=parseResponse('Artifact',envelope(`{"id":${PROTOCOL.artifactId},"name":"${t.name}","size_in_bytes":${t.size},"digest":"sha256:${t.hash}","expired":false,"workflow_run":{"id":3,"repository_id":1,"head_sha":"${identity.source}"}}`),t);
  assert.deepEqual(r.observedContext,{repositoryId:'1',runId:'3',source:identity.source});assert.equal('context' in r,false);assert.equal('attempt' in r.observedContext,false);assert.equal('workflowId' in r.observedContext,false);
});
test('unobserved artifact-own attempt/workflow cannot become a claimed observation',testCase=>{
  const f=setup(testCase,{metadataChange:{context:{...identity,attempt:'2',workflowId:'9'}}});upload(f.tx);const r=f.tx.observe();
  // This information is absent from that REST artifact schema; neither accepted
  // expected context nor the separate current-Run read proves artifact-own attempt.
  assert.equal(r.state,'Observed');assert.equal(r.artifactOwnAttemptObserved,false);assert.equal(r.artifactOwnWorkflowIdObserved,false);assert.equal(r.serviceInteroperabilityProven,false);assert.equal(r.operationalPolicyEmissionAllowed,false);
});
for(const kind of ['runAttemptAfter','runWorkflowAfter']) test(`separate current-Run reread detects ${kind}`,testCase=>{
  const f=setup(testCase,{responseFault:{op:'Run',kind}});upload(f.tx);assert.equal(f.tx.observe().state,'ObservationUnknown');assert.equal(f.transport.transcript().filter(x=>x.op==='Run').length,2);
});
test('v2 terminal journal cannot retain a protocol-incompatible unsigned artifact ID',testCase=>{
  const f=setup(testCase);upload(f.tx);f.tx.observe();f.tx.close();const file=path.join(f.tx.directory,'journal.json'),j=JSON.parse(fs.readFileSync(file));j.artifactId='9223372036854775808';fs.writeFileSync(file,JSON.stringify(j));const before=fs.readFileSync(file);
  assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);assert.deepEqual(fs.readFileSync(file),before);assert.equal(f.transport.transcript().length,11);
});
test('v1 abstract journal remains preserved and refuses implicit migration/reserialization',testCase=>{
  const f=setup(testCase);f.tx.close();const file=path.join(f.tx.directory,'journal.json'),j=JSON.parse(fs.readFileSync(file));j.version=1;j.kind='OfflineFakeArtifactTransaction';fs.writeFileSync(file,JSON.stringify(j));const before=fs.readFileSync(file);
  assert.throws(()=>Tx.open({directory:f.tx.directory,context:identity,transport:f.transport,clock:f.clock}),/OfflineResumeRefused/);assert.deepEqual(fs.readFileSync(file),before);assert.equal(f.transport.transcript().length,0);
});

test('time consumed decoding a response cannot become a timely acknowledgement',testCase=>{
  const f=setup(testCase),decode=TextDecoder.prototype.decode;
  TextDecoder.prototype.decode=function(input,...args){const result=decode.call(this,input,...args);if(result.startsWith('{"ok":true,"signed_upload_url"'))f.clock.advance(180000);return result;};
  let r;try{r=f.tx.advance();}finally{TextDecoder.prototype.decode=decode;}
  assert.equal(r.state,'CreateUnknown');assert.equal(f.transport.transcript().length,1);assert.equal(f.tx.snapshot().ledger.length,1);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
});
