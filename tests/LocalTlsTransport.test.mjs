import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import {execFileSync,execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {OfflineArtifactTransaction as Tx,createFakeClock,createFakeTransport} from '../scripts/offline/TokenForgeArtifactTransaction.mjs';
import {createLocalTlsTransport,createServiceTransport,localRuntimeIdentity} from '../scripts/transport/TokenForgeLocalTlsTransport.mjs';
import {tlsMaterial,startTlsFixture,CONTEXT} from './fixtures/publication/LocalTlsFixture.mjs';
let root,material,other,wrongName,original;
const hash=b=>createHash('sha256').update(b).digest('hex');
before(()=>{
 root=fs.mkdtempSync(path.join(os.tmpdir(),'tf-local-tls-'));fs.chmodSync(root,0o700);material=tlsMaterial(root);other=tlsMaterial(root);wrongName=tlsMaterial(root,'wrong.fixture.invalid');
 const dir=path.join(root,'files');fs.mkdirSync(dir,{mode:0o700});for(const n of ['coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json'])fs.writeFileSync(path.join(dir,n),n.endsWith('.json')?'{}':'Synthetic');
 const file=path.join(root,'original.zip');execFileSync('/usr/bin/python3',['-I',path.join(path.dirname(fileURLToPath(import.meta.url)),'fixtures/publication/MutateSealerZip.py'),dir,file,'canonical-from-directory']);original=fs.readFileSync(file);
});
after(()=>fs.rmSync(root,{recursive:true,force:true}));
async function fixture(t,options={}) {
 const server=await startTlsFixture(material,options),transport=createLocalTlsTransport({port:server.port,ca:material.cert}),tx=Tx.prepare({parent:root,original,context:CONTEXT,transport});
 t.after(async()=>{tx.close();await server.close();});return {server,transport,tx};
}
async function upload(tx){for(let i=0;i<4;i++)await tx.advance();}
async function until(predicate){const end=Date.now()+3000;while(!predicate()){if(Date.now()>end)throw Error('FixtureWaitExceeded');await new Promise(r=>setTimeout(r,5));}}

test('actual TLS flow preserves C, roles, query and one fresh TLS1.3 connection per request',async t=>{
 const f=await fixture(t);await upload(f.tx);const r=await f.tx.observe();assert.equal(r.state,'Observed');assert.equal(r.kind,'LocalTlsTransactionObservation');assert.equal(r.externalHttpsEnabled,false);assert.equal(r.serviceInteroperabilityProven,false);assert.equal(r.operationalPolicyEmissionAllowed,false);
 assert.deepEqual(f.server.state.body,original);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);assert.deepEqual(f.server.state.violations,[]);assert.equal(f.server.state.requests,11);assert.equal(f.server.state.connections,11);
 assert.equal(new Set(f.server.state.records.map(x=>x.connection)).size,11);for(const x of f.server.state.records){assert.equal(x.tls,'TLSv1.3');assert.equal(x.remote,'127.0.0.1');}
 assert.equal(hash(f.server.state.records.find(x=>x.op==='Block').body),hash(original));assert.match(f.server.state.records.find(x=>x.op==='Block').query,/sig=fixture%2Bonly%2f%3D%3D&comp=block&blockid=/);
 assert.equal(f.server.state.records.find(x=>x.op==='Redirect').authorization,'Bearer TF_FIXTURE_READ_ONLY');assert.equal(f.server.state.records.find(x=>x.op==='Download').authorization,null);assert.equal(f.tx.snapshot().ledger.length,11);
});
test('chunked HTTP transfer framing leaves original payload exact',async t=>{
 const f=await fixture(t,{chunked:true});await upload(f.tx);assert.equal((await f.tx.observe()).state,'Observed');assert.deepEqual(f.server.state.body,original);
});
for(const [op,unknown] of [['Create','CreateUnknown'],['Block','UploadUnknown'],['Commit','UploadUnknown'],['Finalize','FinalizeUnknown']])for(const mode of ['dropBeforeBody','dropAck'])test(`${op}/${mode}: server counts one attempt and mutation never replays`,async t=>{
 const f=await fixture(t,{fault:{op,mode}}),n=['Create','Block','Commit','Finalize'].indexOf(op);for(let i=0;i<=n;i++)await f.tx.advance();assert.equal(f.tx.snapshot().state,unknown);
 const count=f.server.state.requests;await f.tx.advance();assert.equal(f.server.state.requests,count);assert.equal(f.server.state.records.filter(x=>x.op===op).length,1);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
 if(op==='Finalize'&&mode==='dropAck'){assert.equal((await f.tx.observe()).state,'Observed');assert.equal(f.server.state.requests,12);assert.equal(f.tx.snapshot().priorUnknown,'FinalizeUnknown');}
});
for(const mode of ['headerOverflow','duplicateLength','ambiguousLength','oversizeDeclared','oversizeChunked','partial','encoding','badJson'])test(`actual ${mode} response is bounded/sanitized and remains unknown`,async t=>{
 const f=await fixture(t,{fault:{op:'Create',mode}});const r=await f.tx.advance();assert.equal(r.state,'CreateUnknown');assert.equal(f.tx.snapshot().ledger.length,1);assert.equal(f.server.state.requests,1);
 assert.doesNotMatch(JSON.stringify(r)+JSON.stringify(f.tx.snapshot())+JSON.stringify(f.transport.transcript()),/TF_FIXTURE_|SYNTHETIC_RESPONSE_SECRET|fixture%2B/);await f.tx.advance();assert.equal(f.server.state.requests,1);
});
for(const [op,mode] of [['Redirect','duplicateLocation'],['Redirect','foreignRedirect'],['Download','redirect'],['Create','redirect']])test(`actual ${op}/${mode} never follows unapproved redirect`,async t=>{
 const f=await fixture(t,{fault:{op,mode}});await upload(f.tx);const r=await f.tx.observe();assert.notEqual(r.state,'Observed');assert.equal(f.server.state.records.filter(x=>x.op==='Download').length,op==='Download'?1:0);
});
test('explicit cancellation holds custody through socket teardown and never releases lock early',async t=>{
 const f=await fixture(t,{fault:{op:'Create',mode:'holdHeaders'}}),pending=f.tx.advance();await until(()=>f.server.state.effects.includes('Create'));
 assert.throws(()=>f.tx.close(),/TransactionBusy/);await assert.rejects(f.tx.advance(),/TransactionUnavailable/);assert.ok(fs.existsSync(path.join(f.tx.directory,'lock')));
 f.transport.cancel();assert.equal((await pending).state,'CreateUnknown');assert.ok(fs.existsSync(path.join(f.tx.directory,'lock')));f.tx.close();assert.equal(fs.existsSync(path.join(f.tx.directory,'lock')),false);assert.equal(f.server.state.requests,1);
});
for(const mode of ['holdHeaders','holdBody'])test(`real ten-second ${mode} timeout aborts once without resend`,{timeout:18000},async t=>{
 const f=await fixture(t,{fault:{op:'Create',mode}}),start=performance.now();assert.equal((await f.tx.advance()).state,'CreateUnknown');assert.ok(performance.now()-start>=9500);assert.equal(f.server.state.requests,1);await f.tx.advance();assert.equal(f.server.state.requests,1);
});
test('real TLS handshake stall is timed out with no HTTP mutation',{timeout:18000},async t=>{
 const sockets=new Set(),server=net.createServer(s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 t.after(async()=>{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));});
 const transport=createLocalTlsTransport({port:server.address().port,ca:material.cert}),tx=Tx.prepare({parent:root,original,context:CONTEXT,transport});t.after(()=>tx.close());const start=performance.now();assert.equal((await tx.advance()).state,'CreateUnknown');assert.ok(performance.now()-start>=9500);assert.equal(tx.snapshot().ledger.length,1);
});
test('connection refusal is one charged attempt',async t=>{
 const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const port=s.address().port;await new Promise(r=>s.close(r));const transport=createLocalTlsTransport({port,ca:material.cert}),tx=Tx.prepare({parent:root,original,context:CONTEXT,transport});t.after(()=>tx.close());assert.equal((await tx.advance()).state,'CreateUnknown');assert.equal(tx.snapshot().ledger.length,1);assert.equal(transport.transcript().length,1);
});
for(const kind of ['wrongCA','wrongSAN'])test(`${kind} uses normal certificate verification and sends no HTTP request`,async t=>{
 const fixture=await startTlsFixture(kind==='wrongSAN'?wrongName:material),transport=createLocalTlsTransport({port:fixture.port,ca:kind==='wrongCA'?other.cert:wrongName.cert}),tx=Tx.prepare({parent:root,original,context:CONTEXT,transport});t.after(async()=>{tx.close();await fixture.close();});assert.equal((await tx.advance()).state,'CreateUnknown');assert.equal(fixture.state.requests,0);
});
test('store binds runtime/profile/fixture authority and refuses changed authority or fake mode',async t=>{
 const f=await fixture(t);await upload(f.tx);f.tx.close();const file=path.join(f.tx.directory,'journal.json'),before=fs.readFileSync(file);assert.equal(f.tx.snapshot().binding.runtimeSha256,localRuntimeIdentity().sha256);
 const wrong=createLocalTlsTransport({port:f.server.port,ca:other.cert});assert.throws(()=>Tx.open({directory:f.tx.directory,context:CONTEXT,transport:wrong}),/OfflineResumeRefused/);assert.deepEqual(fs.readFileSync(file),before);
 assert.throws(()=>Tx.open({directory:f.tx.directory,context:CONTEXT,transport:createFakeTransport()}),/OfflineResumeRefused/);assert.equal(f.server.state.requests,4);
 const resumed=Tx.open({directory:f.tx.directory,context:CONTEXT,transport:f.transport});t.after(()=>resumed.close());assert.equal((await resumed.observe()).state,'Observed');
});
test('actual TLS rejects fake clock and all caller endpoint/credential/client hooks before store',async t=>{
 const f=await fixture(t);const before=fs.readdirSync(root);assert.throws(()=>Tx.prepare({parent:root,original,context:CONTEXT,transport:f.transport,clock:createFakeClock()}),/ClockBindingRefused/);assert.deepEqual(fs.readdirSync(root),before);
 for(const extra of [{hostname:'example.com'},{token:'DO_NOT_ACCEPT'},{agent:https.globalAgent},{rejectUnauthorized:false},{lookup:()=>{}}])assert.throws(()=>createLocalTlsTransport({port:f.server.port,ca:material.cert,...extra}),/SchemaRefused/);
 let read=false;assert.throws(()=>createServiceTransport(new Proxy({},{get(){read=true;throw Error();}})),/ServiceModeDisabled/);assert.equal(read,false);
});
test('global agent and inherited proxy options cannot redirect the actual client',async t=>{
 const f=await fixture(t),saved=https.globalAgent,poison=new https.Agent();poison.addRequest=()=>{throw Error('GlobalAgentUsed');};https.globalAgent=poison;try{assert.equal((await f.tx.advance()).state,'Created');}finally{https.globalAgent=saved;poison.destroy();}
 const script=path.join(root,'proxy-child.mjs'),moduleUrl=new URL('../scripts/offline/TokenForgeArtifactTransaction.mjs',import.meta.url).href,transportUrl=new URL('../scripts/transport/TokenForgeLocalTlsTransport.mjs',import.meta.url).href;
 const cert=path.join(root,'child-ca.pem');fs.writeFileSync(cert,material.cert,{mode:0o600});
 fs.writeFileSync(script,`import fs from 'node:fs';import {OfflineArtifactTransaction as Tx} from ${JSON.stringify(moduleUrl)};import {createLocalTlsTransport} from ${JSON.stringify(transportUrl)};const transport=createLocalTlsTransport({port:${f.server.port},ca:fs.readFileSync(${JSON.stringify(cert)})});const tx=Tx.prepare({parent:${JSON.stringify(root)},original:fs.readFileSync(${JSON.stringify(path.join(root,'original.zip'))}),context:${JSON.stringify(CONTEXT)},transport});const r=await tx.advance();tx.close();if(r.state!=='Created')process.exitCode=1;`);
 const result=await promisify(execFile)(process.execPath,['--use-env-proxy',script],{env:{PATH:'/usr/bin:/bin',HOME:root,HTTP_PROXY:'http://127.0.0.1:9',HTTPS_PROXY:'http://127.0.0.1:9',ALL_PROXY:'http://127.0.0.1:9'},timeout:15000});assert.equal(result.stdout,'');assert.equal(f.server.state.requests,2);
});

test('realistic extra REST fields and diagnostic headers are ignored as authority, not mistaken for observed provenance',async t=>{
 const f=await fixture(t,{extras:true});await upload(f.tx);const r=await f.tx.observe();assert.equal(r.state,'Observed');assert.equal(r.artifactOwnAttemptObserved,false);assert.equal(r.artifactOwnWorkflowIdObserved,false);
});

for(const op of ['Artifact','Run'])test(`expiry during ${op} response cannot become Observed and never replays`,async t=>{
 const f=await fixture(t,{expiryDelayOp:op});await upload(f.tx);assert.equal((await f.tx.observe()).state,'ObservationUnknown');const n=f.server.state.requests;await f.tx.observe();assert.equal(f.server.state.requests,n);assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'original.zip')),original);
});
test('completed evidence remains historical when its known expiry passes',async t=>{
 const f=await fixture(t,{expiryDelayOp:'Never'});await upload(f.tx);assert.equal((await f.tx.observe()).state,'Observed');const before=fs.readFileSync(path.join(f.tx.directory,'journal.json'));await new Promise(r=>setTimeout(r,Math.max(0,f.server.state.expiry-Date.now()+50)));assert.equal((await f.tx.observe()).state,'SavedObservationExpired');assert.deepEqual(fs.readFileSync(path.join(f.tx.directory,'journal.json')),before);assert.equal(f.server.state.requests,11);
});
